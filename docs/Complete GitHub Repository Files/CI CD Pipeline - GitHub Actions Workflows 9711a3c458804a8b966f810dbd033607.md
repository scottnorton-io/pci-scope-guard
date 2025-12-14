# CI/CD Pipeline - GitHub Actions Workflows

# CI/CD Pipeline

**Complete GitHub Actions workflows for automated testing, building, and deployment**

---

## GitHub Actions Workflows

### Workflow Structure

```
.github/
└── workflows/
    ├── ci.yml              # Pull request checks
    ├── release.yml         # Release automation
    ├── security.yml        # Security scanning
    ├── docker.yml          # Docker image builds
    └── docs.yml            # Documentation deployment
```

---

## CI Workflow (Pull Request Checks)

**File: `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main, develop]

env:
  PYTHON_VERSION: '3.11'

jobs:
  lint:
    name: Lint Code
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: $ env.PYTHON_VERSION 
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: $ runner.os -pip-$ hashFiles('**/requirements*.txt') 
          restore-keys: |
            $ runner.os -pip-
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      
      - name: Run Black (formatting check)
        run: black --check src/ tests/
      
      - name: Run isort (import sorting)
        run: isort --check-only src/ tests/
      
      - name: Run Flake8 (linting)
        run: flake8 src/ tests/
      
      - name: Run mypy (type checking)
        run: mypy src/

  test:
    name: Test Suite
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: timescale/timescaledb:latest-pg15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test_pci_scope_guard
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: $ env.PYTHON_VERSION 
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: $ runner.os -pip-$ hashFiles('**/requirements*.txt') 
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      
      - name: Run unit tests
        env:
          DATABASE_URL: postgresql://test:[test@localhost:5432](mailto:test@localhost:5432)/test_pci_scope_guard
          REDIS_URL: redis://[localhost:6379/0](http://localhost:6379/0)
        run: pytest tests/unit/ -v --cov=src --cov-report=xml
      
      - name: Run integration tests
        env:
          DATABASE_URL: postgresql://test:[test@localhost:5432](mailto:test@localhost:5432)/test_pci_scope_guard
          REDIS_URL: redis://[localhost:6379/0](http://localhost:6379/0)
        run: pytest tests/integration/ -v --cov=src --cov-append --cov-report=xml
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          fail_ci_if_error: false

  build:
    name: Build Docker Image
    runs-on: ubuntu-latest
    needs: [lint, test]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Build API image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: deployment/docker/Dockerfile.api
          push: false
          tags: pci-scope-guard/api:test
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

---

## Release Workflow (Automated Releases)

**File: `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

env:
  PYTHON_VERSION: '3.11'
  REGISTRY: [ghcr.io](http://ghcr.io)
  IMAGE_NAME: $ github.repository 

jobs:
  test:
    name: Run Tests
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: timescale/timescaledb:latest-pg15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test_pci_scope_guard
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: $ env.PYTHON_VERSION 
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      
      - name: Run full test suite
        env:
          DATABASE_URL: postgresql://test:[test@localhost:5432](mailto:test@localhost:5432)/test_pci_scope_guard
          REDIS_URL: redis://[localhost:6379/0](http://localhost:6379/0)
        run: pytest tests/ -v --cov=src --cov-report=xml
      
      - name: Verify coverage threshold
        run: |
          coverage report --fail-under=80

  build-and-push:
    name: Build and Push Docker Images
    runs-on: ubuntu-latest
    needs: test
    permissions:
      contents: read
      packages: write
    
    strategy:
      matrix:
        image: [api, worker]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: $ env.REGISTRY 
          username: $ [github.actor](http://github.actor) 
          password: $ secrets.GITHUB_TOKEN 
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: $ env.REGISTRY /$ env.IMAGE_NAME /$ matrix.image 
          tags: |
            type=semver,pattern=version
            type=semver,pattern=major.minor
            type=semver,pattern=major
            type=sha
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          file: deployment/docker/Dockerfile.$ matrix.image 
          push: true
          tags: $ steps.meta.outputs.tags 
          labels: $ steps.meta.outputs.labels 
          cache-from: type=gha
          cache-to: type=gha,mode=max

  create-release:
    name: Create GitHub Release
    runs-on: ubuntu-latest
    needs: build-and-push
    permissions:
      contents: write
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Generate changelog
        id: changelog
        run: |
          # Extract version from tag
          VERSION=${GITHUB_REF#refs/tags/v}
          
          # Extract changelog for this version
          sed -n "/## \[$VERSION\]/,/## \[/p" [CHANGELOG.md](http://CHANGELOG.md) | sed '$ d' > release_[notes.md](http://notes.md)
      
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          body_path: release_[notes.md](http://notes.md)
          generate_release_notes: true
          draft: false
          prerelease: false
        env:
          GITHUB_TOKEN: $ secrets.GITHUB_TOKEN 

  publish-pypi:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    needs: test
    permissions:
      id-token: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: $ env.PYTHON_VERSION 
      
      - name: Install build tools
        run: pip install build
      
      - name: Build package
        run: python -m build
      
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

---

## Security Scanning Workflow

**File: `.github/workflows/security.yml`**

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  dependency-scan:
    name: Dependency Vulnerability Scan
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Safety check
        uses: pyupio/safety@2.3.5
        with:
          api-key: $ [secrets.SAFETY](http://secrets.SAFETY)_API_KEY 
          args: --file requirements.txt --json

  secret-scan:
    name: Secret Scanning
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Run TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: $ github.event.repository.default_branch 
          head: HEAD

  code-scan:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: python
      
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2

  container-scan:
    name: Container Security Scan
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build API image
        run: docker build -t pci-scope-guard/api:scan -f deployment/docker/Dockerfile.api .
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: pci-scope-guard/api:scan
          format: 'sarif'
          output: 'trivy-results.sarif'
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
```

---

## Docker Build Workflow

**File: `.github/workflows/docker.yml`**

```yaml
name: Docker

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  REGISTRY: [ghcr.io](http://ghcr.io)
  IMAGE_NAME: $ github.repository 

jobs:
  build-and-push:
    name: Build Docker Images
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    
    strategy:
      matrix:
        image: [api, worker, dashboard]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Log in to Container Registry
        if: github.event_name != 'pull_request'
        uses: docker/login-action@v3
        with:
          registry: $ env.REGISTRY 
          username: $ [github.actor](http://github.actor) 
          password: $ secrets.GITHUB_TOKEN 
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: $ env.REGISTRY /$ env.IMAGE_NAME /$ matrix.image 
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=sha
            type=raw,value=latest,enable=is_default_branch
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          file: deployment/docker/Dockerfile.$ matrix.image 
          platforms: linux/amd64,linux/arm64
          push: $ github.event_name != 'pull_request' 
          tags: $ steps.meta.outputs.tags 
          labels: $ steps.meta.outputs.labels 
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

---

## Documentation Deployment

**File: `.github/workflows/docs.yml`**

```yaml
name: Documentation

on:
  push:
    branches: [main]
    paths:
      - 'docs/**'
      - '[README.md](http://README.md)'
  pull_request:
    branches: [main]
    paths:
      - 'docs/**'

jobs:
  build-and-deploy:
    name: Build and Deploy Docs
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install MkDocs
        run: |
          pip install mkdocs
          pip install mkdocs-material
          pip install pymdown-extensions
      
      - name: Build documentation
        run: mkdocs build
      
      - name: Deploy to GitHub Pages
        if: github.event_name == 'push'
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: $ secrets.GITHUB_TOKEN 
          publish_dir: ./site
```

---

## Required GitHub Secrets

### Repository Secrets

Configure these in **Settings → Secrets and variables → Actions**:

```
SAFETY_API_KEY           # For dependency vulnerability scanning
CODECOV_TOKEN            # For code coverage reporting (optional)
PYPI_API_TOKEN           # For publishing to PyPI
AWS_ACCESS_KEY_ID        # For AWS deployment (optional)
AWS_SECRET_ACCESS_KEY    # For AWS deployment (optional)
DOCKER_HUB_USERNAME      # For Docker Hub publishing (optional)
DOCKER_HUB_TOKEN         # For Docker Hub publishing (optional)
```

### Environment Secrets (Production)

**Settings → Environments → production**:

```
DATABASE_URL             # Production database connection
REDIS_URL                # Production Redis connection
SIGNING_KEY_PRIVATE      # Evidence signing private key
VANTA_API_KEY            # Vanta integration
DRATA_API_KEY            # Drata integration
```

---

## Branch Protection Rules

### Main Branch

**Settings → Branches → Add rule** (branch pattern: `main`):

- [x]  Require a pull request before merging
    - [x]  Require approvals: 1
    - [x]  Dismiss stale pull request approvals
    - [x]  Require review from Code Owners
- [x]  Require status checks to pass before merging
    - [x]  Require branches to be up to date
    - Required checks:
        - `lint`
        - `test`
        - `build`
        - `security / dependency-scan`
        - `security / code-scan`
- [x]  Require conversation resolution before merging
- [x]  Require signed commits
- [x]  Include administrators

---

## Automated Dependency Updates

**File: `.github/dependabot.yml`**

```yaml
version: 2
updates:
  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "scottnorton"
    labels:
      - "dependencies"
      - "python"
    commit-message:
      prefix: "chore"
      include: "scope"
  
  # Docker dependencies
  - package-ecosystem: "docker"
    directory: "/deployment/docker"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    reviewers:
      - "scottnorton"
    labels:
      - "dependencies"
      - "docker"
  
  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    reviewers:
      - "scottnorton"
    labels:
      - "dependencies"
      - "github-actions"
```

---

## CI/CD Best Practices

### 1. Fast Feedback

```yaml
# Run linting first (fast fail)
jobs:
  lint:    # 2-3 minutes
    ...
  test:    # 5-10 minutes
    needs: [lint]
  build:   # 3-5 minutes
    needs: [test]
```

### 2. Caching

```yaml
# Cache pip dependencies
- uses: actions/cache@v3
  with:
    path: ~/.cache/pip
    key: $ runner.os -pip-$ hashFiles('**/requirements*.txt') 

# Cache Docker layers
- uses: docker/build-push-action@v5
  with:
    cache-from: type=gha
    cache-to: type=gha,mode=max
```

### 3. Parallel Execution

```yaml
strategy:
  matrix:
    python-version: ['3.11', '3.12']
    os: [ubuntu-latest, windows-latest, macos-latest]
```

### 4. Security Scanning

- ✅ Dependency vulnerabilities (Safety)
- ✅ Secret scanning (TruffleHog)
- ✅ Static analysis (CodeQL)
- ✅ Container scanning (Trivy)

### 5. Automated Testing

- ✅ Unit tests (fast, isolated)
- ✅ Integration tests (with services)
- ✅ E2E tests (full workflow)
- ✅ Coverage reporting (Codecov)

---

## Deployment Pipeline

### Development → Staging → Production

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to deploy to'
        required: true
        type: choice
        options:
          - staging
          - production

jobs:
  deploy:
    name: Deploy to $ inputs.environment 
    runs-on: ubuntu-latest
    environment: $ inputs.environment 
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Deploy to ECS
        run: |
          # Update ECS task definition
          # Update ECS service
          echo "Deploying to $ inputs.environment "
```

---

## Monitoring CI/CD

### GitHub Actions Dashboard

- View workflow runs: **Actions** tab
- Monitor deployment status: **Environments**
- Check security alerts: **Security** tab

### Metrics to Track

- ⏱️ Build time (target: <15 minutes)
- ✅ Success rate (target: >95%)
- 🐛 Failed builds (investigate immediately)
- 📊 Code coverage trend (maintain >80%)
- 🔒 Security scan results (zero high/critical)

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton