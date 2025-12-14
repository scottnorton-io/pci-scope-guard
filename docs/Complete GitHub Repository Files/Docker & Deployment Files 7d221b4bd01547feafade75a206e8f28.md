# Docker & Deployment Files

# Docker & Deployment Files

---

## docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: timescale/timescaledb:latest-pg15
    environment:
      POSTGRES_USER: pci_scope_guard
      POSTGRES_PASSWORD: changeme
      POSTGRES_DB: pci_scope_guard
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U pci_scope_guard"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  api:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile.api
    env_file:
      - .env
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./keys:/app/keys:ro
      - evidence_storage:/app/evidence
    command: uvicorn [src.api.rest](http://src.api.rest).main:app --host 0.0.0.0 --port 8000 --reload
    healthcheck:
      test: ["CMD", "curl", "-f", "119"]
      interval: 30s
      timeout: 10s
      retries: 3

  worker:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile.worker
    env_file:
      - .env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./keys:/app/keys:ro
      - evidence_storage:/app/evidence
    command: celery -A src.core.celery_app worker --loglevel=info

  dashboard:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile.dashboard
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=120
      - REACT_APP_WS_URL=121
    depends_on:
      - api

volumes:
  postgres_data:
  redis_data:
  evidence_storage:
```

---

## deployment/docker/Dockerfile.api

```docker
# Multi-stage build for PCI Scope Guard API
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create app directory
WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 pci && chown -R pci:pci /app

# Copy application code
COPY --chown=pci:pci . .

# Switch to non-root user
USER pci

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f 122 || exit 1

# Run application
CMD ["uvicorn", "[src.api.rest](http://src.api.rest).main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## deployment/docker/Dockerfile.worker

```docker
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -u 1000 pci && chown -R pci:pci /app
USER pci

# Run Celery worker
CMD ["celery", "-A", "src.core.celery_app", "worker", "--loglevel=info", "--concurrency=4"]
```

---

## .env.example

```bash
# Environment
ENV=production
DEBUG=false
LOG_LEVEL=INFO

# Security
SECRET_KEY=generate-with-openssl-rand-hex-32
SIGNING_KEY_PATH=/app/keys/evidence-signing-key.pem
SIGNING_ALGORITHM=ES256

# Database
DATABASE_URL=postgresql://pci_scope_guard:changeme@postgres:5432/pci_scope_guard
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_MAX_CONNECTIONS=50
CACHE_TTL=300

# Celery
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0

# AWS
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_ENABLE_FLOW_LOGS=true
AWS_FLOW_LOG_GROUP=/aws/vpc/flowlogs

# Azure (optional)
AZURE_SUBSCRIPTION_ID=
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=

# GCP (optional)
GCP_PROJECT_ID=
GCP_CREDENTIALS_PATH=/app/keys/gcp-credentials.json

# GRC Integrations
VANTA_API_KEY=
VANTA_API_URL=[https://api.vanta.com/v1](https://api.vanta.com/v1)
DRATA_API_KEY=
DRATA_API_URL=[https://api.drata.com/v1](https://api.drata.com/v1)
SECUREFRAME_API_KEY=
SECUREFRAME_API_URL=[https://api.secureframe.com/v1](https://api.secureframe.com/v1)

# Evidence Storage
EVIDENCE_STORAGE_TYPE=s3
EVIDENCE_BUCKET_NAME=pci-scope-guard-evidence
EVIDENCE_RETENTION_YEARS=7

# Monitoring
PROMETHEUS_PORT=9090
JAEGER_AGENT_HOST=
JAEGER_AGENT_PORT=6831

# API
RATE_LIMIT_PER_MINUTE=60
CORS_ORIGINS=[http://localhost:3000,http://localhost:8080](http://localhost:3000,http://localhost:8080)

# Classification
CLASSIFICATION_CONFIDENCE_THRESHOLD=0.8
AUTO_CLASSIFY=true
SCAN_BATCH_SIZE=100
```

---

## .gitignore

```
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
PIPFILE.lock

# Virtual Environment
venv/
ENV/
env/
.venv

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Environment
.env
.env.local
.env.*.local

# Keys and Secrets
keys/
*.pem
*.key
*.p12
*.pfx
credentials.json

# Database
*.db
*.sqlite
*.sqlite3

# Logs
*.log
logs/

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/
.hypothesis/

# Evidence (local development)
evidence/
*.evidence.json

# Terraform
.terraform/
*.tfstate
*.tfstate.backup
.terraform.lock.hcl

# Node (for dashboard)
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Build artifacts
dist/
build/
*.whl
```

---

## requirements.txt

```
# Core
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0

# Database
sqlalchemy==2.0.25
alembic==1.13.1
psycopg2-binary==2.9.9
asyncopg==0.29.0

# Cache
redis==5.0.1
hiredis==2.3.2

# Task Queue
celery==5.3.6

# Cloud SDKs
boto3==1.34.34
botocore==1.34.34
azure-identity==1.15.0
azure-mgmt-compute==30.5.0
azure-mgmt-network==25.2.0
gazure-mgmt-sql==4.0.0
oogle-cloud-compute==1.15.0
google-cloud-logging==3.9.0

# Cryptography
cryptography==42.0.0

# HTTP
httpx==0.26.0
requests==2.31.0

# CLI
typer==0.9.0
rich==13.7.0
click==8.1.7

# GraphQL
strawberry-graphql[fastapi]==0.219.1

# Monitoring
prometheus-client==0.19.0
opentelemetry-api==1.22.0
opentelemetry-sdk==1.22.0
opentelemetry-instrumentation-fastapi==0.43b0

# Utilities
python-dotenv==1.0.0
python-multipart==0.0.6
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4

# Testing
pytest==7.4.4
pytest-asyncio==0.23.3
pytest-cov==4.1.0
pytest-mock==3.12.0
faker==22.2.0

# Code Quality
black==24.1.0
flake8==7.0.0
mypy==1.8.0
isort==5.13.2
```

---

## Makefile

```makefile
.PHONY: help install dev-install test lint format clean docker-build docker-up docker-down

help:
	@echo "PCI Scope Guard - Development Commands"
	@echo ""
	@echo "  make install      - Install production dependencies"
	@echo "  make dev-install  - Install development dependencies"
	@echo "  make test         - Run tests"
	@echo "  make lint         - Run linters"
	@echo "  make format       - Format code"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make docker-build - Build Docker images"
	@echo "  make docker-up    - Start services"
	@echo "  make docker-down  - Stop services"

install:
	pip install -r requirements.txt

dev-install:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	pytest tests/ -v --cov=src --cov-report=html

lint:
	flake8 src/ tests/
	mypy src/
	isort --check-only src/ tests/
	black --check src/ tests/

format:
	isort src/ tests/
	black src/ tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

db-init:
	docker-compose exec api python -m src.core.database init_db

db-migrate:
	docker-compose exec api alembic upgrade head

keys-generate:
	mkdir -p keys
	docker-compose exec api python -m src.evidence.signer generate_keys --output-dir /app/keys
```

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton