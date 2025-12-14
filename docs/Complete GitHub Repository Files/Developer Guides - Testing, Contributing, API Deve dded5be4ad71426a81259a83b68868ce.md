# Developer Guides - Testing, Contributing, API Development

# Developer Guides

**Complete documentation for contributors and developers extending PCI Scope Guard**

---

## Testing Guide

### Test Structure

```
tests/
├── unit/                    # Fast, isolated tests
│   ├── test_[models.py](http://models.py)
│   ├── test_[classifier.py](http://classifier.py)
│   ├── test_[evidence.py](http://evidence.py)
│   └── test_[discovery.py](http://discovery.py)
├── integration/             # Tests with external dependencies
│   ├── test_aws_[integration.py](http://integration.py)
│   ├── test_[database.py](http://database.py)
│   └── test_grc_[sync.py](http://sync.py)
├── e2e/                     # End-to-end scenarios
│   ├── test_full_[scan.py](http://scan.py)
│   └── test_evidence_[workflow.py](http://workflow.py)
├── fixtures/                # Test data and mocks
│   ├── aws_responses.json
│   ├── sample_flows.json
│   └── test_keys/
└── [conftest.py](http://conftest.py)             # Pytest configuration
```

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run specific test file
pytest tests/unit/test_[classifier.py](http://classifier.py)

# Run specific test
pytest tests/unit/test_[classifier.py](http://classifier.py)::test_cde_classification

# Run with coverage
pytest --cov=src --cov-report=html

# Run only unit tests (fast)
pytest tests/unit/

# Run with verbose output
pytest -v

# Run tests matching pattern
pytest -k "classifier"

# Stop on first failure
pytest -x

# Show print statements
pytest -s
```

### Writing Unit Tests

**Example: Testing Scope Classifier**

```python
# tests/unit/test_[classifier.py](http://classifier.py)
import pytest
from unittest.mock import Mock, patch
from src.analysis.scope_classifier import ScopeClassifier, ClassificationResult
from src.core.models import Resource, PCIScope

@pytest.fixture
def db_session():
    """Mock database session"""
    return Mock()

@pytest.fixture
def classifier(db_session):
    """Classifier instance with mocked DB"""
    return ScopeClassifier(db_session)

@pytest.fixture
def payment_resource():
    """Sample CDE resource"""
    return Resource(
        resource_id="i-payment123",
        resource_type="ec2_instance",
        resource_name="payment-api-prod",
        vpc_id="vpc-abc123",
        tags={"Name": "payment-api-prod", "Environment": "production"}
    )

def test_cde_keyword_detection(classifier, payment_resource):
    """Test that resources with payment keywords are classified as CDE"""
    result = classifier._check_cde_keywords(payment_resource)
    
    assert result is True
    assert "payment" in payment_resource.resource_name.lower()

def test_classification_confidence_scoring(classifier, payment_resource):
    """Test confidence score calculation"""
    result = classifier.classify_resource(payment_resource)
    
    assert isinstance(result, ClassificationResult)
    assert result.scope == PCIScope.CDE
    assert result.confidence_score["keyword_match"] > 0.8
    assert len(result.justification) > 0

def test_connected_resource_detection(classifier, db_session):
    """Test detection of resources connected to CDE"""
    # Mock CDE resource
    cde_resource = Mock(id=1, scope=PCIScope.CDE)
    
    # Mock data flow showing connection
    db_session.query().filter().all.return_value = [Mock(dest_resource_id=1)]
    
    result = classifier._check_connected_to_cde(Mock(id=2))
    
    assert result is True

@pytest.mark.parametrize("resource_name,expected_scope", [
    ("payment-api", PCIScope.CDE),
    ("tokenization-service", PCIScope.CDE),
    ("analytics-worker", PCIScope.OUT_OF_SCOPE),
    ("app-server-connected-to-payment", PCIScope.CONNECTED_CDE),
])
def test_classification_by_name(classifier, resource_name, expected_scope):
    """Test classification based on resource naming"""
    resource = Resource(
        resource_id=f"i-{resource_name}",
        resource_type="ec2_instance",
        resource_name=resource_name,
        vpc_id="vpc-test"
    )
    
    result = classifier.classify_resource(resource)
    assert result.scope == expected_scope
```

### Writing Integration Tests

**Example: Testing AWS Discovery**

```python
# tests/integration/test_aws_[integration.py](http://integration.py)
import pytest
import boto3
from moto import mock_ec2, mock_rds
from [src.discovery.aws](http://src.discovery.aws)_discovery import AWSDiscoveryAgent
from src.core.database import get_db_context

@pytest.fixture
def aws_credentials(monkeypatch):
    """Mock AWS credentials"""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")

@mock_ec2
def test_ec2_discovery(aws_credentials):
    """Test EC2 instance discovery"""
    # Create mock EC2 instances
    ec2 = boto3.client("ec2", region_name="us-east-1")
    [ec2.run](http://ec2.run)_instances(
        ImageId="ami-12345",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": "test-instance"}]
        }]
    )
    
    # Run discovery
    with get_db_context() as db:
        agent = AWSDiscoveryAgent(db, region="us-east-1")
        resources = [agent.discover](http://agent.discover)_ec2_instances()
    
    assert len(resources) == 1
    assert resources[0].resource_type == "ec2_instance"
    assert resources[0].resource_name == "test-instance"

@mock_rds
def test_rds_discovery(aws_credentials):
    """Test RDS discovery"""
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="payment-db",
        DBInstanceClass="db.t2.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123"
    )
    
    with get_db_context() as db:
        agent = AWSDiscoveryAgent(db, region="us-east-1")
        resources = [agent.discover](http://agent.discover)_rds_instances()
    
    assert len(resources) == 1
    assert "payment" in resources[0].resource_name
```

### Writing E2E Tests

**Example: Full Scan Workflow**

```python
# tests/e2e/test_full_[scan.py](http://scan.py)
import pytest
import asyncio
from [src.discovery.aws](http://src.discovery.aws)_discovery import run_aws_discovery
from src.analysis.scope_classifier import bulk_classify
from src.evidence.generator import generate_all_evidence

@pytest.mark.e2e
@pytest.mark.asyncio
async def test_complete_scan_workflow():
    """Test complete scan, classify, and evidence generation"""
    
    # Step 1: Run discovery
    stats = await run_aws_discovery(region="us-east-1")
    assert stats["resources_discovered"] > 0
    
    # Step 2: Classify resources
    classification_stats = bulk_classify()
    assert classification_stats["processed"] > 0
    assert classification_stats["pending"] == 0
    
    # Step 3: Generate evidence
    evidence_list = generate_all_evidence()
    assert len(evidence_list) > 0
    
    # Step 4: Verify evidence signatures
    for evidence in evidence_list:
        assert evidence.signature is not None
        assert evidence.hash is not None
```

### Test Fixtures and Mocks

[**conftest.py**](http://conftest.py)

```python
# tests/[conftest.py](http://conftest.py)
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.core.models import Base
from src.evidence.signer import EvidenceSigner
import tempfile

@pytest.fixture(scope="session")
def test_db_engine():
    """Create test database engine"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def db_session(test_db_engine):
    """Create database session for each test"""
    Session = sessionmaker(bind=test_db_engine)
    session = Session()
    
    yield session
    
    session.rollback()
    session.close()

@pytest.fixture
def test_keys():
    """Generate temporary signing keys for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        private_key, public_key = EvidenceSigner.generate_key_pair(tmpdir)
        yield {"private": private_key, "public": public_key}

@pytest.fixture
def sample_vpc_flow_log():
    """Sample VPC Flow Log entry"""
    return {
        "srcaddr": "10.0.1.50",
        "dstaddr": "10.0.2.100",
        "srcport": 45678,
        "dstport": 443,
        "protocol": 6,
        "packets": 10,
        "bytes": 5000,
        "start": 1609459200,
        "end": 1609459260
    }
```

### Code Coverage

**Target: 80%+ coverage**

```bash
# Generate HTML coverage report
pytest --cov=src --cov-report=html
open htmlcov/index.html

# Show coverage in terminal
pytest --cov=src --cov-report=term-missing

# Fail if coverage below threshold
pytest --cov=src --cov-fail-under=80
```

---

## Contributing Guide

### Development Workflow

**1. Fork and Clone**

```bash
# Fork on GitHub
# Clone your fork
git clone 165
cd pci-scope-guard

# Add upstream remote
git remote add upstream 166
```

**2. Create Feature Branch**

```bash
# Update main
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/aws-gov-cloud-support
```

**3. Make Changes**

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Make your changes
vim src/discovery/aws_[discovery.py](http://discovery.py)

# Run tests frequently
pytest tests/unit/test_[discovery.py](http://discovery.py)

# Format code
black src/ tests/
isort src/ tests/

# Lint
flake8 src/
mypy src/
```

**4. Commit**

```bash
# Stage changes
git add src/discovery/aws_[discovery.py](http://discovery.py) tests/unit/test_[discovery.py](http://discovery.py)

# Commit with descriptive message
git commit -m "feat: add AWS GovCloud region support

- Add gov-cloud region detection
- Update IAM policy examples
- Add tests for GovCloud endpoints

Closes #42"
```

**5. Push and Create PR**

```bash
# Push to your fork
git push origin feature/aws-gov-cloud-support

# Create Pull Request on GitHub
# Fill out PR template
```

### Commit Message Convention

Use [Conventional Commits](167):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code restructuring
- `perf`: Performance improvement
- `test`: Adding tests
- `chore`: Build process, dependencies

**Examples:**

```
feat(discovery): add Azure NSG Flow Log analysis

fix(classifier): correct confidence score calculation for edge cases

docs(compliance): update PCI DSS v4.0.1 mapping

test(integration): add tests for GCP service account rotation
```

### Code Standards

**Python Style**

```python
# Use type hints
def classify_resource(resource: Resource) -> ClassificationResult:
    pass

# Docstrings for all public functions
def discover_ec2_instances(region: str) -> List[Resource]:
    """
    Discover all EC2 instances in the specified region.
    
    Args:
        region: AWS region name (e.g., 'us-east-1')
        
    Returns:
        List of Resource objects representing EC2 instances
        
    Raises:
        AWSDiscoveryError: If discovery fails
    """
    pass

# Use descriptive variable names
for cde_resource in cde_resources:
    process_resource(cde_resource)

# Avoid magic numbers
MAX_RETRIES = 3
DEFAULT_TIMEOUT_SECONDS = 30
```

**Error Handling**

```python
# Specific exceptions
try:
    response = ec2.describe_instances()
except ClientError as e:
    if e.response["Error"]["Code"] == "UnauthorizedOperation":
        logger.error("Insufficient IAM permissions")
        raise AWSPermissionError("Missing ec2:DescribeInstances")
    raise

# Log before raising
logger.error(f"Failed to discover instances: {e}")
raise
```

### Pull Request Checklist

Before submitting:

- [ ]  Tests pass locally (`make test`)
- [ ]  Code is formatted (`make format`)
- [ ]  Linters pass (`make lint`)
- [ ]  Type hints added for new functions
- [ ]  Docstrings added for public APIs
- [ ]  Tests added for new features
- [ ]  Documentation updated
- [ ]  [CHANGELOG.md](http://CHANGELOG.md) updated
- [ ]  No merge conflicts with main

---

## API Development Guide

### Adding New REST Endpoints

**1. Define Route**

```python
# src/api/rest/routes/[resources.py](http://resources.py)
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from ...core.database import get_db
from ...core.models import Resource
from .schemas import ResourceResponse

router = APIRouter(prefix="/api/v1/resources", tags=["resources"])

@router.get("/", response_model=List[ResourceResponse])
def list_resources(
    scope: Optional[str] = None,
    provider: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    List resources with optional filtering.
    
    - **scope**: Filter by PCI scope (cde, connected-cde, out-of-scope)
    - **provider**: Filter by cloud provider (aws, azure, gcp)
    - **limit**: Maximum number of results (default: 100)
    """
    query = db.query(Resource)
    
    if scope:
        query = query.join(ScopeDecision).filter(
            ScopeDecision.scope == scope,
            [ScopeDecision.is](http://ScopeDecision.is)_current == True
        )
    
    if provider:
        query = query.filter(Resource.provider == provider)
    
    resources = query.limit(limit).all()
    return resources

@router.get("/{resource_id}", response_model=ResourceResponse)
def get_resource(
    resource_id: str,
    db: Session = Depends(get_db)
):
    """Get a single resource by ID."""
    resource = db.query(Resource).filter(
        Resource.resource_id == resource_id
    ).first()
    
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    
    return resource
```

**2. Define Schemas**

```python
# src/api/rest/[schemas.py](http://schemas.py)
from pydantic import BaseModel, Field
from typing import Optional, Dict
from datetime import datetime

class ResourceResponse(BaseModel):
    """Resource API response schema"""
    resource_id: str
    resource_type: str
    resource_name: str
    provider: str
    vpc_id: Optional[str]
    region: str
    tags: Dict[str, str]
    discovered_at: datetime
    
    class Config:
        orm_mode = True

class ClassifyResourceRequest(BaseModel):
    """Request to manually classify a resource"""
    scope: str = Field(..., regex="^(cde|connected-cde|out-of-scope)$")
    justification: str = Field(..., min_length=10)
    decided_by: str
```

**3. Add Tests**

```python
# tests/unit/test_api_[resources.py](http://resources.py)
from fastapi.testclient import TestClient
from [src.api.rest](http://src.api.rest).main import app

client = TestClient(app)

def test_list_resources():
    response = client.get("/api/v1/resources/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_resource_not_found():
    response = client.get("/api/v1/resources/nonexistent")
    assert response.status_code == 404

def test_classify_resource():
    payload = {
        "scope": "cde",
        "justification": "Processes payment card data",
        "decided_by": "[security-team@company.com](mailto:security-team@company.com)"
    }
    response = [client.post](http://client.post)("/api/v1/resources/i-123/classify", json=payload)
    assert response.status_code == 200
```

### Adding GraphQL Queries

**1. Define Types**

```python
# src/api/graphql/[types.py](http://types.py)
import strawberry
from typing import Optional, List
from datetime import datetime

@strawberry.type
class Resource:
    resource_id: str
    resource_type: str
    resource_name: str
    provider: str
    vpc_id: Optional[str]
    region: str
    discovered_at: datetime
    
    @strawberry.field
    def scope_decision(self) -> Optional["ScopeDecision"]:
        # Fetch current scope decision
        pass

@strawberry.type
class ScopeDecision:
    scope: str
    justification: str
    confidence_score: float
    decided_at: datetime
    decided_by: str
```

**2. Define Queries**

```python
# src/api/graphql/[queries.py](http://queries.py)
import strawberry
from typing import List, Optional

@strawberry.type
class Query:
    @strawberry.field
    def resources(
        self,
        scope: Optional[str] = None,
        provider: Optional[str] = None
    ) -> List[Resource]:
        # Implementation
        pass
    
    @strawberry.field
    def scope_summary(self) -> ScopeSummary:
        # Implementation
        pass
```

### Adding New Discovery Providers

**Example: Adding DigitalOcean Support**

```python
# src/discovery/digitalocean_[discovery.py](http://discovery.py)
from typing import List
import digitalocean
from ..core.models import Resource, CloudProvider
from .base import DiscoveryAgent

class DigitalOceanDiscoveryAgent(DiscoveryAgent):
    """
    Discovery agent for DigitalOcean resources.
    """
    
    def __init__(self, db, token: str):
        super().__init__(db, CloudProvider.DIGITALOCEAN)
        self.manager = digitalocean.Manager(token=token)
    
    def discover_droplets(self) -> List[Resource]:
        """Discover DigitalOcean Droplets"""
        resources = []
        
        for droplet in self.manager.get_all_droplets():
            resource = Resource(
                provider=CloudProvider.DIGITALOCEAN,
                resource_type="droplet",
                resource_id=str([droplet.id](http://droplet.id)),
                resource_name=[droplet.name](http://droplet.name),
                region=droplet.region["slug"],
                metadata={
                    "size": droplet.size_slug,
                    "image": droplet.image["slug"],
                    "status": droplet.status
                },
                tags={tag: "" for tag in droplet.tags}
            )
            resources.append(resource)
            self.db.add(resource)
        
        self.db.commit()
        return resources
```

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton

**Target Audience**: Contributors and Developers