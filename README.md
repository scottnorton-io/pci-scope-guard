# PCI Scope Guard

**Automated Cardholder Data Environment boundary detection and continuous compliance monitoring for cloud infrastructure.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## What is PCI Scope Guard?

PCI Scope Guard automates the most challenging aspect of PCI DSS compliance: **accurately identifying which cloud resources are in scope**. It discovers resources across AWS, Azure, and GCP, analyzes network connectivity, and automatically classifies resources as CDE (in-scope), Connected-to-CDE, or Out-of-Scope.

**Key Innovation**: Treats compliance as code, generating cryptographically-signed evidence that proves the system's own compliance.

### The Problem It Solves

QSAs and security teams waste weeks manually:
- 📋 Cataloging cloud resources from spreadsheets
- 🔍 Analyzing network flows to find CDE boundaries  
- 🏷️ Tagging resources with PCI scope classifications
- 📊 Generating evidence for assessors
- 🔄 Repeating this quarterly as infrastructure changes

**PCI Scope Guard automates all of this.**

---

## Features

### 🔍 Multi-Cloud Discovery
- **AWS**: EC2, RDS, Lambda, ELB, S3, ECS, EKS
- **Azure**: VMs, SQL, App Services, Storage (coming soon)
- **GCP**: Compute, Cloud SQL, GKE (coming soon)
- Automatic VPC/VNet Flow Log analysis
- IP-to-resource mapping

### 🎯 Intelligent Classification
- ML-enhanced scope detection
- CDE keyword analysis (payment, card, tokenization)
- Network connectivity tracing
- Confidence scoring for each decision
- Manual override support via tags

### 🔐 Compliance Evidence
- ECDSA cryptographic signing (NIST P-256)
- Compliance Evidence Format (CEF) 1.0
- 7-year retention (PCI requirement)
- Immutable audit trail
- One-click assessor export

### 🔗 GRC Integration
- Vanta bidirectional sync
- Drata API integration  
- SecureFrame custom attributes
- Export to CSV/PDF/JSON

### 📊 Real-Time Monitoring
- Scope drift detection
- Segmentation violation alerts
- Compliance dashboards
- WebSocket live updates

---

## Quick Start

### Prerequisites

#### Required

- Python 3.11+
- PostgreSQL 15+ (with TimescaleDB extension)
- Redis 7+
- Docker & Docker Compose

#### Cloud Access

- AWS credentials with read-only permissions
- Azure credentials (optional)
- GCP credentials (optional)

### Installation
```bash
# Clone repository

git clone https://github.com/scottnorton-io/pci-scope-guard.git
cd pci-scope-guard

# Create virtual environment

python3.11 -m venv venv
source venv/bin/activate  # On Windows: venvScriptsactivate


# Install dependencies

pip install -r requirements.txt

# Copy environment template

cp .env.example .env


# Edit .env with your configuration

vim .env

```

### Quick Start with Docker
```bash
# Start all services

docker-compose up -d

# Initialize database

docker-compose exec api python -m src.core.database init_db

# Generate signing keys

docker-compose exec api python -m src.evidence.signer generate_keys

# Run discovery

docker-compose exec api pci-scope-guard scan --cloud aws

# Access dashboard

open http://localhost:3000

```

---

## Usage

### Command Line Interface
```bash
# Discover AWS resources

pci-scope-guard scan --cloud aws --region us-east-1

# Classify all pending resources

pci-scope-guard classify --auto

# Generate compliance evidence

pci-scope-guard evidence generate --requirement 1.2.4

# Export for assessor

pci-scope-guard evidence export --start 2025-01-01 --format pdf

# Sync to Vanta

pci-scope-guard integrations sync vanta

# View scope summary

pci-scope-guard scope summary
```

### Python API
```python
import asyncio

from [src.discovery.aws](http://src.discovery.aws)_discovery import run_aws_discovery
from src.analysis.scope_classifier import bulk_classif
from src.evidence.generator import generate_all_evidence

# Discover resources
stats = [asyncio.run](http://asyncio.run)(run_aws_discovery(region="us-east-1"))
print(f"Discovered {stats['resources_discovered']} resources")

# Classify resources
results = bulk_classify(batch_size=100)
print(f"Classified {results['processed']} resources")

# Generate evidence
evidence = generate_all_evidence()
print(f"Generated {len(evidence)} evidence artifacts")

```

---

## Architecture
```GraphQL
graph TB

subgraph "Discovery Layer"
  AWS[AWS Discovery]
  Azure[Azure Discovery]
  GCP[GCP Discovery]
end

subgraph "Analysis Engine"
  Flow[Flow Analyzer]
  Classifier[Scope Classifier]
end

subgraph "Data Layer"
  DB[(PostgreSQL + TimescaleDB)]
  Cache[(Redis)]
end

subgraph "Compliance Layer"
  Evidence[Evidence Generator]
  Signer[Crypto Signer]
end

subgraph "Integration Layer"
  Vanta[Vanta]
  Drata[Drata]
end

AWS --> Flow
Azure --> Flow
GCP --> Flow
Flow --> Classifier
Classifier --> DB
DB --> Evidence
Evidence --> Signer
DB --> Vanta
DB --> Drata

style Classifier fill:#4ecdc4
style Evidence fill:#6bcf7f

```

---

## Configuration

### Environment Variables

See [.env.example](.env.example) for all configuration options.

**Required:**
```bash
DATABASE_URL=postgresql://user:[pass@localhost:5432](mailto:pass@localhost:5432)/pci_scope_guard
REDIS_URL=redis://[localhost:6379/0](http://localhost:6379/0)
SECRET_KEY=<generate-with-openssl-rand-hex-32>
SIGNING_KEY_PATH=/path/to/signing-key.pem
```

**AWS:**
```bash
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

**GRC Integration:**
```bash
VANTA_API_KEY=...
DRATA_API_KEY=...
```

---

## Deployment

### Docker Compose (Development)
```bash
docker-compose up -d
```

### Kubernetes (Production)
```bash
# Install with Helm

helm install pci-scope-guard ./deployment/helm/pci-scope-guard \
--set aws.enabled=true \
--set aws.region=us-east-1 \
--namespace pci-scope-guard
```

### Terraform (Infrastructure)
```bash
cd terraform/examples/aws-production
terraform init
terraform apply
```

See [Deployment Guide](docs/guides/deployment.md) for detailed instructions.

---

## Documentation

- [Architecture Overview](docs/architecture/system-design.md)
- [Installation Guide](docs/guides/installation.md)
- [User Guide](docs/guides/user-guide.md)
- [API Reference](docs/api/rest-api.md)
- [Integration Guides](docs/integrations/)
- [PCI DSS Mapping](docs/compliance/pci-dss-mapping.md)
- [Assessor Guide](docs/compliance/assessor-guide.md)

---

## Security

### Cryptographic Signing

All compliance evidence is signed with ECDSA (NIST P-256 curve):

#### Generate keys (run once)
```python
from src.evidence.signer import EvidenceSigner
private, public = EvidenceSigner.generate_key_pair('./keys')
```

#### Verification
```python
signer = EvidenceSigner(private_key_path='./keys/signing-key.pem',
public_key_path='./keys/[signing-key.pub](http://signing-key.pub)')
valid = signer.verify_signature(evidence_data, signature)
```

### IAM Permissions

PCI Scope Guard requires **read-only** permissions:

**AWS Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
      {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:Describe*",
        "elasticloadbalancing:Describe*",
        "lambda:List*",
        "lambda:Get*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketTagging",
        "ecs:Describe*",
        "eks:Describe*",
        "logs:StartQuery",
        "logs:GetQueryResults"
        ],
      "Resource": "*"
    }
  ]
}
```

See [AWS Integration Guide](docs/integrations/aws.md) for detailed permissions.

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

### Development Setup
```bash
# Install dev dependencies

pip install -r requirements-dev.txt

# Run tests

pytest

# Run with coverage

pytest --cov=src --cov-report=html

# Format code

black src/ tests/

# Lint

flake8 src/ tests/
mypy src/
```

---

## Roadmap

- [x] AWS discovery with VPC Flow Logs
- [x] Scope classification engine
- [x] Evidence generator with crypto signing
- [ ] Azure discovery with NSG Flow Logs
- [ ] GCP discovery with VPC Flow Logs  
- [ ] REST API (FastAPI)
- [ ] GraphQL API (Strawberry)
- [ ] React dashboard with network visualization
- [ ] ML model for classification confidence
- [ ] Multi-region support
- [ ] Compliance-as-code policies

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Support

- 📧 Email: scott@johansonllp.com
- 🐛 Issues: [GitHub Issues](https://github.com/scottnorton-io/pci-scope-guard/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/scottnorton-io/pci-scope-guard/discussions)

---

## Acknowledgments

Built with:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [TimescaleDB](https://www.timescale.com/) - Time-series PostgreSQL
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) - AWS SDK
- [cryptography](https://cryptography.io/) - Cryptographic signing

Inspired by the need to make PCI DSS compliance less painful for cloud-native organizations.

---

**Built with ❤️ by [Scott Norton](https://github.com/scottnorton-io)**
