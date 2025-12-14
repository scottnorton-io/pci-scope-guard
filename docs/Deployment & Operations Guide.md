# Deployment & Operations Guide

**Complete deployment documentation for all environments**

---

## Quick Start (5 Minutes)

### Prerequisites

```bash
# Required
- Docker 24+
- Docker Compose 2.20+
- Python 3.11+
- AWS/Azure/GCP credentials

# Optional
- Kubernetes 1.28+
- Terraform 1.6+
- Helm 3.12+
```

### One-Command Deploy

```bash
git clone [https://github.com/your-org/pci-scope-guard.git](https://github.com/your-org/pci-scope-guard.git)
cd pci-scope-guard

# Configure environment
cp .env.example .env
vim .env  # Add your cloud credentials

# Deploy with Docker Compose
docker-compose up -d

# Run initial scan
docker-compose exec api pci-scope-guard scan --cloud aws

# Access dashboard
open [http://localhost:8080](http://localhost:8080)
```

---

## Production Deployment

### AWS Deployment (Terraform)

```bash
cd terraform/examples/aws-production

# Initialize
terraform init

# Review plan
terraform plan \
  -var="aws_region=us-east-1" \
  -var="environment=production" \
  -var="database_instance_class=db.t3.large"

# Deploy
terraform apply

# Outputs
terraform output api_endpoint
terraform output dashboard_url
```

### Kubernetes Deployment (Helm)

```bash
# Add Helm repository
helm repo add pci-scope-guard [https://charts.pci-scope-guard.io](https://charts.pci-scope-guard.io)
helm repo update

# Install
helm install pci-scope-guard pci-scope-guard/pci-scope-guard \
  --namespace pci-scope-guard \
  --create-namespace \
  --set aws.enabled=true \
  --set aws.accessKeyId=AKIA... \
  --set aws.secretAccessKey=... \
  --set postgresql.enabled=true \
  --set redis.enabled=true

# Verify
kubectl get pods -n pci-scope-guard
kubectl logs -f deployment/pci-scope-guard-api -n pci-scope-guard
```

---

## Configuration

### Environment Variables

```bash
# Core
ENV=production
LOG_LEVEL=info
SECRET_KEY=<generate-with-openssl>

# Database
DATABASE_URL=postgresql://user:pass@host:5432/pci_scope_guard
REDIS_URL=redis://host:6379/0

# AWS
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_ENABLE_FLOW_LOGS=true

# Azure (optional)
AZURE_SUBSCRIPTION_ID=...
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...

# GCP (optional)
GCP_PROJECT_ID=...
GCP_CREDENTIALS_PATH=/secrets/gcp-key.json

# Integrations
VANTA_API_KEY=...
VANTA_API_URL=[https://api.vanta.com/v1](https://api.vanta.com/v1)
DRATA_API_KEY=...
SECUREFRAME_API_KEY=...

# Evidence Signing
SIGNING_KEY_PATH=/secrets/signing-key.pem
SIGNING_ALGORITHM=ES256

# Monitoring
PROMETHEUS_PORT=9090
GRAFANA_URL=[http://grafana:3000](http://grafana:3000)
JAEGER_AGENT_HOST=jaeger
JAEGER_AGENT_PORT=6831
```

---

## Operations

### Running Scans

```bash
# Full scan across all clouds
pci-scope-guard scan --all

# AWS only
pci-scope-guard scan --cloud aws --region us-east-1

# Specific VPCs
pci-scope-guard scan --cloud aws --vpc vpc-12345

# With classification
pci-scope-guard scan --cloud aws --classify

# Generate evidence after scan
pci-scope-guard scan --cloud aws --generate-evidence
```

### Scope Management

```bash
# View scope summary
pci-scope-guard scope summary

# List CDE resources
pci-scope-guard scope list --scope cde

# Classify specific resource
pci-scope-guard scope classify i-1234567890abcdef0 --scope cde --reason "Processes card payments"

# Validate segmentation
pci-scope-guard scope validate-segmentation

# Generate scope report
pci-scope-guard scope report --format pdf --output scope-report.pdf
```

### Evidence Management

```bash
# Generate evidence package
pci-scope-guard evidence generate --requirement 1.2.4

# Verify evidence signature
pci-scope-guard evidence verify <evidence-id>

# Export for assessor
pci-scope-guard evidence export --start-date 2025-01-01 --end-date 2025-12-31 --format zip

# List all evidence
pci-scope-guard evidence list --requirement-id 1.2.4
```

### GRC Integration

```bash
# Sync to Vanta
pci-scope-guard integrations sync vanta

# Sync to Drata
pci-scope-guard integrations sync drata

# Sync to all
pci-scope-guard integrations sync-all

# Check sync status
pci-scope-guard integrations status
```

---

## Monitoring

### Health Checks

```bash
# API health
curl [http://localhost:8000/health](http://localhost:8000/health)

# Database connection
curl [http://localhost:8000/health/db](http://localhost:8000/health/db)

# Redis connection
curl [http://localhost:8000/health/redis](http://localhost:8000/health/redis)

# Worker queue
curl [http://localhost:8000/health/workers](http://localhost:8000/health/workers)
```

### Metrics

```bash
# Prometheus metrics endpoint
curl [http://localhost:8000/metrics](http://localhost:8000/metrics)

# Key metrics:
# - pci_scope_guard_resources_total{scope="cde"}
# - pci_scope_guard_scan_duration_seconds
# - pci_scope_guard_classification_accuracy
# - pci_scope_guard_api_requests_total
# - pci_scope_guard_evidence_generated_total
```

### Grafana Dashboards

Pre-built dashboards included:

- **PCI Scope Overview**: Resource counts by scope
- **Network Topology**: Real-time CDE boundary visualization
- **Compliance Metrics**: Evidence generation and validation rates
- **System Performance**: API latency, database queries, worker throughput
- **Security Alerts**: Segmentation violations, drift detection

---

## Troubleshooting

### Common Issues

**Issue**: Scan fails with "Access Denied"

```bash
# Verify IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/pci-scope-guard \
  --action-names ec2:DescribeInstances ec2:DescribeVpcs

# Required permissions documented in docs/integrations/[aws.md](http://aws.md)
```

**Issue**: No data flows detected

```bash
# Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs

# Wait 5-10 minutes for data collection
pci-scope-guard scan --cloud aws --force-flow-analysis
```

**Issue**: Database migrations failing

```bash
# Check current version
alembic current

# Roll back one version
alembic downgrade -1

# Apply migrations
alembic upgrade head

# If stuck, reset (CAUTION: data loss)
docker-compose down -v
docker-compose up -d
pci-scope-guard db init
```

---

## Backup & Recovery

### Database Backup

```bash
# Automated daily backups
pg_dump -h [localhost](http://localhost) -U pci_scope_guard pci_scope_guard | gzip > backup-$(date +%Y%m%d).sql.gz

# Upload to S3
aws s3 cp backup-$(date +%Y%m%d).sql.gz s3://backups/pci-scope-guard/

# Retention: 90 days
```

### Evidence Archive

```bash
# Evidence is immutable and stored in S3 with versioning
# Retention: 7 years (PCI requirement)
# Object Lock: Governance mode

aws s3api put-object-legal-hold \
  --bucket evidence-bucket \
  --key evidence/2025/evidence-123.json \
  --legal-hold Status=ON
```

### Disaster Recovery

```bash
# Restore from backup
gunzip -c backup-20251213.sql.gz | psql -h [localhost](http://localhost) -U pci_scope_guard pci_scope_guard

# Re-run classification
pci-scope-guard scope reclassify --all

# Verify evidence integrity
pci-scope-guard evidence verify-all
```

---

## Security Hardening

### Network Security

```yaml
# Firewall rules (example for AWS Security Groups)
Ingress:
  - Port 443: HTTPS from assessor IPs only
  - Port 5432: PostgreSQL from API subnets only
  - Port 6379: Redis from API subnets only

Egress:
  - Port 443: Cloud provider APIs
  - Port 443: GRC platform APIs
```

### Secrets Management

```bash
# Use AWS Secrets Manager
aws secretsmanager create-secret \
  --name pci-scope-guard/database \
  --secret-string '{"username":"admin","password":"..."}'

# Rotate credentials every 90 days
aws secretsmanager rotate-secret \
  --secret-id pci-scope-guard/database \
  --rotation-lambda-arn arn:aws:lambda:...
```

### Audit Logging

```bash
# All API calls logged with:
# - User identity
# - IP address
# - Action performed
# - Resource affected
# - Timestamp
# - Result (success/failure)

# View audit log
pci-scope-guard audit list --user [scott@example.com](mailto:scott@example.com) --action classify_resource

# Export for compliance
pci-scope-guard audit export --start-date 2025-01-01 --format csv
```

---

## Upgrades

### Zero-Downtime Upgrade

```bash
# Pull latest version
docker pull pci-scope-guard/api:latest

# Run database migrations
docker-compose run --rm api alembic upgrade head

# Rolling update
docker-compose up -d --no-deps --build api

# Verify
curl [http://localhost:8000/version](http://localhost:8000/version)
```

### Kubernetes Rolling Update

```bash
# Update Helm chart
helm upgrade pci-scope-guard pci-scope-guard/pci-scope-guard \
  --namespace pci-scope-guard \
  --reuse-values \
  --set image.tag=v2.0.0

# Watch rollout
kubectl rollout status deployment/pci-scope-guard-api -n pci-scope-guard
```

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton

**License**: MIT
