# Compliance Documentation - PCI DSS Mapping & Assessor Guide

# Compliance Documentation

**PCI DSS v4.0 requirement mapping, assessor guide, and evidence formats**

---

## PCI DSS v4.0 Requirements Mapping

### How PCI Scope Guard Addresses PCI DSS Requirements

### Requirement 1: Install and Maintain Network Security Controls

**1.2.4** - All system components are assigned to a network zone

**PCI Scope Guard Implementation:**

- ✅ **Automated Discovery**: Discovers all system components across AWS, Azure, GCP
- ✅ **Network Zone Assignment**: Maps resources to VPCs, VNets, network segments
- ✅ **Continuous Monitoring**: Detects new resources and assigns zones automatically
- ✅ **Evidence Generated**: `scope_identification_evidence` with complete resource inventory

**Testing Procedure 1.2.4.a**: Examine documentation to verify system components are assigned to network zones

- **PCI Scope Guard Provides**: Auto-generated inventory with network assignments
- **Export Command**: `pci-scope-guard evidence export --requirement 1.2.4`

**Testing Procedure 1.2.4.b**: Interview personnel and examine network diagrams

- **PCI Scope Guard Provides**: Real-time network topology visualization
- **Dashboard**: Interactive diagram showing all network zones and connections

---

**1.2.5** - All security controls are identified for each network zone

**PCI Scope Guard Implementation:**

- ✅ **Security Group Analysis**: Catalogs all security groups, NSGs, firewall rules
- ✅ **Control Mapping**: Links each resource to its security controls
- ✅ **Gap Detection**: Identifies resources without appropriate controls
- ✅ **Evidence Generated**: `network_segmentation_validation` report

---

**1.2.7** - Configurations of network security controls are reviewed at least once every six months

**PCI Scope Guard Implementation:**

- ✅ **Continuous Scanning**: Runs discovery on configurable schedule
- ✅ **Configuration Drift Detection**: Alerts on security control changes
- ✅ **Audit Trail**: Maintains 7-year history of all configuration reviews
- ✅ **Automated Alerts**: Notifies on violations or drift

---

**1.3.1** - Inbound traffic to the CDE is restricted

**PCI Scope Guard Implementation:**

- ✅ **Flow Analysis**: Analyzes VPC/NSG Flow Logs to identify all inbound connections
- ✅ **Violation Detection**: Identifies unauthorized inbound traffic to CDE
- ✅ **Segmentation Testing**: Validates CDE isolation from out-of-scope networks
- ✅ **Evidence Generated**: `data_flow_analysis` showing all inbound connections

---

**1.3.2** - Outbound traffic from the CDE is restricted

**PCI Scope Guard Implementation:**

- ✅ **Egress Analysis**: Tracks all outbound connections from CDE resources
- ✅ **Whitelist Validation**: Verifies only approved destinations are reached
- ✅ **Alert on Violations**: Notifies when CDE connects to unauthorized systems

---

### Requirement 3: Protect Stored Account Data

**3.5.1** - Cryptographic keys used to protect stored account data are documented

**PCI Scope Guard Implementation:**

- ✅ **Encryption Detection**: Identifies encrypted RDS, S3, disk volumes
- ✅ **Key Management Inventory**: Catalogs KMS keys, key vaults
- ✅ **CDE Data Classification**: Tags resources storing cardholder data
- ✅ **Evidence**: `configuration_snapshot` includes encryption status

---

### Requirement 11: Test Security of Systems and Networks Regularly

**11.3.1** - Internal vulnerability scans are performed quarterly

**PCI Scope Guard Implementation:**

- ✅ **Scope Definition for Scans**: Provides accurate CDE inventory for vulnerability scanners
- ✅ **Integration Ready**: Exports scope data to Tenable, Qualys, Rapid7
- ✅ **Scan Coverage Validation**: Ensures all CDE resources are included in scans

---

**11.3.2** - External vulnerability scans are performed quarterly by a PCI SSC Approved Scanning Vendor (ASV)

**PCI Scope Guard Implementation:**

- ✅ **Public-Facing Resource Identification**: Lists all resources with public IPs
- ✅ **ASV Scope Definition**: Generates IP lists for external scanners
- ✅ **Scope Changes**: Alerts when new public resources are added

---

### Requirement 12: Support Information Security with Organizational Policies and Programs

**12.5.2** - Scope of PCI DSS assessment is documented

**PCI Scope Guard Implementation:**

- ✅ **Complete Scope Documentation**: Auto-generates comprehensive scope report
- ✅ **Cryptographic Attestation**: Signs scope decisions with ECDSA keys
- ✅ **Assessor-Ready Export**: One-click PDF/JSON export for QSAs
- ✅ **Version Control**: Maintains full history of scope changes

---

**12.5.2.1** - The frequency of scoping reviews is defined

**PCI Scope Guard Implementation:**

- ✅ **Continuous Review**: Runs discovery daily, weekly, or on-demand
- ✅ **Scheduled Classification**: Automatically reclassifies resources quarterly
- ✅ **Review Tracking**: Logs all scope validation activities

---

### Complete Requirements Coverage Matrix

| PCI DSS Requirement | Description | PCI Scope Guard Feature | Evidence Type | Status |
| --- | --- | --- | --- | --- |
| 1.2.4 | System components assigned to zones | Auto-discovery + zone assignment | scope_identification | ✅ |
| 1.2.5 | Security controls identified | Security group analysis | configuration_snapshot | ✅ |
| 1.2.7 | Review controls every 6 months | Continuous scanning + drift alerts | tag_audit_trail | ✅ |
| 1.3.1 | Restrict inbound to CDE | Flow log analysis | network_segmentation | ✅ |
| 1.3.2 | Restrict outbound from CDE | Egress flow analysis | data_flow_analysis | ✅ |
| 3.5.1 | Document crypto keys | Encryption detection | configuration_snapshot | ✅ |
| 11.3.1 | Internal vulnerability scans | Scope export for scanners | scope_identification | ✅ |
| 11.3.2 | External ASV scans | Public IP inventory | scope_identification | ✅ |
| 12.5.2 | Document PCI DSS scope | Cryptographic evidence export | All evidence types | ✅ |
| 12.5.2.1 | Define scope review frequency | Scheduled scanning + review logs | tag_audit_trail | ✅ |

---

## Assessor Guide

### For Qualified Security Assessors (QSAs) and Internal Security Assessors (ISAs)

### How to Use PCI Scope Guard During an Assessment

**Pre-Assessment Phase**

1. **Request Access**
    - Entity provides read-only access to PCI Scope Guard dashboard
    - Alternative: Entity exports evidence package
2. **Review Scope Documentation**
    
    ```bash
    # Entity runs:
    pci-scope-guard evidence export \
      --start-date 2025-01-01 \
      --end-date 2025-12-31 \
      --format pdf \
      --output pci-scope-evidence-2025.pdf
    ```
    
3. **Verify Evidence Signatures**
    
    ```bash
    # Assessor verifies cryptographic signature:
    pci-scope-guard evidence verify <evidence-id>
    
    # Output shows:
    # ✓ Signature valid
    # ✓ Hash matches: a3f2e8b9...
    # ✓ Signed by: ecdsa-sha256:abc123...
    # ✓ Signed at: 2025-06-15T10:30:00Z
    ```
    

**Assessment Phase - Testing 1.2.4 (System Component Assignment)**

1. **Examine Documentation** (1.2.4.a)
    - Open PCI Scope Guard dashboard or exported evidence
    - Verify each system component has:
        - Resource ID
        - Resource type
        - Network zone (VPC/VNet)
        - Scope classification (CDE, Connected, Out-of-Scope)
        - Justification for classification
2. **Interview Personnel** (1.2.4.b)
    - Ask: "How do you identify which systems are in scope?"
    - Expected answer: "PCI Scope Guard discovers all resources and automatically classifies them based on network connectivity and data flows"
3. **Examine Network Diagrams** (1.2.4.c)
    - PCI Scope Guard provides real-time network topology
    - Verify CDE boundaries are clearly defined
    - Check for segmentation between zones

**Sample Assessment Questions**

Q: "How often do you review scope?"

A: "PCI Scope Guard runs discovery weekly. Classification reviews are performed quarterly with evidence generated each time."

Q: "How do you detect scope changes?"

A: "PCI Scope Guard alerts us immediately when new resources are discovered or when existing resources change network connectivity."

Q: "Can you prove this resource is in scope?"

A: "Yes, here's the scope decision with cryptographic signature, timestamp, classification justification, and network flow evidence."

**Verification Steps for Assessors**

✅ **Step 1**: Verify all cloud accounts are scanned

```bash
# Check discovery coverage
pci-scope-guard integrations status

# Expected output:
# AWS: ✓ Connected (last scan: 2 hours ago)
# Azure: ✓ Connected (last scan: 3 hours ago)
# GCP: ✓ Connected (last scan: 1 hour ago)
```

✅ **Step 2**: Validate scope decisions have justifications

```bash
pci-scope-guard scope list --scope cde --show-justification
```

✅ **Step 3**: Check for pending reviews

```bash
pci-scope-guard scope summary

# Should show:
# CDE: 45 resources
# Connected-to-CDE: 120 resources
# Out-of-Scope: 892 resources
# Pending Review: 0 resources ← Should be zero
```

✅ **Step 4**: Verify evidence retention (7 years for PCI)

```bash
# Check oldest evidence
pci-scope-guard evidence list --oldest

# Verify retention policy
pci-scope-guard evidence retention-policy
```

✅ **Step 5**: Test segmentation validation

```bash
pci-scope-guard scope validate-segmentation

# Should show zero violations:
# ✓ All CDE resources properly segmented
# ✓ No out-of-scope to CDE connections
# ✗ Found 2 violations (details below) ← Investigate if present
```

**Red Flags for Assessors**

🚩 **High number of "Pending Review" resources**

- Indicates incomplete scope identification
- Request timeline for completion

🚩 **Recent scope changes without documented justification**

- Check audit trail for scope changes
- Verify approval process

🚩 **VPC Flow Logs not enabled**

- Network connectivity cannot be verified
- Scope decisions lack supporting evidence

🚩 **Evidence signatures don't verify**

- Potential tampering
- Request fresh evidence generation

🚩 **Gaps in discovery (missing cloud accounts)**

- Incomplete scope assessment
- Request all accounts be connected

**Assessment Deliverables**

PCI Scope Guard provides everything needed for ROC/SAQ documentation:

1. **Network Diagram** (PNG/PDF export)
2. **System Component Inventory** (CSV/Excel)
3. **Scope Justification Report** (PDF with signatures)
4. **Flow Analysis Report** (Shows all network connections)
5. **Segmentation Test Results** (Pass/Fail for each boundary)
6. **Change Audit Trail** (7-year history of scope changes)

---

## Evidence Formats

### Compliance Evidence Format (CEF) v1.0

PCI Scope Guard uses CEF 1.0 for all generated evidence. CEF is a structured, machine-readable, cryptographically-signed format.

### Evidence Structure

```json
{
  "cef_version": "1.0",
  "evidence": {
    "id": "<uuid>",
    "type": "<evidence_type>",
    "timestamp": "<iso8601>",
    "collector": {
      "name": "pci-scope-guard",
      "version": "1.0.0"
    },
    "compliance_context": {
      "framework": "PCI-DSS",
      "version": "4.0",
      "requirement_id": "1.2.4",
      "testing_procedure": "1.2.4.a"
    },
    "data": { /* Evidence-specific payload */ },
    "signature": {
      "algorithm": "ECDSA-SHA256",
      "hash": "<sha256_hex>",
      "signature": "<base64_signature>",
      "key_id": "<key_identifier>",
      "signed_at": "<iso8601>"
    }
  }
}
```

### Evidence Types

**1. Scope Identification Evidence** (`pci_scope_identification`)

Generated for: PCI DSS 1.2.4, 12.5.2

```json
{
  "type": "pci_scope_identification",
  "data": {
    "period": {
      "start": "2025-01-01T00:00:00Z",
      "end": "2025-12-31T23:59:59Z"
    },
    "scope_summary": {
      "total_resources": 1057,
      "cde_resources": 45,
      "connected_resources": 120,
      "out_of_scope": 892
    },
    "resources": {
      "cde": [
        {
          "resource_id": "i-1234567890abcdef0",
          "resource_type": "ec2_instance",
          "provider": "aws",
          "name": "payment-api-prod-01",
          "vpc_id": "vpc-abc123",
          "region": "us-east-1",
          "justification": "Processes cardholder data via payment API",
          "decided_at": "2025-06-15T10:30:00Z",
          "decided_by": "[security-team@company.com](mailto:security-team@company.com)",
          "confidence_score": {"keyword_match": 0.95}
        }
      ]
    }
  }
}
```

**2. Network Segmentation Validation** (`network_segmentation_validation`)

Generated for: PCI DSS 1.2.1, 1.3.1, 1.3.2

```json
{
  "type": "network_segmentation_validation",
  "data": {
    "tests_performed": 45,
    "tests_passed": 43,
    "tests_failed": 2,
    "test_results": [
      {
        "resource_id": "i-1234567890abcdef0",
        "resource_type": "ec2_instance",
        "test": "out-of-scope-isolation",
        "result": "pass",
        "violations": 0
      },
      {
        "resource_id": "i-abcdef1234567890",
        "resource_type": "ec2_instance",
        "test": "out-of-scope-isolation",
        "result": "fail",
        "violations": 1,
        "details": [
          {
            "source": "i-oos123",
            "protocol": "TCP",
            "port": 3306
          }
        ]
      }
    ]
  }
}
```

**3. Data Flow Analysis** (`data_flow_analysis`)

Generated for: PCI DSS 1.2.4, 1.3.1, 1.3.2

```json
{
  "type": "data_flow_analysis",
  "data": {
    "vpc_id": "vpc-abc123",
    "time_window": {
      "start": "2025-06-15T00:00:00Z",
      "end": "2025-06-15T23:59:59Z",
      "hours": 24
    },
    "summary": {
      "total_flows": 15420,
      "total_packets": 9823471,
      "total_bytes": 8472939201
    },
    "flows": [
      {
        "source": {
          "resource_id": "i-source123",
          "ip": "10.0.1.50"
        },
        "destination": {
          "resource_id": "i-dest456",
          "ip": "10.0.2.100",
          "port": 443
        },
        "protocol": "TCP",
        "packets": 523,
        "bytes": 492301,
        "observed_at": "2025-06-15T14:22:33Z"
      }
    ]
  }
}
```

**4. Tag Audit Trail** (`tag_audit_trail`)

Generated for: PCI DSS 1.2.7, 12.5.2.1

```json
{
  "type": "tag_audit_trail",
  "data": {
    "resource_id": "i-1234567890abcdef0",
    "tag_history": [
      {
        "key": "pci:scope",
        "old_value": "pending-review",
        "new_value": "cde",
        "changed_by": "[security-team@company.com](mailto:security-team@company.com)",
        "changed_at": "2025-06-15T10:30:00Z",
        "justification": "Confirmed processes cardholder data"
      }
    ]
  }
}
```

### Signature Verification

**For Assessors Using OpenSSL**

```bash
# Extract public key from evidence
echo "$PUBLIC_KEY" > public-key.pem

# Extract signature and hash
SIGNATURE=$(jq -r '.evidence.signature.signature' evidence.json)
HASH=$(jq -r '.evidence.signature.hash' evidence.json)

# Decode signature
echo "$SIGNATURE" | base64 -d > signature.bin

# Verify
openssl dgst -sha256 -verify public-key.pem -signature signature.bin evidence-payload.json
```

**For Assessors Using Python**

```python
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import json

# Load evidence
with open('evidence.json') as f:
    evidence = json.load(f)

# Load public key
with open('public-key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key([f.read](http://f.read)())

# Verify signature
signature = base64.b64decode(evidence['evidence']['signature']['signature'])
hash_hex = evidence['evidence']['signature']['hash']

try:
    public_key.verify(
        signature,
        hash_hex.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    print("✓ Signature verified - Evidence is authentic")
except:
    print("✗ Signature verification failed - Evidence may be tampered")
```

---

## Compliance Workflow

### Quarterly Scope Review Process

**Week 1: Discovery**

```bash
# Run full discovery
pci-scope-guard scan --all --force

# Generate preliminary report
pci-scope-guard scope summary > quarterly-scope-review.txt
```

**Week 2: Classification Review**

```bash
# Review pending classifications
pci-scope-guard scope list --scope pending-review

# Classify manually if needed
pci-scope-guard scope classify <resource-id> \
  --scope cde \
  --reason "Payment processing microservice"

# Run automated classification
pci-scope-guard classify --auto
```

**Week 3: Validation**

```bash
# Validate segmentation
pci-scope-guard scope validate-segmentation

# Check for violations
pci-scope-guard monitoring violations

# Remediate any issues found
```

**Week 4: Evidence Generation**

```bash
# Generate compliance evidence
pci-scope-guard evidence generate --requirement 1.2.4
pci-scope-guard evidence generate --requirement 1.3.1

# Export for records
pci-scope-guard evidence export \
  --start-date $(date -d '3 months ago' +%Y-%m-%d) \
  --end-date $(date +%Y-%m-%d) \
  --format pdf \
  --output scope-review-$(date +%Y-Q$(($(date +%-m)/3+1))).pdf
```

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton

**Target Audience**: QSAs, ISAs, Security Teams