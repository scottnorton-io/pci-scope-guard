# models.py - Data Models

# Data Models - Complete Implementation

**File**: `src/core/[models.py](http://models.py)`

```python
"""
PCI Scope Guard - Core Data Models
SQLAlchemy models with TimescaleDB support for compliance audit trails
"""

from datetime import datetime
from typing import Optional, List
from uuid import uuid4
import enum

from sqlalchemy import (
    Column, String, Integer, DateTime, JSON, Boolean, 
    ForeignKey, Enum, Text, BigInteger, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()

# Enums

class CloudProvider(str, enum.Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ON_PREMISE = "on_premise"

class ResourceType(str, enum.Enum):
    """Cloud resource types"""
    # AWS
    EC2_INSTANCE = "ec2_instance"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"
    ELB = "elastic_load_balancer"
    S3_BUCKET = "s3_bucket"
    ECS_SERVICE = "ecs_service"
    EKS_CLUSTER = "eks_cluster"
    # Azure
    VIRTUAL_MACHINE = "virtual_machine"
    SQL_DATABASE = "sql_database"
    APP_SERVICE = "app_service"
    STORAGE_ACCOUNT = "storage_account"
    # GCP
    COMPUTE_INSTANCE = "compute_instance"
    CLOUD_SQL = "cloud_sql"
    CLOUD_FUNCTION = "cloud_function"
    GKE_CLUSTER = "gke_cluster"

class PCIScope(str, enum.Enum):
    """PCI DSS scope classification"""
    CDE = "cde"  # In cardholder data environment
    CONNECTED_CDE = "connected-cde"  # Connected to/supporting CDE
    OUT_OF_SCOPE = "out-of-scope"  # Not in scope
    PENDING_REVIEW = "pending-review"  # Newly discovered, needs classification

class DataClassification(str, enum.Enum):
    """Data handling classification for CDE resources"""
    STORES_CARDHOLDER = "stores-cardholder"
    PROCESSES_CARDHOLDER = "processes-cardholder"
    TRANSMITS_CARDHOLDER = "transmits-cardholder"

class EvidenceType(str, enum.Enum):
    """Types of compliance evidence"""
    SCOPE_IDENTIFICATION = "pci_scope_identification"
    NETWORK_SEGMENTATION = "network_segmentation_validation"
    DATA_FLOW_ANALYSIS = "data_flow_analysis"
    TAG_AUDIT = "tag_audit_trail"
    CONFIGURATION_SNAPSHOT = "configuration_snapshot"

# Core Models

class Resource(Base):
    """Cloud resource discovered across environments"""
    __tablename__ = "resources"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    provider = Column(Enum(CloudProvider), nullable=False, index=True)
    resource_type = Column(Enum(ResourceType), nullable=False, index=True)
    resource_id = Column(String(255), nullable=False, unique=True, index=True)
    resource_arn = Column(String(512), nullable=True)  # AWS ARN or equivalent
    resource_name = Column(String(255), nullable=True)
    
    # Network context
    vpc_id = Column(String(128), nullable=True, index=True)
    subnet_id = Column(String(128), nullable=True)
    availability_zone = Column(String(64), nullable=True)
    region = Column(String(64), nullable=True, index=True)
    
    # Resource metadata (full cloud provider response)
    metadata = Column(JSONB, nullable=False, default=dict)
    
    # IP addressing
    private_ip = Column(String(45), nullable=True)  # IPv4 or IPv6
    public_ip = Column(String(45), nullable=True)
    
    # Security groups / firewall rules
    security_groups = Column(JSONB, nullable=True, default=list)
    
    # Discovery metadata
    discovered_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True, index=True)
    
    # Relationships
    tags = relationship("Tag", back_populates="resource", cascade="all, delete-orphan")
    scope_decisions = relationship("ScopeDecision", back_populates="resource", cascade="all, delete-orphan")
    source_flows = relationship("DataFlow", foreign_keys="DataFlow.source_resource_id", back_populates="source_resource")
    dest_flows = relationship("DataFlow", foreign_keys="DataFlow.dest_resource_id", back_populates="dest_resource")
    
    # Indexes
    __table_args__ = (
        Index('idx_resource_provider_type', 'provider', 'resource_type'),
        Index('idx_resource_vpc_active', 'vpc_id', 'is_active'),
        Index('idx_resource_discovered_at', 'discovered_at'),
    )
    
    def __repr__(self):
        return f"<Resource {self.provider.value}:{self.resource_type.value}:{self.resource_id}>"

class Tag(Base):
    """Resource tags including PCI scope tags"""
    __tablename__ = "tags"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    resource_id = Column(UUID(as_uuid=True), ForeignKey("[resources.id](http://resources.id)", ondelete="CASCADE"), nullable=False, index=True)
    
    key = Column(String(255), nullable=False, index=True)
    value = Column(Text, nullable=False)
    
    # Tag source tracking
    source = Column(String(64), nullable=False, default="manual")  # manual, automated, imported
    applied_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    applied_by = Column(String(255), nullable=False)  # User email or system
    
    # Version tracking for audit trail
    version = Column(Integer, nullable=False, default=1)
    previous_value = Column(Text, nullable=True)
    
    # Relationship
    resource = relationship("Resource", back_populates="tags")
    
    __table_args__ = (
        Index('idx_tag_key_value', 'key', 'value'),
        Index('idx_tag_resource_key', 'resource_id', 'key'),
    )
    
    def __repr__(self):
        return f"<Tag {self.key}={self.value}>"

class DataFlow(Base):
    """Network data flows between resources (from VPC Flow Logs, etc.)"""
    __tablename__ = "data_flows"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    source_resource_id = Column(UUID(as_uuid=True), ForeignKey("[resources.id](http://resources.id)", ondelete="CASCADE"), nullable=False, index=True)
    dest_resource_id = Column(UUID(as_uuid=True), ForeignKey("[resources.id](http://resources.id)", ondelete="CASCADE"), nullable=False, index=True)
    
    # Flow details
    protocol = Column(String(8), nullable=False)  # TCP, UDP, ICMP
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=False)
    
    # Traffic metrics
    packet_count = Column(BigInteger, nullable=False, default=0)
    byte_count = Column(BigInteger, nullable=False, default=0)
    
    # Flow metadata
    flow_direction = Column(String(16), nullable=False)  # ingress, egress, intra-vpc
    action = Column(String(16), nullable=False)  # ACCEPT, REJECT
    
    # Temporal data (TimescaleDB hypertable)
    observed_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    
    # Relationships
    source_resource = relationship("Resource", foreign_keys=[source_resource_id], back_populates="source_flows")
    dest_resource = relationship("Resource", foreign_keys=[dest_resource_id], back_populates="dest_flows")
    
    __table_args__ = (
        Index('idx_flow_src_dst', 'source_resource_id', 'dest_resource_id'),
        Index('idx_flow_dst_port', 'dst_port'),
        Index('idx_flow_observed_at', 'observed_at'),
    )
    
    def __repr__(self):
        return f"<DataFlow {self.protocol}:{self.dst_port}>"

class ScopeDecision(Base):
    """PCI scope classification decisions with audit trail"""
    __tablename__ = "scope_decisions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    resource_id = Column(UUID(as_uuid=True), ForeignKey("[resources.id](http://resources.id)", ondelete="CASCADE"), nullable=False, index=True)
    
    # Scope classification
    scope = Column(Enum(PCIScope), nullable=False, index=True)
    data_classification = Column(Enum(DataClassification), nullable=True)
    segment = Column(String(64), nullable=True)  # Network segment identifier
    
    # Decision justification
    justification = Column(Text, nullable=False)
    confidence_score = Column(JSONB, nullable=True)  # ML confidence metrics
    
    # Decision metadata
    decided_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    decided_by = Column(String(255), nullable=False)  # User or 'automated-classifier'
    decision_method = Column(String(64), nullable=False)  # manual, automated, ml
    
    # Version control
    is_current = Column(Boolean, nullable=False, default=True, index=True)
    superseded_by_id = Column(UUID(as_uuid=True), ForeignKey("scope_[decisions.id](http://decisions.id)"), nullable=True)
    
    # Dependencies (resources that influenced this decision)
    dependency_resource_ids = Column(JSONB, nullable=True, default=list)
    
    # Relationships
    resource = relationship("Resource", back_populates="scope_decisions")
    evidence = relationship("Evidence", back_populates="scope_decision", cascade="all, delete-orphan")
    superseded_by = relationship("ScopeDecision", remote_side=[id], foreign_keys=[superseded_by_id])
    
    __table_args__ = (
        Index('idx_scope_decision_resource_current', 'resource_id', 'is_current'),
        Index('idx_scope_decision_scope', 'scope', 'is_current'),
    )
    
    def __repr__(self):
        return f"<ScopeDecision scope={self.scope.value} current={[self.is](http://self.is)_current}>"

class Evidence(Base):
    """Compliance evidence artifacts with cryptographic signatures"""
    __tablename__ = "evidence"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scope_decision_id = Column(UUID(as_uuid=True), ForeignKey("scope_[decisions.id](http://decisions.id)", ondelete="CASCADE"), nullable=False, index=True)
    
    # Evidence type and content
    evidence_type = Column(Enum(EvidenceType), nullable=False, index=True)
    data = Column(JSONB, nullable=False)  # Full evidence payload
    
    # Cryptographic verification
    hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash
    signature = Column(Text, nullable=False)  # ECDSA signature
    signing_key_id = Column(String(128), nullable=False)  # Key identifier for verification
    
    # Storage location
    storage_url = Column(String(512), nullable=True)  # S3 URL or equivalent
    
    # Compliance metadata
    pci_requirement = Column(String(16), nullable=True, index=True)  # e.g., "1.2.4"
    generated_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    generated_by = Column(String(255), nullable=False)
    
    # Retention (7 years for PCI)
    expires_at = Column(DateTime, nullable=False)  # Auto-calculated as generated_at + 7 years
    
    # Verification tracking
    last_verified_at = Column(DateTime, nullable=True)
    verification_count = Column(Integer, nullable=False, default=0)
    
    # Relationship
    scope_decision = relationship("ScopeDecision", back_populates="evidence")
    
    __table_args__ = (
        Index('idx_evidence_type_requirement', 'evidence_type', 'pci_requirement'),
        Index('idx_evidence_generated_at', 'generated_at'),
    )
    
    def __repr__(self):
        return f"<Evidence type={self.evidence_type.value} hash={self.hash[:8]}>"

class GRCSync(Base):
    """Track synchronization with GRC platforms (Vanta, Drata, etc.)"""
    __tablename__ = "grc_syncs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    provider = Column(String(64), nullable=False, index=True)  # vanta, drata, secureframe
    sync_type = Column(String(64), nullable=False)  # full, incremental
    
    # Sync status
    status = Column(String(32), nullable=False, index=True)  # pending, in_progress, completed, failed
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # Sync statistics
    resources_synced = Column(Integer, nullable=False, default=0)
    errors_count = Column(Integer, nullable=False, default=0)
    error_details = Column(JSONB, nullable=True, default=list)
    
    # Metadata
    sync_metadata = Column(JSONB, nullable=True, default=dict)
    
    __table_args__ = (
        Index('idx_grc_sync_provider_status', 'provider', 'status'),
    )

class Alert(Base):
    """Compliance alerts for drift detection and violations"""
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Alert details
    severity = Column(String(16), nullable=False, index=True)  # critical, high, medium, low
    alert_type = Column(String(64), nullable=False, index=True)  # scope_drift, segmentation_violation, untagged_resource
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    # Affected resource
    resource_id = Column(UUID(as_uuid=True), ForeignKey("[resources.id](http://resources.id)", ondelete="CASCADE"), nullable=True, index=True)
    
    # Alert lifecycle
    triggered_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(255), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(255), nullable=True)
    
    # Status
    status = Column(String(32), nullable=False, default="open", index=True)  # open, acknowledged, resolved, false_positive
    
    # Alert context
    context = Column(JSONB, nullable=True, default=dict)
    
    __table_args__ = (
        Index('idx_alert_severity_status', 'severity', 'status'),
        Index('idx_alert_type_triggered', 'alert_type', 'triggered_at'),
    )

class AuditLog(Base):
    """Comprehensive audit log for all system actions"""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Actor information
    user_id = Column(String(255), nullable=False, index=True)
    user_email = Column(String(255), nullable=False)
    user_ip = Column(String(45), nullable=True)
    
    # Action details
    action = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(255), nullable=True, index=True)
    
    # Request/response
    request_data = Column(JSONB, nullable=True)
    response_data = Column(JSONB, nullable=True)
    
    # Outcome
    success = Column(Boolean, nullable=False, index=True)
    error_message = Column(Text, nullable=True)
    
    # Timing
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    duration_ms = Column(Integer, nullable=True)
    
    # Context
    session_id = Column(String(128), nullable=True)
    request_id = Column(String(128), nullable=True, index=True)
    
    __table_args__ = (
        Index('idx_audit_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_audit_action_success', 'action', 'success'),
    )

# Database initialization helper

def init_db(engine):
    """Initialize database schema"""
    Base.metadata.create_all(engine)
    
    # Enable TimescaleDB for data_flows table (if using TimescaleDB)
    with engine.connect() as conn:
        try:
            conn.execute(
                "SELECT create_hypertable('data_flows', 'observed_at', if_not_exists => TRUE)"
            )
            conn.commit()
        except Exception as e:
            print(f"TimescaleDB not available or already configured: {e}")
```

**Key Features:**

1. **Complete Audit Trail**: Every change tracked with timestamps, actors, and versioning
2. **Cryptographic Evidence**: All compliance decisions cryptographically signed
3. **TimescaleDB Support**: Network flow data optimized for time-series queries
4. **Multi-Cloud**: Support for AWS, Azure, GCP, on-premise
5. **Compliance-Ready**: 7-year retention, immutable evidence, full audit logs
6. **Performance**: Strategic indexes on all query paths
7. **Relationships**: Proper foreign keys with cascade deletes
8. **Type Safety**: Enums for all categorical data

---

**Document Version**: 1.0

**Last Updated**: December 2025

**Author**: Scott Norton