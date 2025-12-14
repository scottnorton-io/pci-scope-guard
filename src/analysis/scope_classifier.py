"""
PCI Scope Guard - Scope Classifier
ML-enhanced classification engine for determining PCI scope
"""

from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from uuid import uuid4
import logging
from dataclasses import dataclass
import json

from sqlalchemy.orm import Session

from ..core.models import (
    Resource, ScopeDecision, DataFlow, Tag,
    PCIScope, DataClassification, CloudProvider
)
from ..core.database import get_db_context
from ..core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ClassificationResult:
    """Result of scope classification"""
    resource_id: str
    scope: PCIScope
    data_classification: Optional[DataClassification]
    justification: str
    confidence_score: Dict[str, float]
    decision_method: str
    dependency_resource_ids: List[str]


class ScopeClassifier:
    """
    Intelligent scope classification engine
    
    Uses rule-based logic with ML-enhancement to classify
    resources into PCI scope categories
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.confidence_threshold = settings.CLASSIFICATION_CONFIDENCE_THRESHOLD
        
        # CDE indicators (keywords suggesting cardholder data)
        self.cde_keywords = {
            'payment', 'card', 'cardholder', 'chd', 'pan',
            'tokenization', 'tokenize', 'checkout', 'billing',
            'transaction', 'merchant', 'processor', 'gateway',
            'stripe', 'braintree', 'adyen', 'cybersource'
        }
        
        # Port mappings for common payment services
        self.payment_ports = {
            443,   # HTTPS (common for payment APIs)
            8443,  # Alt HTTPS
            3000,  # Common for payment microservices
            8080,  # Alt HTTP for payment systems
        }
        
        logger.info(\"Initialized Scope Classifier\")
    
    def classify_resource(
        self, 
        resource: Resource,
        user_id: str = \"automated-classifier\"
    ) -> ClassificationResult:
        \"\"\"
        Classify a single resource's PCI scope
        
        Args:
            resource: Resource to classify
            user_id: User or system performing classification
            
        Returns:
            ClassificationResult with scope and justification
        \"\"\"
        logger.info(f\"Classifying resource {resource.resource_id}\")
        
        # Step 1: Check for explicit tag override
        explicit_scope = self._check_explicit_tags(resource)
        if explicit_scope:
            return ClassificationResult(
                resource_id=resource.resource_id,
                scope=explicit_scope['scope'],
                data_classification=explicit_scope.get('data_classification'),
                justification=explicit_scope['justification'],
                confidence_score={'explicit_tag': 1.0},
                decision_method='manual_tag',
                dependency_resource_ids=[]
            )
        
        # Step 2: Check for direct CDE indicators
        direct_cde_result = self._check_direct_cde_indicators(resource)
        if direct_cde_result:
            return direct_cde_result
        
        # Step 3: Analyze network connections
        network_result = self._analyze_network_connections(resource)
        if network_result:
            return network_result
        
        # Step 4: Check resource configuration
        config_result = self._analyze_configuration(resource)
        if config_result:
            return config_result
        
        # Step 5: Default to out-of-scope with low confidence
        return ClassificationResult(
            resource_id=resource.resource_id,
            scope=PCIScope.OUT_OF_SCOPE,
            data_classification=None,
            justification=\"No CDE indicators found; no network connections to CDE resources\",
            confidence_score={'default': 0.7},
            decision_method='automated',
            dependency_resource_ids=[]
        )
    
    def _check_explicit_tags(self, resource: Resource) -> Optional[Dict]:
        \"\"\"Check for explicit pci:scope tags\"\"\"
        
        for tag in resource.tags:
            if tag.key == 'pci:scope':
                scope_map = {
                    'cde': PCIScope.CDE,
                    'connected-cde': PCIScope.CONNECTED_CDE,
                    'out-of-scope': PCIScope.OUT_OF_SCOPE,
                }
                
                scope = scope_map.get(tag.value.lower())
                if not scope:
                    continue
                
                # Check for data classification tag
                data_class = None
                for t in resource.tags:
                    if t.key == 'pci:data-class':
                        data_class_map = {
                            'stores-cardholder': DataClassification.STORES_CARDHOLDER,
                            'processes-cardholder': DataClassification.PROCESSES_CARDHOLDER,
                            'transmits-cardholder': DataClassification.TRANSMITS_CARDHOLDER,
                        }
                        data_class = data_class_map.get(t.value.lower())
                
                return {
                    'scope': scope,
                    'data_classification': data_class,
                    'justification': f\"Explicit pci:scope tag set to '{tag.value}' by {tag.applied_by}\"
                }
        
        return None
    
    def _check_direct_cde_indicators(self, resource: Resource) -> Optional[ClassificationResult]:
        \"\"\"Check resource name, tags, and metadata for CDE keywords\"\"\"
        
        indicators_found = []
        confidence = 0.0
        
        # Check resource name
        if resource.resource_name:
            for keyword in self.cde_keywords:
                if keyword in resource.resource_name.lower():
                    indicators_found.append(f\"name contains '{keyword}'\")
                    confidence += 0.3
        
        # Check tags
        for tag in resource.tags:
            tag_text = f\"{tag.key}:{tag.value}\".lower()
            for keyword in self.cde_keywords:
                if keyword in tag_text:
                    indicators_found.append(f\"tag '{tag.key}' contains '{keyword}'\")
                    confidence += 0.2
        
        # Check metadata
        metadata_str = json.dumps(resource.metadata).lower()
        for keyword in self.cde_keywords:
            if keyword in metadata_str:
                indicators_found.append(f\"metadata contains '{keyword}'\")
                confidence += 0.1
        
        # Determine classification based on indicators
        if confidence >= 0.5:
            # High confidence CDE
            data_classification = self._infer_data_classification(resource)
            
            return ClassificationResult(
                resource_id=resource.resource_id,
                scope=PCIScope.CDE,
                data_classification=data_classification,
                justification=f\"CDE indicators found: {', '.join(indicators_found)}\",
                confidence_score={
                    'keyword_match': min(confidence, 1.0),
                    'indicators': indicators_found
                },
                decision_method='automated',
                dependency_resource_ids=[]
            )
        elif confidence >= 0.3:
            # Medium confidence - needs review
            return ClassificationResult(
                resource_id=resource.resource_id,
                scope=PCIScope.PENDING_REVIEW,
                data_classification=None,
                justification=f\"Possible CDE indicators found: {', '.join(indicators_found)} (needs review)\",
                confidence_score={'keyword_match': confidence},
                decision_method='automated',
                dependency_resource_ids=[]
            )
        
        return None
    
    def _analyze_network_connections(self, resource: Resource) -> Optional[ClassificationResult]:
        \"\"\"Analyze network connections to determine scope\"\"\"
        
        # Get all data flows involving this resource
        outbound_flows = self.db.query(DataFlow).filter(
            DataFlow.source_resource_id == resource.id
        ).all()
        
        inbound_flows = self.db.query(DataFlow).filter(
            DataFlow.dest_resource_id == resource.id
        ).all()
        
        # Check if connected to known CDE resources
        connected_cde_resources = []
        
        for flow in outbound_flows + inbound_flows:
            # Get the other resource in the flow
            other_resource_id = (
                flow.dest_resource_id if flow.source_resource_id == resource.id 
                else flow.source_resource_id
            )
            
            # Check if other resource is CDE
            other_resource = self.db.query(Resource).filter(
                Resource.id == other_resource_id
            ).first()
            
            if not other_resource:
                continue
            
            # Check current scope decision
            current_decision = self.db.query(ScopeDecision).filter(
                ScopeDecision.resource_id == other_resource_id,
                ScopeDecision.is_current == True
            ).first()
            
            if current_decision and current_decision.scope == PCIScope.CDE:
                connected_cde_resources.append({
                    'resource_id': other_resource.resource_id,
                    'protocol': flow.protocol,
                    'port': flow.dst_port,
                    'packets': flow.packet_count
                })
        
        if connected_cde_resources:
            # This resource connects to CDE, so it's connected-to-CDE
            return ClassificationResult(
                resource_id=resource.resource_id,
                scope=PCIScope.CONNECTED_CDE,
                data_classification=None,
                justification=f\"Connected to {len(connected_cde_resources)} CDE resource(s): \" +
                             \", \".join([r['resource_id'] for r in connected_cde_resources[:3]]),
                confidence_score={
                    'network_connectivity': 0.9,
                    'connected_resources': len(connected_cde_resources)
                },
                decision_method='automated',
                dependency_resource_ids=[r['resource_id'] for r in connected_cde_resources]
            )
        
        return None
    
    def _analyze_configuration(self, resource: Resource) -> Optional[ClassificationResult]:
        \"\"\"Analyze resource configuration for CDE indicators\"\"\"
        
        indicators = []
        confidence = 0.0
        
        # Check database encryption (important for CDE)
        if resource.resource_type.value in ['rds_instance', 'sql_database', 'cloud_sql']:
            encrypted = resource.metadata.get('encrypted', False)
            if encrypted:
                indicators.append('database encryption enabled')
                confidence += 0.1
            
            publicly_accessible = resource.metadata.get('publicly_accessible', False)
            if not publicly_accessible:
                indicators.append('not publicly accessible')
                confidence += 0.1
        
        # Check S3 bucket encryption
        if resource.resource_type.value == 's3_bucket':
            encrypted = resource.metadata.get('encrypted')
            if encrypted:
                indicators.append('bucket encryption enabled')
                confidence += 0.1
        
        # Check for specific security group configurations
        if resource.security_groups:
            # Analyze security group rules
            restrictive_sg = self._analyze_security_groups(resource.security_groups)
            if restrictive_sg:
                indicators.append('restrictive security groups')
                confidence += 0.1
        
        # Configuration alone is insufficient for CDE classification
        # But can boost confidence for pending review
        if confidence >= 0.2:
            return ClassificationResult(
                resource_id=resource.resource_id,
                scope=PCIScope.PENDING_REVIEW,
                data_classification=None,
                justification=f\"Security configuration suggests possible CDE: {', '.join(indicators)}\",
                confidence_score={'configuration': confidence},
                decision_method='automated',
                dependency_resource_ids=[]
            )
        
        return None
    
    def _infer_data_classification(self, resource: Resource) -> Optional[DataClassification]:
        \"\"\"Infer how resource handles cardholder data\"\"\"
        
        # Check resource type
        if resource.resource_type.value in ['rds_instance', 'sql_database', 'cloud_sql', 's3_bucket']:
            return DataClassification.STORES_CARDHOLDER
        
        # Check for processing indicators
        if resource.resource_type.value in ['lambda_function', 'cloud_function', 'app_service']:
            return DataClassification.PROCESSES_CARDHOLDER
        
        # Check for transmission indicators
        if resource.resource_type.value in ['elastic_load_balancer', 'api_gateway']:
            return DataClassification.TRANSMITS_CARDHOLDER
        
        # Default to processes
        return DataClassification.PROCESSES_CARDHOLDER
    
    def _analyze_security_groups(self, security_groups: List[Dict]) -> bool:
        \"\"\"Analyze if security groups are restrictive (good for CDE)\"\"\"
        
        # Simplified check - in production, would analyze actual rules
        # Returns True if security groups look restrictive
        
        return len(security_groups) > 0
    
    def classify_all_pending(self) -> List[ScopeDecision]:
        \"\"\"
        Classify all resources with pending-review scope
        
        Returns:
            List of new scope decisions
        \"\"\"
        logger.info(\"Starting batch classification of pending resources\")
        
        # Get all resources needing classification
        pending_resources = self.db.query(Resource).join(
            ScopeDecision, 
            (ScopeDecision.resource_id == Resource.id) & (ScopeDecision.is_current == True)
        ).filter(
            ScopeDecision.scope == PCIScope.PENDING_REVIEW
        ).all()
        
        logger.info(f\"Found {len(pending_resources)} resources pending classification\")
        
        new_decisions = []
        
        for resource in pending_resources:
            try:
                result = self.classify_resource(resource)
                decision = self._create_scope_decision(resource, result)
                new_decisions.append(decision)
            except Exception as e:
                logger.error(f\"Failed to classify resource {resource.resource_id}: {e}\")
        
        self.db.commit()
        logger.info(f\"Completed classification: {len(new_decisions)} decisions made\")
        
        return new_decisions
    
    def reclassify_resource(
        self, 
        resource: Resource,
        user_id: str,
        reason: Optional[str] = None
    ) -> ScopeDecision:
        \"\"\"
        Force reclassification of a resource
        
        Args:
            resource: Resource to reclassify
            user_id: User requesting reclassification
            reason: Optional reason for reclassification
            
        Returns:
            New scope decision
        \"\"\"
        logger.info(f\"Reclassifying resource {resource.resource_id} (requested by {user_id})\")
        
        # Supersede current decision
        current_decision = self.db.query(ScopeDecision).filter(
            ScopeDecision.resource_id == resource.id,
            ScopeDecision.is_current == True
        ).first()
        
        if current_decision:
            current_decision.is_current = False
        
        # Create new classification
        result = self.classify_resource(resource, user_id=user_id)
        
        if reason:
            result.justification = f\"{result.justification} (Reclassification reason: {reason})\"
        
        decision = self._create_scope_decision(resource, result)
        decision.decided_by = user_id
        
        if current_decision:
            decision.superseded_by_id = current_decision.id
        
        self.db.commit()
        
        return decision
    
    def _create_scope_decision(
        self, 
        resource: Resource, 
        result: ClassificationResult
    ) -> ScopeDecision:
        \"\"\"Create and persist a scope decision from classification result\"\"\"
        
        # Supersede any current decision
        current_decision = self.db.query(ScopeDecision).filter(
            ScopeDecision.resource_id == resource.id,
            ScopeDecision.is_current == True
        ).first()
        
        if current_decision:
            current_decision.is_current = False
        
        # Create new decision
        decision = ScopeDecision(
            resource_id=resource.id,
            scope=result.scope,
            data_classification=result.data_classification,
            justification=result.justification,
            confidence_score=result.confidence_score,
            decided_by=result.decision_method,
            decision_method=result.decision_method,
            dependency_resource_ids=result.dependency_resource_ids,
            is_current=True
        )
        
        self.db.add(decision)
        
        # Apply scope tag to resource
        self._apply_scope_tag(resource, result.scope)
        
        return decision
    
    def _apply_scope_tag(self, resource: Resource, scope: PCIScope):
        \"\"\"Apply pci:scope tag to resource\"\"\"
        
        # Check if tag already exists
        existing_tag = None
        for tag in resource.tags:
            if tag.key == 'pci:scope':
                existing_tag = tag
                break
        
        if existing_tag:
            # Update existing tag
            existing_tag.previous_value = existing_tag.value
            existing_tag.value = scope.value
            existing_tag.version += 1
            existing_tag.applied_at = datetime.utcnow()
            existing_tag.applied_by = 'automated-classifier'
        else:
            # Create new tag
            tag = Tag(
                resource_id=resource.id,
                key='pci:scope',
                value=scope.value,
                source='automated',
                applied_by='automated-classifier'
            )
            self.db.add(tag)
    
    def get_scope_summary(self) -> Dict[str, int]:
        \"\"\"Get summary statistics of current scope classifications\"\"\"
        
        summary = {
            'total': 0,
            PCIScope.CDE.value: 0,
            PCIScope.CONNECTED_CDE.value: 0,
            PCIScope.OUT_OF_SCOPE.value: 0,
            PCIScope.PENDING_REVIEW.value: 0,
        }
        
        # Query current scope decisions
        decisions = self.db.query(
            ScopeDecision.scope,
            func.count(ScopeDecision.id).label('count')
        ).filter(
            ScopeDecision.is_current == True
        ).group_by(ScopeDecision.scope).all()
        
        for scope, count in decisions:
            summary[scope.value] = count
            summary['total'] += count
        
        return summary
    
    def validate_scope_dependencies(self) -> List[Dict]:
        \"\"\"
        Validate scope dependencies for consistency
        
        Returns:
            List of validation issues found
        \"\"\"
        issues = []
        
        # Rule 1: Resources connected to CDE must be connected-to or CDE
        cde_resources = self.db.query(Resource.id).join(
            ScopeDecision,
            (ScopeDecision.resource_id == Resource.id) & (ScopeDecision.is_current == True)
        ).filter(
            ScopeDecision.scope == PCIScope.CDE
        ).all()
        
        cde_ids = [r[0] for r in cde_resources]
        
        # Find flows involving CDE resources
        flows = self.db.query(DataFlow).filter(
            (DataFlow.source_resource_id.in_(cde_ids)) |
            (DataFlow.dest_resource_id.in_(cde_ids))
        ).all()
        
        for flow in flows:
            # Get the non-CDE end of the connection
            other_id = (
                flow.dest_resource_id if flow.source_resource_id in cde_ids
                else flow.source_resource_id
            )
            
            # Check its scope
            other_decision = self.db.query(ScopeDecision).filter(
                ScopeDecision.resource_id == other_id,
                ScopeDecision.is_current == True
            ).first()
            
            if other_decision and other_decision.scope == PCIScope.OUT_OF_SCOPE:
                issues.append({
                    'type': 'out-of-scope-connected-to-cde',
                    'resource_id': other_id,
                    'description': f\"Resource marked out-of-scope but has network connection to CDE\"
                })
        
        logger.info(f\"Scope validation found {len(issues)} issues\")
        return issues


# Convenience functions

def classify_resource_by_id(resource_id: str, user_id: str = \"automated\") -> ScopeDecision:
    \"\"\"
    Classify a resource by its resource_id
    
    Args:
        resource_id: Cloud provider resource ID
        user_id: User performing classification
        
    Returns:
        New scope decision
    \"\"\"
    with get_db_context() as db:
        classifier = ScopeClassifier(db)
        
        resource = db.query(Resource).filter(
            Resource.resource_id == resource_id
        ).first()
        
        if not resource:
            raise ValueError(f\"Resource not found: {resource_id}\")
        
        result = classifier.classify_resource(resource, user_id=user_id)
        decision = classifier._create_scope_decision(resource, result)
        
        db.commit()
        return decision


def bulk_classify(batch_size: int = 100) -> Dict[str, int]:
    \"\"\"
    Classify resources in batches
    
    Args:
        batch_size: Number of resources to classify per batch
        
    Returns:
        Statistics on classification
    \"\"\"
    stats = {
        'processed': 0,
        'cde': 0,
        'connected_cde': 0,
        'out_of_scope': 0,
        'pending_review': 0,
    }
    
    with get_db_context() as db:
        classifier = ScopeClassifier(db)
        
        # Get pending resources in batches
        offset = 0
        while True:
            pending = db.query(Resource).join(
                ScopeDecision,
                (ScopeDecision.resource_id == Resource.id) & (ScopeDecision.is_current == True)
            ).filter(
                ScopeDecision.scope == PCIScope.PENDING_REVIEW
            ).limit(batch_size).offset(offset).all()
            
            if not pending:
                break
            
            for resource in pending:
                result = classifier.classify_resource(resource)
                classifier._create_scope_decision(resource, result)
                
                stats['processed'] += 1
                
                if result.scope == PCIScope.CDE:
                    stats['cde'] += 1
                elif result.scope == PCIScope.CONNECTED_CDE:
                    stats['connected_cde'] += 1
                elif result.scope == PCIScope.OUT_OF_SCOPE:
                    stats['out_of_scope'] += 1
                else:
                    stats['pending_review'] += 1
            
            db.commit()
            offset += batch_size
    
    return stats
