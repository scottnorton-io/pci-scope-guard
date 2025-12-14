\"\"\"
PCI Scope Guard - Evidence Generator
Generates cryptographically-signed compliance evidence
\"\"\"

from typing import Dict, List, Optional
from datetime import datetime, timedelta
from uuid import uuid4
import json
import logging

from sqlalchemy.orm import Session

from ..core.models import (
    Resource, ScopeDecision, DataFlow, Evidence,
    EvidenceType, PCIScope
)
from ..core.database import get_db_context
from ..core.config import settings
from .signer import EvidenceSigner

logger = logging.getLogger(__name__)


class EvidenceGenerator:
    \"\"\"
    Generate PCI DSS compliance evidence artifacts
    
    Creates structured, signed evidence that can be verified
    by assessors and automated compliance tools
    \"\"\"
    
    def __init__(self, db: Session):
        self.db = db
        self.signer = EvidenceSigner(
            private_key_path=settings.SIGNING_KEY_PATH
        )
        
        logger.info(\"Initialized Evidence Generator\")
    
    def generate_scope_identification_evidence(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Evidence:
        \"\"\"
        Generate evidence for PCI DSS Requirement 1.2.4 (scope identification)
        
        Args:
            start_date: Start of evidence period
            end_date: End of evidence period
            
        Returns:
            Signed Evidence object
        \"\"\"
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=90)
        if not end_date:
            end_date = datetime.utcnow()
        
        logger.info(f\"Generating scope identification evidence for {start_date} to {end_date}\")
        
        # Get all current scope decisions
        decisions = self.db.query(ScopeDecision).filter(
            ScopeDecision.is_current == True,
            ScopeDecision.decided_at >= start_date,
            ScopeDecision.decided_at <= end_date
        ).all()
        
        # Group by scope
        scope_summary = {
            PCIScope.CDE.value: [],
            PCIScope.CONNECTED_CDE.value: [],
            PCIScope.OUT_OF_SCOPE.value: [],
            PCIScope.PENDING_REVIEW.value: []
        }
        
        for decision in decisions:
            resource = decision.resource
            
            scope_summary[decision.scope.value].append({
                'resource_id': resource.resource_id,
                'resource_type': resource.resource_type.value,
                'provider': resource.provider.value,
                'name': resource.resource_name,
                'vpc_id': resource.vpc_id,
                'region': resource.region,
                'justification': decision.justification,
                'decided_at': decision.decided_at.isoformat(),
                'decided_by': decision.decided_by,
                'confidence_score': decision.confidence_score
            })
        
        # Build evidence payload
        evidence_data = {
            'cef_version': '1.0',
            'evidence': {
                'id': str(uuid4()),
                'type': EvidenceType.SCOPE_IDENTIFICATION.value,
                'timestamp': datetime.utcnow().isoformat(),
                'collector': {
                    'name': 'pci-scope-guard',
                    'version': settings.APP_VERSION
                },
                'compliance_context': {
                    'framework': 'PCI-DSS',
                    'version': '4.0',
                    'requirement_id': '1.2.4',
                    'testing_procedure': '1.2.4.a'
                },
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'scope_summary': {
                    'total_resources': len(decisions),
                    'cde_resources': len(scope_summary[PCIScope.CDE.value]),
                    'connected_resources': len(scope_summary[PCIScope.CONNECTED_CDE.value]),
                    'out_of_scope': len(scope_summary[PCIScope.OUT_OF_SCOPE.value]),
                    'pending_review': len(scope_summary[PCIScope.PENDING_REVIEW.value])
                },
                'resources': scope_summary
            }
        }
        
        # Sign evidence
        signature_data = self.signer.sign_evidence(evidence_data)
        
        # Create Evidence record
        evidence = Evidence(
            scope_decision_id=decisions[0].id if decisions else None,
            evidence_type=EvidenceType.SCOPE_IDENTIFICATION,
            data=evidence_data,
            hash=signature_data['hash'],
            signature=signature_data['signature'],
            signing_key_id=signature_data['key_id'],
            pci_requirement='1.2.4',
            generated_by='automated-evidence-generator',
            expires_at=datetime.utcnow() + timedelta(days=365*7)  # 7 years
        )
        
        self.db.add(evidence)
        self.db.commit()
        
        logger.info(f\"Generated scope identification evidence: {evidence.id}\")
        
        return evidence
    
    def generate_data_flow_evidence(
        self,
        vpc_id: str,
        time_window_hours: int = 24
    ) -> Evidence:
        \"\"\"
        Generate evidence of network data flows
        
        Args:
            vpc_id: VPC to analyze
            time_window_hours: Hours of flow data to include
            
        Returns:
            Signed Evidence object
        \"\"\"
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_window_hours)
        
        logger.info(f\"Generating data flow evidence for VPC {vpc_id}\")
        
        # Get all flows in time window
        flows = self.db.query(DataFlow).filter(
            DataFlow.observed_at >= start_time,
            DataFlow.observed_at <= end_time
        ).all()
        
        # Filter flows for resources in this VPC
        vpc_flows = []
        for flow in flows:
            src_resource = self.db.query(Resource).filter(
                Resource.id == flow.source_resource_id
            ).first()
            
            if src_resource and src_resource.vpc_id == vpc_id:
                dst_resource = self.db.query(Resource).filter(
                    Resource.id == flow.dest_resource_id
                ).first()
                
                vpc_flows.append({
                    'source': {
                        'resource_id': src_resource.resource_id,
                        'ip': src_resource.private_ip
                    },
                    'destination': {
                        'resource_id': dst_resource.resource_id if dst_resource else 'unknown',
                        'ip': dst_resource.private_ip if dst_resource else 'unknown',
                        'port': flow.dst_port
                    },
                    'protocol': flow.protocol,
                    'packets': flow.packet_count,
                    'bytes': flow.byte_count,
                    'observed_at': flow.observed_at.isoformat()
                })
        
        # Build evidence
        evidence_data = {
            'cef_version': '1.0',
            'evidence': {
                'id': str(uuid4()),
                'type': EvidenceType.DATA_FLOW_ANALYSIS.value,
                'timestamp': datetime.utcnow().isoformat(),
                'vpc_id': vpc_id,
                'time_window': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': time_window_hours
                },
                'summary': {
                    'total_flows': len(vpc_flows),
                    'total_packets': sum(f['packets'] for f in vpc_flows),
                    'total_bytes': sum(f['bytes'] for f in vpc_flows)
                },
                'flows': vpc_flows
            }
        }
        
        # Sign evidence
        signature_data = self.signer.sign_evidence(evidence_data)
        
        # Create Evidence record
        evidence = Evidence(
            evidence_type=EvidenceType.DATA_FLOW_ANALYSIS,
            data=evidence_data,
            hash=signature_data['hash'],
            signature=signature_data['signature'],
            signing_key_id=signature_data['key_id'],
            pci_requirement='1.2.4',
            generated_by='automated-evidence-generator',
            expires_at=datetime.utcnow() + timedelta(days=365*7)
        )
        
        self.db.add(evidence)
        self.db.commit()
        
        logger.info(f\"Generated data flow evidence: {evidence.id}\")
        
        return evidence
    
    def generate_segmentation_validation_evidence(self) -> Evidence:
        \"\"\"
        Generate evidence that CDE is properly segmented
        
        Returns:
            Signed Evidence object
        \"\"\"
        logger.info(\"Generating network segmentation validation evidence\")
        
        # Get all CDE resources
        cde_decisions = self.db.query(ScopeDecision).filter(
            ScopeDecision.scope == PCIScope.CDE,
            ScopeDecision.is_current == True
        ).all()
        
        segmentation_tests = []
        
        for decision in cde_decisions:
            resource = decision.resource
            
            # Check if out-of-scope resources can reach this CDE resource
            outbound_from_oos = self.db.query(DataFlow).join(
                Resource,
                Resource.id == DataFlow.source_resource_id
            ).join(
                ScopeDecision,
                ScopeDecision.resource_id == Resource.id
            ).filter(
                ScopeDecision.scope == PCIScope.OUT_OF_SCOPE,
                ScopeDecision.is_current == True,
                DataFlow.dest_resource_id == resource.id
            ).all()
            
            segmentation_tests.append({
                'resource_id': resource.resource_id,
                'resource_type': resource.resource_type.value,
                'test': 'out-of-scope-isolation',
                'result': 'pass' if len(outbound_from_oos) == 0 else 'fail',
                'violations': len(outbound_from_oos),
                'details': [
                    {
                        'source': flow.source_resource.resource_id,
                        'protocol': flow.protocol,
                        'port': flow.dst_port
                    }
                    for flow in outbound_from_oos
                ]
            })
        
        # Build evidence
        evidence_data = {
            'cef_version': '1.0',
            'evidence': {
                'id': str(uuid4()),
                'type': EvidenceType.NETWORK_SEGMENTATION.value,
                'timestamp': datetime.utcnow().isoformat(),
                'compliance_context': {
                    'framework': 'PCI-DSS',
                    'version': '4.0',
                    'requirement_id': '1.2.1',
                    'testing_procedure': '1.2.1.a'
                },
                'tests_performed': len(segmentation_tests),
                'tests_passed': sum(1 for t in segmentation_tests if t['result'] == 'pass'),
                'tests_failed': sum(1 for t in segmentation_tests if t['result'] == 'fail'),
                'test_results': segmentation_tests
            }
        }
        
        # Sign evidence
        signature_data = self.signer.sign_evidence(evidence_data)
        
        # Create Evidence record
        evidence = Evidence(
            evidence_type=EvidenceType.NETWORK_SEGMENTATION,
            data=evidence_data,
            hash=signature_data['hash'],
            signature=signature_data['signature'],
            signing_key_id=signature_data['key_id'],
            pci_requirement='1.2.1',
            generated_by='automated-evidence-generator',
            expires_at=datetime.utcnow() + timedelta(days=365*7)
        )
        
        self.db.add(evidence)
        self.db.commit()
        
        logger.info(f\"Generated segmentation validation evidence: {evidence.id}\")
        
        return evidence
    
    def verify_evidence(self, evidence: Evidence) -> bool:
        \"\"\"
        Verify evidence signature
        
        Args:
            evidence: Evidence object to verify
            
        Returns:
            True if signature is valid
        \"\"\"
        return self.signer.verify_signature(
            evidence.data,
            evidence.signature
        )
    
    def export_evidence_package(
        self,
        start_date: datetime,
        end_date: datetime,
        output_format: str = 'json'
    ) -> Dict:
        \"\"\"
        Export complete evidence package for assessor
        
        Args:
            start_date: Start of evidence period
            end_date: End of evidence period
            output_format: Format (json, pdf)
            
        Returns:
            Complete evidence package
        \"\"\"
        logger.info(f\"Exporting evidence package for {start_date} to {end_date}\")
        
        # Get all evidence in period
        evidence_records = self.db.query(Evidence).filter(
            Evidence.generated_at >= start_date,
            Evidence.generated_at <= end_date
        ).all()
        
        package = {
            'meta': {
                'generated_at': datetime.utcnow().isoformat(),
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'evidence_count': len(evidence_records),
                'framework': 'PCI-DSS',
                'version': '4.0'
            },
            'evidence': [
                {
                    'id': str(ev.id),
                    'type': ev.evidence_type.value,
                    'requirement': ev.pci_requirement,
                    'generated_at': ev.generated_at.isoformat(),
                    'hash': ev.hash,
                    'signature': ev.signature,
                    'data': ev.data
                }
                for ev in evidence_records
            ]
        }
        
        return package


# Convenience functions

def generate_all_evidence() -> List[Evidence]:
    \"\"\"Generate all current evidence artifacts\"\"\"
    
    with get_db_context() as db:
        generator = EvidenceGenerator(db)
        
        evidence_list = []
        
        # Scope identification
        evidence_list.append(generator.generate_scope_identification_evidence())
        
        # Segmentation validation
        evidence_list.append(generator.generate_segmentation_validation_evidence())
        
        # Data flows for each VPC
        vpcs = db.query(Resource.vpc_id).distinct().filter(
            Resource.vpc_id.isnot(None)
        ).all()
        
        for vpc_tuple in vpcs:
            vpc_id = vpc_tuple[0]
            evidence_list.append(generator.generate_data_flow_evidence(vpc_id))
        
        db.commit()
        
        return evidence_list
