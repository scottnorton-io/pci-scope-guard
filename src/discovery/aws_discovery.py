"""
PCI Scope Guard - AWS Discovery Agent
Comprehensive AWS resource discovery with VPC Flow Log analysis
"""

import asyncio
import boto3
from boto3.session import Session
from botocore.exceptions import ClientError, BotoCoreError
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
import json

from ..core.models import (
    Resource, Tag, DataFlow, CloudProvider, 
    ResourceType, PCIScope
)
from ..core.config import settings
from ..core.database import get_db_context

logger = logging.getLogger(__name__)


@dataclass
class AWSCredentials:
    """AWS credential configuration"""
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    region: str = "us-east-1"
    profile: Optional[str] = None


class AWSDiscoveryAgent:
    """
    AWS resource discovery with network flow analysis
    
    Discovers all PCI-relevant AWS resources and analyzes
    network connectivity through VPC Flow Logs
    """
    
    def __init__(self, credentials: AWSCredentials):
        self.credentials = credentials
        self.region = credentials.region
        
        # Initialize AWS session
        if credentials.profile:
            self.session = Session(profile_name=credentials.profile)
        else:
            self.session = Session(
                aws_access_key_id=credentials.access_key_id,
                aws_secret_access_key=credentials.secret_access_key,
                aws_session_token=credentials.session_token,
                region_name=credentials.region
            )
        
        # Initialize AWS clients
        self.ec2 = self.session.client('ec2', region_name=self.region)
        self.rds = self.session.client('rds', region_name=self.region)
        self.elbv2 = self.session.client('elbv2', region_name=self.region)
        self.lambda_client = self.session.client('lambda', region_name=self.region)
        self.s3 = self.session.client('s3', region_name=self.region)
        self.ecs = self.session.client('ecs', region_name=self.region)
        self.eks = self.session.client('eks', region_name=self.region)
        self.logs = self.session.client('logs', region_name=self.region)
        
        # Resource caches
        self._vpc_cache: Dict[str, dict] = {}
        self._subnet_cache: Dict[str, dict] = {}
        self._ip_to_resource: Dict[str, str] = {}
        
        logger.info(f"Initialized AWS Discovery Agent for region {self.region}")
    
    async def discover_all_resources(self) -> List[Resource]:
        """
        Discover all AWS resources in parallel
        
        Returns:
            List of discovered Resource objects
        """
        logger.info(f"Starting full discovery in region {self.region}")
        
        # Run all discovery tasks in parallel
        tasks = [
            self._discover_ec2_instances(),
            self._discover_rds_instances(),
            self._discover_load_balancers(),
            self._discover_lambda_functions(),
            self._discover_s3_buckets(),
            self._discover_ecs_services(),
            self._discover_eks_clusters(),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results and filter out errors
        resources = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Discovery task failed: {result}")
            else:
                resources.extend(result)
        
        logger.info(f"Discovered {len(resources)} total resources")
        return resources
    
    async def _discover_ec2_instances(self) -> List[Resource]:
        """Discover EC2 instances"""
        resources = []
        
        try:
            paginator = self.ec2.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        resource = self._convert_ec2_to_resource(instance)
                        resources.append(resource)
                        
                        # Cache IP to resource mapping
                        if instance.get('PrivateIpAddress'):
                            self._ip_to_resource[instance['PrivateIpAddress']] = resource.resource_id
                        if instance.get('PublicIpAddress'):
                            self._ip_to_resource[instance['PublicIpAddress']] = resource.resource_id
            
            logger.info(f"Discovered {len(resources)} EC2 instances")
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to discover EC2 instances: {e}")
        
        return resources
    
    def _convert_ec2_to_resource(self, instance: dict) -> Resource:
        """Convert EC2 instance to Resource model"""
        
        # Extract tags
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        
        # Determine initial scope from tags
        initial_scope = self._determine_scope_from_tags(tags)
        
        resource = Resource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.EC2_INSTANCE,
            resource_id=instance['InstanceId'],
            resource_arn=f"arn:aws:ec2:{self.region}:{instance.get('OwnerId', '')}:instance/{instance['InstanceId']}",
            resource_name=tags.get('Name', instance['InstanceId']),
            vpc_id=instance.get('VpcId'),
            subnet_id=instance.get('SubnetId'),
            availability_zone=instance.get('Placement', {}).get('AvailabilityZone'),
            region=self.region,
            private_ip=instance.get('PrivateIpAddress'),
            public_ip=instance.get('PublicIpAddress'),
            security_groups=[
                {
                    'id': sg['GroupId'],
                    'name': sg['GroupName']
                }
                for sg in instance.get('SecurityGroups', [])
            ],
            metadata={
                'instance_type': instance.get('InstanceType'),
                'state': instance.get('State', {}).get('Name'),
                'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                'platform': instance.get('Platform'),
                'ami_id': instance.get('ImageId'),
            }
        )
        
        return resource
    
    async def _discover_rds_instances(self) -> List[Resource]:
        """Discover RDS database instances"""
        resources = []
        
        try:
            paginator = self.rds.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db in page['DBInstances']:
                    resource = self._convert_rds_to_resource(db)
                    resources.append(resource)
                    
                    # Cache endpoint IP if available
                    if db.get('Endpoint', {}).get('Address'):
                        endpoint = db['Endpoint']['Address']
                        self._ip_to_resource[endpoint] = resource.resource_id
            
            logger.info(f"Discovered {len(resources)} RDS instances")
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to discover RDS instances: {e}")
        
        return resources
    
    def _convert_rds_to_resource(self, db: dict) -> Resource:
        """Convert RDS instance to Resource model"""
        
        # Get tags
        try:
            tag_response = self.rds.list_tags_for_resource(
                ResourceName=db['DBInstanceArn']
            )
            tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagList', [])}
        except Exception as e:
            logger.warning(f"Could not fetch RDS tags: {e}")
            tags = {}
        
        initial_scope = self._determine_scope_from_tags(tags)
        
        resource = Resource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.RDS_INSTANCE,
            resource_id=db['DBInstanceIdentifier'],
            resource_arn=db['DBInstanceArn'],
            resource_name=db['DBInstanceIdentifier'],
            vpc_id=db.get('DBSubnetGroup', {}).get('VpcId'),
            availability_zone=db.get('AvailabilityZone'),
            region=self.region,
            private_ip=db.get('Endpoint', {}).get('Address'),
            security_groups=[
                {
                    'id': sg['VpcSecurityGroupId'],
                    'status': sg['Status']
                }
                for sg in db.get('VpcSecurityGroups', [])
            ],
            metadata={
                'engine': db.get('Engine'),
                'engine_version': db.get('EngineVersion'),
                'instance_class': db.get('DBInstanceClass'),
                'storage_type': db.get('StorageType'),
                'allocated_storage': db.get('AllocatedStorage'),
                'encrypted': db.get('StorageEncrypted', False),
                'multi_az': db.get('MultiAZ', False),
                'publicly_accessible': db.get('PubliclyAccessible', False),
            }
        )
        
        return resource
    
    async def _discover_load_balancers(self) -> List[Resource]:
        """Discover Application and Network Load Balancers"""
        resources = []
        
        try:
            paginator = self.elbv2.get_paginator('describe_load_balancers')
            
            for page in paginator.paginate():
                for lb in page['LoadBalancers']:
                    resource = self._convert_elb_to_resource(lb)
                    resources.append(resource)
                    
                    # Cache IPs from load balancer
                    for az in lb.get('AvailabilityZones', []):
                        for addr in az.get('LoadBalancerAddresses', []):
                            if addr.get('IpAddress'):
                                self._ip_to_resource[addr['IpAddress']] = resource.resource_id
            
            logger.info(f"Discovered {len(resources)} load balancers")
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to discover load balancers: {e}")
        
        return resources
    
    def _convert_elb_to_resource(self, lb: dict) -> Resource:
        """Convert ELB to Resource model"""
        
        # Get tags
        try:
            tag_response = self.elbv2.describe_tags(
                ResourceArns=[lb['LoadBalancerArn']]
            )
            tags = {}
            for tag_desc in tag_response.get('TagDescriptions', []):
                for tag in tag_desc.get('Tags', []):
                    tags[tag['Key']] = tag['Value']
        except Exception as e:
            logger.warning(f"Could not fetch ELB tags: {e}")
            tags = {}
        
        initial_scope = self._determine_scope_from_tags(tags)
        
        resource = Resource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.ELB,
            resource_id=lb['LoadBalancerName'],
            resource_arn=lb['LoadBalancerArn'],
            resource_name=lb['LoadBalancerName'],
            vpc_id=lb.get('VpcId'),
            region=self.region,
            security_groups=[
                {'id': sg}
                for sg in lb.get('SecurityGroups', [])
            ],
            metadata={
                'type': lb.get('Type'),
                'scheme': lb.get('Scheme'),
                'dns_name': lb.get('DNSName'),
                'state': lb.get('State', {}).get('Code'),
                'availability_zones': [
                    {
                        'zone': az['ZoneName'],
                        'subnet': az['SubnetId']
                    }
                    for az in lb.get('AvailabilityZones', [])
                ],
            }
        )
        
        return resource
    
    async def _discover_lambda_functions(self) -> List[Resource]:
        """Discover Lambda functions"""
        resources = []
        
        try:
            paginator = self.lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for func in page['Functions']:
                    resource = self._convert_lambda_to_resource(func)
                    resources.append(resource)
            
            logger.info(f"Discovered {len(resources)} Lambda functions")
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to discover Lambda functions: {e}")
        
        return resources
    
    def _convert_lambda_to_resource(self, func: dict) -> Resource:
        """Convert Lambda function to Resource model"""
        
        # Get tags
        try:
            tag_response = self.lambda_client.list_tags(
                Resource=func['FunctionArn']
            )
            tags = tag_response.get('Tags', {})
        except Exception as e:
            logger.warning(f"Could not fetch Lambda tags: {e}")
            tags = {}
        
        initial_scope = self._determine_scope_from_tags(tags)
        
        # Extract VPC config if present
        vpc_config = func.get('VpcConfig', {})
        vpc_id = vpc_config.get('VpcId')
        subnet_ids = vpc_config.get('SubnetIds', [])
        
        resource = Resource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            resource_id=func['FunctionName'],
            resource_arn=func['FunctionArn'],
            resource_name=func['FunctionName'],
            vpc_id=vpc_id,
            subnet_id=subnet_ids[0] if subnet_ids else None,
            region=self.region,
            security_groups=[
                {'id': sg}
                for sg in vpc_config.get('SecurityGroupIds', [])
            ],
            metadata={
                'runtime': func.get('Runtime'),
                'handler': func.get('Handler'),
                'memory_size': func.get('MemorySize'),
                'timeout': func.get('Timeout'),
                'last_modified': func.get('LastModified'),
                'environment_variables': bool(func.get('Environment', {}).get('Variables')),
            }
        )
        
        return resource
    
    async def _discover_s3_buckets(self) -> List[Resource]:
        """Discover S3 buckets"""
        resources = []
        
        try:
            response = self.s3.list_buckets()
            
            for bucket in response.get('Buckets', []):
                resource = await self._convert_s3_to_resource(bucket)
                if resource:
                    resources.append(resource)
            
            logger.info(f"Discovered {len(resources)} S3 buckets")
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to discover S3 buckets: {e}")
        
        return resources
    
    async def _convert_s3_to_resource(self, bucket: dict) -> Optional[Resource]:
        """Convert S3 bucket to Resource model"""
        
        bucket_name = bucket['Name']
        
        try:
            # Get bucket location
            location_response = self.s3.get_bucket_location(Bucket=bucket_name)
            bucket_region = location_response.get('LocationConstraint', 'us-east-1')
            if bucket_region is None:
                bucket_region = 'us-east-1'
            
            # Only include buckets in our region
            if bucket_region != self.region:
                return None
            
            # Get tags
            try:
                tag_response = self.s3.get_bucket_tagging(Bucket=bucket_name)
                tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchTagSet':
                    tags = {}
                else:
                    raise
            
            # Get encryption
            try:
                encryption_response = self.s3.get_bucket_encryption(Bucket=bucket_name)
                encrypted = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    encrypted = False
                else:
                    encrypted = None
            
            initial_scope = self._determine_scope_from_tags(tags)
            
            resource = Resource(
                provider=CloudProvider.AWS,
                resource_type=ResourceType.S3_BUCKET,
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                resource_name=bucket_name,
                region=bucket_region,
                metadata={
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'encrypted': encrypted,
                }
            )
            
            return resource
            
        except Exception as e:
            logger.warning(f"Could not process S3 bucket {bucket_name}: {e}")
            return None
    
    async def _discover_ecs_services(self) -> List[Resource]:
        """Discover ECS services"""
        resources = []
        
        try:
            # List clusters first
            cluster_response = self.ecs.list_clusters()
            cluster_arns = cluster_response.get('clusterArns', [])
            
            for cluster_arn in cluster_arns:
                # List services in cluster
                service_paginator = self.ecs.get_paginator('list_services')
                
                for page in service_paginator.paginate(cluster=cluster_arn):
                    service_arns = page.get('serviceArns', [])
                    
                    if service_arns:
                        # Describe services in batches
                        services_response = self.ecs.describe_services(
                            cluster=cluster_arn,
                            services=service_arns
                        )
                        
                        for service in services_response.get('services', []):
                            resource = self._convert_ecs_to_resource(service, cluster_arn)
                            resources.append(resource)
            
            logger.info(f\"Discovered {len(resources)} ECS services\")
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f\"Failed to discover ECS services: {e}\")
        
        return resources
    
    def _convert_ecs_to_resource(self, service: dict, cluster_arn: str) -> Resource:
        \"\"\"Convert ECS service to Resource model\"\"\"
        
        # Get tags
        try:
            tag_response = self.ecs.list_tags_for_resource(
                resourceArn=service['serviceArn']
            )
            tags = {tag['key']: tag['value'] for tag in tag_response.get('tags', [])}
        except Exception as e:
            logger.warning(f\"Could not fetch ECS tags: {e}\")
            tags = {}
        
        initial_scope = self._determine_scope_from_tags(tags)
        
        resource = Resource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.ECS_SERVICE,
            resource_id=service['serviceName'],
            resource_arn=service['serviceArn'],
            resource_name=service['serviceName'],
            region=self.region,
            metadata={
                'cluster': cluster_arn,
                'task_definition': service.get('taskDefinition'),
                'desired_count': service.get('desiredCount'),
                'running_count': service.get('runningCount'),
                'launch_type': service.get('launchType'),
                'network_configuration': service.get('networkConfiguration'),
            }
        )
        
        return resource
    
    async def _discover_eks_clusters(self) -> List[Resource]:
        \"\"\"Discover EKS clusters\"\"\"
        resources = []
        
        try:
            cluster_response = self.eks.list_clusters()
            cluster_names = cluster_response.get('clusters', [])
            
            for cluster_name in cluster_names:
                cluster_detail = self.eks.describe_cluster(name=cluster_name)
                cluster = cluster_detail['cluster']
                
                resource = self._convert_eks_to_resource(cluster)
                resources.append(resource)
            
            logger.info(f\"Discovered {len(resources)} EKS clusters\")
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f\"Failed to discover EKS clusters: {e}\")
        
        return resources
    
    def _convert_eks_to_resource(self, cluster: dict) -> Resource:
        \"\"\"Convert EKS cluster to Resource model\"\"\"
        
        tags = cluster.get('tags', {})
        initial_scope = self._determine_scope_from_tags(tags)
        
        vpc_config = cluster.get('resourcesVpcConfig', {})
        
        resource = Resource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.EKS_CLUSTER,
            resource_id=cluster['name'],
            resource_arn=cluster['arn'],
            resource_name=cluster['name'],
            vpc_id=vpc_config.get('vpcId'),
            region=self.region,
            security_groups=[
                {'id': sg}
                for sg in vpc_config.get('securityGroupIds', [])
            ],
            metadata={
                'version': cluster.get('version'),
                'endpoint': cluster.get('endpoint'),
                'status': cluster.get('status'),
                'created_at': cluster.get('createdAt', '').isoformat() if cluster.get('createdAt') else None,
            }
        )
        
        return resource
    
    async def analyze_vpc_flows(
        self, 
        vpc_id: str, 
        time_window_hours: int = 1
    ) -> List[DataFlow]:
        \"\"\"
        Analyze VPC Flow Logs to identify network connections
        
        Args:
            vpc_id: VPC identifier
            time_window_hours: Hours of flow logs to analyze
            
        Returns:
            List of DataFlow objects representing network connections
        \"\"\"
        logger.info(f\"Analyzing VPC Flow Logs for {vpc_id}\")
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_window_hours)
        
        # CloudWatch Logs Insights query
        query = f\"\"\"
        fields srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, action
        | filter vpcid = '{vpc_id}'
        | stats sum(packets) as total_packets, sum(bytes) as total_bytes by srcaddr, dstaddr, dstport, protocol, action
        | sort total_packets desc
        | limit 10000
        \"\"\"
        
        try:
            # Start query
            query_response = self.logs.start_query(
                logGroupName=settings.AWS_FLOW_LOG_GROUP,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
            
            query_id = query_response['queryId']
            
            # Poll for results
            max_attempts = 30
            for attempt in range(max_attempts):
                await asyncio.sleep(2)  # Wait 2 seconds between polls
                
                result_response = self.logs.get_query_results(queryId=query_id)
                status = result_response['status']
                
                if status == 'Complete':
                    flows = self._parse_flow_log_results(
                        result_response['results'],
                        start_time,
                        end_time
                    )
                    logger.info(f\"Found {len(flows)} unique data flows in {vpc_id}\")
                    return flows
                elif status == 'Failed':
                    logger.error(f\"Flow log query failed: {result_response.get('statistics')}\")
                    return []
            
            logger.warning(f\"Flow log query timed out after {max_attempts * 2} seconds\")
            return []
            
        except (ClientError, BotoCoreError) as e:
            logger.error(f\"Failed to analyze VPC flows: {e}\")
            return []
    
    def _parse_flow_log_results(
        self, 
        results: List[List[Dict]], 
        start_time: datetime,
        end_time: datetime
    ) -> List[DataFlow]:
        \"\"\"Parse CloudWatch Logs Insights results into DataFlow objects\"\"\"
        
        flows = []
        
        for result in results:
            # Convert result list to dict
            data = {item['field']: item['value'] for item in result}
            
            src_ip = data.get('srcaddr')
            dst_ip = data.get('dstaddr')
            dst_port = data.get('dstport')
            protocol_num = data.get('protocol')
            action = data.get('action', 'ACCEPT')
            packets = int(data.get('total_packets', 0))
            bytes_count = int(data.get('total_bytes', 0))
            
            # Map IPs to resources
            src_resource_id = self._ip_to_resource.get(src_ip)
            dst_resource_id = self._ip_to_resource.get(dst_ip)
            
            # Skip flows where we can't map both endpoints
            if not src_resource_id or not dst_resource_id:
                continue
            
            # Map protocol number to name
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol = protocol_map.get(int(protocol_num), str(protocol_num))
            
            # Create DataFlow (will be persisted to DB later)
            flow = DataFlow(
                source_resource_id=src_resource_id,
                dest_resource_id=dst_resource_id,
                protocol=protocol,
                dst_port=int(dst_port) if dst_port else 0,
                packet_count=packets,
                byte_count=bytes_count,
                flow_direction='intra-vpc',
                action=action,
                observed_at=end_time,
                window_start=start_time,
                window_end=end_time
            )
            
            flows.append(flow)
        
        return flows
    
    def _determine_scope_from_tags(self, tags: Dict[str, str]) -> Optional[PCIScope]:
        \"\"\"Determine PCI scope from resource tags\"\"\"
        
        # Check for explicit pci:scope tag
        scope_tag = tags.get('pci:scope', '').lower()
        
        if scope_tag == 'cde':
            return PCIScope.CDE
        elif scope_tag in ['connected-cde', 'connected_cde']:
            return PCIScope.CONNECTED_CDE
        elif scope_tag in ['out-of-scope', 'out_of_scope']:
            return PCIScope.OUT_OF_SCOPE
        
        # Check for application tags that might indicate CDE
        app_name = tags.get('Application', '').lower()
        name = tags.get('Name', '').lower()
        environment = tags.get('Environment', '').lower()
        
        cde_keywords = ['payment', 'card', 'cardholder', 'chd', 'pan', 'tokenization']
        
        for keyword in cde_keywords:
            if keyword in app_name or keyword in name:
                return PCIScope.CDE
        
        # Default to pending review for untagged resources
        return PCIScope.PENDING_REVIEW
    
    async def persist_resources(self, resources: List[Resource]) -> int:
        \"\"\"
        Persist discovered resources to database
        
        Returns:
            Number of resources persisted
        \"\"\"
        count = 0
        
        with get_db_context() as db:
            for resource in resources:
                # Check if resource already exists
                existing = db.query(Resource).filter(
                    Resource.resource_id == resource.resource_id
                ).first()
                
                if existing:
                    # Update existing resource
                    existing.last_seen_at = datetime.utcnow()
                    existing.metadata = resource.metadata
                    existing.security_groups = resource.security_groups
                else:
                    # Insert new resource
                    db.add(resource)
                    count += 1
            
            db.commit()
        
        logger.info(f\"Persisted {count} new resources to database\")
        return count


# Convenience function for full discovery workflow
async def run_aws_discovery(region: str = None) -> Dict[str, any]:
    \"\"\"
    Run complete AWS discovery workflow
    
    Args:
        region: AWS region (defaults to settings.AWS_REGION)
        
    Returns:
        Discovery statistics
    \"\"\"
    if region is None:
        region = settings.AWS_REGION or 'us-east-1'
    
    credentials = AWSCredentials(
        access_key_id=settings.AWS_ACCESS_KEY_ID,
        secret_access_key=settings.AWS_SECRET_ACCESS_KEY.get_secret_value() if settings.AWS_SECRET_ACCESS_KEY else None,
        region=region
    )
    
    agent = AWSDiscoveryAgent(credentials)
    
    # Discover resources
    resources = await agent.discover_all_resources()
    
    # Persist to database
    new_count = await agent.persist_resources(resources)
    
    # Analyze VPC flows for each VPC
    vpcs = set(r.vpc_id for r in resources if r.vpc_id)
    all_flows = []
    
    for vpc_id in vpcs:
        flows = await agent.analyze_vpc_flows(vpc_id)
        all_flows.extend(flows)
    
    return {
        'region': region,
        'resources_discovered': len(resources),
        'new_resources': new_count,
        'vpcs_analyzed': len(vpcs),
        'data_flows': len(all_flows),
    }
