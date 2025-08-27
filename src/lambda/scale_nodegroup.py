"""
EKS Doctor - Scale NodeGroup Lambda Function
Production-grade nodegroup scaling with safety checks and comprehensive validation.
"""

import os
import json
import boto3
import logging
import time
import traceback
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
HUB_SESSION = boto3.Session()
EXTERNAL_ID = os.environ.get("EXTERNAL_ID")
SPOKE_ROLE_CHANGE = os.environ.get("SPOKE_ROLE_CHANGE", "eks-ops-change")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME")

# Constants
SCALING_TIMEOUT_MINUTES = 15
MIN_SCALE_SIZE = 0
MAX_SCALE_SIZE = 100
SCALE_SAFETY_MARGIN = 2


@dataclass
class NodeGroupInfo:
    """Data class for nodegroup information"""
    nodegroup_name: str
    cluster_name: str
    status: str
    current_size: int
    min_size: int
    max_size: int
    desired_size: int
    instance_types: List[str]
    ami_type: str
    capacity_type: str
    scaling_config: Dict[str, int]
    auto_scaling_group_name: Optional[str] = None
    launch_template: Optional[Dict] = None
    
    @property
    def is_managed(self) -> bool:
        """Check if this is a managed nodegroup"""
        return self.auto_scaling_group_name is None


@dataclass
class ScalingResult:
    """Data class for scaling operation results"""
    nodegroup_name: str
    cluster_name: str
    region: str
    account_id: str
    timestamp: str
    success: bool
    scaling_method: str  # 'eks' or 'asg'
    previous_config: Dict[str, int]
    new_config: Dict[str, int]
    duration_seconds: float
    validation_passed: bool
    warnings: List[str]
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class EKSNodeGroupScaler:
    """Main class for EKS nodegroup scaling operations"""
    
    def __init__(self, hub_session: boto3.Session):
        self.hub_session = hub_session
        self.logger = logger
        
    def assume_spoke_role(self, spoke_account_id: str, role_name: str) -> boto3.Session:
        """Assume role in spoke account"""
        try:
            sts_client = self.hub_session.client("sts")
            
            self.logger.info(f"Assuming role {role_name} in account {spoke_account_id}")
            
            response = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{spoke_account_id}:role/{role_name}",
                RoleSessionName=f"eks-scale-nodegroup-{int(time.time())}",
                ExternalId=EXTERNAL_ID,
                DurationSeconds=3600,
            )
            
            credentials = response["Credentials"]
            
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=self.hub_session.region_name
            )
            
            # Validate the assumed role
            identity = session.client('sts').get_caller_identity()
            self.logger.info(f"Successfully assumed role: {identity['Arn']}")
            
            return session
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            self.logger.error(f"Failed to assume role {role_name} in {spoke_account_id}: {error_code} - {error_message}")
            raise
            
        except Exception as e:
            self.logger.error(f"Unexpected error assuming role: {str(e)}")
            raise
    
    def get_nodegroup_info(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        nodegroup_name: str
    ) -> NodeGroupInfo:
        """Get comprehensive nodegroup information"""
        try:
            eks_client = session.client("eks", region_name=region)
            
            self.logger.info(f"Getting nodegroup info for {nodegroup_name} in cluster {cluster_name}")
            
            # Try to get EKS managed nodegroup first
            try:
                response = eks_client.describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup_name
                )
                
                nodegroup = response["nodegroup"]
                
                return NodeGroupInfo(
                    nodegroup_name=nodegroup_name,
                    cluster_name=cluster_name,
                    status=nodegroup.get("status", "UNKNOWN"),
                    current_size=nodegroup.get("scalingConfig", {}).get("desiredSize", 0),
                    min_size=nodegroup.get("scalingConfig", {}).get("minSize", 0),
                    max_size=nodegroup.get("scalingConfig", {}).get("maxSize", 0),
                    desired_size=nodegroup.get("scalingConfig", {}).get("desiredSize", 0),
                    instance_types=nodegroup.get("instanceTypes", ["unknown"]),
                    ami_type=nodegroup.get("amiType", "unknown"),
                    capacity_type=nodegroup.get("capacityType", "unknown"),
                    scaling_config=nodegroup.get("scalingConfig", {}),
                    launch_template=nodegroup.get("launchTemplate")
                )
                
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                    # Not a managed nodegroup, try to find ASG
                    return self._get_unmanaged_nodegroup_info(
                        session, region, cluster_name, nodegroup_name
                    )
                else:
                    raise
                    
        except Exception as e:
            self.logger.error(f"Failed to get nodegroup info: {str(e)}")
            raise
    
    def _get_unmanaged_nodegroup_info(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        nodegroup_name: str
    ) -> NodeGroupInfo:
        """Get information for unmanaged nodegroup (ASG)"""
        try:
            asg_client = session.client("autoscaling", region_name=region)
            ec2_client = session.client("ec2", region_name=region)
            
            self.logger.info(f"Looking for unmanaged nodegroup ASG: {nodegroup_name}")
            
            # Try to find ASG by name
            try:
                response = asg_client.describe_auto_scaling_groups(
                    AutoScalingGroupNames=[nodegroup_name]
                )
                
                if not response["AutoScalingGroups"]:
                    raise ValueError(f"Auto Scaling Group {nodegroup_name} not found")
                
                asg = response["AutoScalingGroups"][0]
                
                # Get instance types from launch template or configuration
                instance_types = ["unknown"]
                ami_type = "unknown"
                
                if asg.get("LaunchTemplate"):
                    lt_id = asg["LaunchTemplate"]["LaunchTemplateId"]
                    lt_version = asg["LaunchTemplate"]["Version"]
                    
                    try:
                        lt_response = ec2_client.describe_launch_template_versions(
                            LaunchTemplateId=lt_id,
                            Versions=[lt_version]
                        )
                        
                        if lt_response["LaunchTemplateVersions"]:
                            lt_data = lt_response["LaunchTemplateVersions"][0]["LaunchTemplateData"]
                            if "InstanceType" in lt_data:
                                instance_types = [lt_data["InstanceType"]]
                            
                    except Exception as e:
                        self.logger.warning(f"Failed to get launch template details: {str(e)}")
                
                return NodeGroupInfo(
                    nodegroup_name=nodegroup_name,
                    cluster_name=cluster_name,
                    status="ACTIVE",  # ASGs don't have EKS-specific status
                    current_size=len(asg["Instances"]),
                    min_size=asg["MinSize"],
                    max_size=asg["MaxSize"],
                    desired_size=asg["DesiredCapacity"],
                    instance_types=instance_types,
                    ami_type=ami_type,
                    capacity_type="ON_DEMAND",  # Default assumption
                    scaling_config={
                        "minSize": asg["MinSize"],
                        "maxSize": asg["MaxSize"],
                        "desiredSize": asg["DesiredCapacity"]
                    },
                    auto_scaling_group_name=nodegroup_name
                )
                
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'ValidationError':
                    raise ValueError(f"Nodegroup {nodegroup_name} not found (neither managed EKS nodegroup nor ASG)")
                else:
                    raise
                    
        except Exception as e:
            self.logger.error(f"Failed to get unmanaged nodegroup info: {str(e)}")
            raise
    
    def validate_scaling_request(
        self, 
        nodegroup_info: NodeGroupInfo, 
        new_desired_size: int,
        new_min_size: Optional[int] = None,
        new_max_size: Optional[int] = None
    ) -> tuple[bool, List[str], Dict[str, int]]:
        """Validate scaling request and calculate new configuration"""
        
        warnings = []
        
        # Use current values as defaults
        final_min_size = new_min_size if new_min_size is not None else nodegroup_info.min_size
        final_max_size = new_max_size if new_max_size is not None else nodegroup_info.max_size
        
        # Basic validation
        if new_desired_size < MIN_SCALE_SIZE or new_desired_size > MAX_SCALE_SIZE:
            return False, [f"Desired size {new_desired_size} outside allowed range ({MIN_SCALE_SIZE}-{MAX_SCALE_SIZE})"], {}
        
        if final_min_size < 0 or final_max_size < 0:
            return False, ["Min and max sizes cannot be negative"], {}
        
        if new_desired_size < final_min_size:
            return False, [f"Desired size {new_desired_size} is less than min size {final_min_size}"], {}
        
        if new_desired_size > final_max_size:
            return False, [f"Desired size {new_desired_size} exceeds max size {final_max_size}"], {}
        
        if final_min_size > final_max_size:
            return False, [f"Min size {final_min_size} cannot exceed max size {final_max_size}"], {}
        
        # Safety checks
        current_size = nodegroup_info.current_size
        size_change = abs(new_desired_size - current_size)
        
        if size_change > current_size and current_size > 0:
            warnings.append(f"Large scaling change: {current_size} -> {new_desired_size} (>{100}% change)")
        
        if new_desired_size == 0:
            warnings.append("Scaling to zero nodes - cluster may become unavailable")
        
        if new_desired_size > 20 and current_size <= 5:
            warnings.append("Large scale-up detected - consider gradual scaling")
        
        # Check nodegroup status
        if nodegroup_info.status not in ["ACTIVE", "UPDATING"]:
            return False, [f"Nodegroup is in {nodegroup_info.status} status - cannot scale"], {}
        
        # Adjust max size if needed (with safety margin)
        if new_desired_size > final_max_size - SCALE_SAFETY_MARGIN:
            suggested_max = new_desired_size + SCALE_SAFETY_MARGIN
            if new_max_size is None:  # Only auto-adjust if max wasn't explicitly set
                final_max_size = suggested_max
                warnings.append(f"Auto-adjusting max size to {final_max_size} for safety margin")
        
        new_config = {
            "minSize": final_min_size,
            "maxSize": final_max_size,
            "desiredSize": new_desired_size
        }
        
        return True, warnings, new_config
    
    def scale_managed_nodegroup(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        nodegroup_name: str,
        scaling_config: Dict[str, int]
    ) -> bool:
        """Scale EKS managed nodegroup"""
        try:
            eks_client = session.client("eks", region_name=region)
            
            self.logger.info(f"Scaling managed nodegroup {nodegroup_name} with config: {scaling_config}")
            
            response = eks_client.update_nodegroup_config(
                clusterName=cluster_name,
                nodegroupName=nodegroup_name,
                scalingConfig=scaling_config
            )
            
            update_id = response.get("update", {}).get("id")
            self.logger.info(f"EKS nodegroup scaling update initiated: {update_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to scale managed nodegroup: {str(e)}")
            raise
    
    def scale_unmanaged_nodegroup(
        self, 
        session: boto3.Session, 
        region: str, 
        asg_name: str,
        scaling_config: Dict[str, int]
    ) -> bool:
        """Scale unmanaged nodegroup (ASG)"""
        try:
            asg_client = session.client("autoscaling", region_name=region)
            
            self.logger.info(f"Scaling ASG {asg_name} with config: {scaling_config}")
            
            asg_client.update_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                MinSize=scaling_config["minSize"],
                MaxSize=scaling_config["maxSize"],
                DesiredCapacity=scaling_config["desiredSize"]
            )
            
            self.logger.info(f"ASG scaling update completed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to scale ASG: {str(e)}")
            raise
    
    def perform_nodegroup_scaling(
        self, 
        spoke_account_id: str, 
        region: str, 
        cluster_name: str, 
        nodegroup_name: str,
        desired_size: int,
        min_size: Optional[int] = None,
        max_size: Optional[int] = None
    ) -> ScalingResult:
        """Perform comprehensive nodegroup scaling operation"""
        start_time = time.time()
        warnings = []
        
        try:
            self.logger.info(f"Starting nodegroup scaling for {nodegroup_name} in cluster {cluster_name}")
            self.logger.info(f"Target: desired={desired_size}, min={min_size}, max={max_size}")
            
            # Assume spoke role with change permissions
            spoke_session = self.assume_spoke_role(spoke_account_id, SPOKE_ROLE_CHANGE)
            
            # Get current nodegroup information
            nodegroup_info = self.get_nodegroup_info(
                spoke_session, region, cluster_name, nodegroup_name
            )
            
            self.logger.info(f"Current nodegroup config: {nodegroup_info.scaling_config}")
            
            # Store previous config
            previous_config = nodegroup_info.scaling_config.copy()
            
            # Validate scaling request
            validation_passed, validation_warnings, new_config = self.validate_scaling_request(
                nodegroup_info, desired_size, min_size, max_size
            )
            
            warnings.extend(validation_warnings)
            
            if not validation_passed:
                raise ValueError(f"Scaling validation failed: {'; '.join(validation_warnings)}")
            
            self.logger.info(f"New nodegroup config: {new_config}")
            
            # Perform scaling based on nodegroup type
            scaling_method = "eks" if nodegroup_info.is_managed else "asg"
            
            if nodegroup_info.is_managed:
                success = self.scale_managed_nodegroup(
                    spoke_session, region, cluster_name, nodegroup_name, new_config
                )
            else:
                success = self.scale_unmanaged_nodegroup(
                    spoke_session, region, nodegroup_info.auto_scaling_group_name, new_config
                )
            
            execution_time = time.time() - start_time
            
            # Create result
            scaling_result = ScalingResult(
                nodegroup_name=nodegroup_name,
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=success,
                scaling_method=scaling_method,
                previous_config=previous_config,
                new_config=new_config,
                duration_seconds=execution_time,
                validation_passed=validation_passed,
                warnings=warnings
            )
            
            self.logger.info(f"Nodegroup scaling completed in {execution_time:.2f}s - Success: {success}")
            
            return scaling_result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Nodegroup scaling failed after {execution_time:.2f}s: {str(e)}")
            
            # Return failed result
            return ScalingResult(
                nodegroup_name=nodegroup_name,
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=False,
                scaling_method="unknown",
                previous_config={},
                new_config={},
                duration_seconds=execution_time,
                validation_passed=False,
                warnings=warnings,
                error_message=str(e)
            )
    
    def publish_metrics(self, scaling_result: ScalingResult):
        """Publish scaling metrics to CloudWatch"""
        try:
            cloudwatch = self.hub_session.client('cloudwatch')
            
            timestamp = datetime.now(timezone.utc)
            namespace = 'EKSDoctor/NodeGroupScaling'
            
            dimensions = [
                {'Name': 'ClusterName', 'Value': scaling_result.cluster_name},
                {'Name': 'Region', 'Value': scaling_result.region},
                {'Name': 'AccountId', 'Value': scaling_result.account_id},
                {'Name': 'NodeGroupName', 'Value': scaling_result.nodegroup_name}
            ]
            
            metrics = [
                {
                    'MetricName': 'ScalingSuccess',
                    'Dimensions': dimensions,
                    'Value': 1 if scaling_result.success else 0,
                    'Unit': 'None',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'ScalingDuration',
                    'Dimensions': dimensions,
                    'Value': scaling_result.duration_seconds,
                    'Unit': 'Seconds',
                    'Timestamp': timestamp
                }
            ]
            
            # Add size change metrics if successful
            if scaling_result.success and scaling_result.previous_config and scaling_result.new_config:
                previous_size = scaling_result.previous_config.get('desiredSize', 0)
                new_size = scaling_result.new_config.get('desiredSize', 0)
                
                metrics.extend([
                    {
                        'MetricName': 'PreviousDesiredSize',
                        'Dimensions': dimensions,
                        'Value': previous_size,
                        'Unit': 'Count',
                        'Timestamp': timestamp
                    },
                    {
                        'MetricName': 'NewDesiredSize',
                        'Dimensions': dimensions,
                        'Value': new_size,
                        'Unit': 'Count',
                        'Timestamp': timestamp
                    },
                    {
                        'MetricName': 'SizeChange',
                        'Dimensions': dimensions,
                        'Value': new_size - previous_size,
                        'Unit': 'Count',
                        'Timestamp': timestamp
                    }
                ])
            
            cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=metrics
            )
            
            self.logger.info(f"Published scaling metrics to CloudWatch")
            
        except Exception as e:
            self.logger.error(f"Failed to publish scaling metrics: {str(e)}")
    
    def send_notifications(self, scaling_result: ScalingResult):
        """Send notifications about scaling operation"""
        try:
            message = {
                "operation": "nodegroup_scaling",
                "cluster": scaling_result.cluster_name,
                "region": scaling_result.region,
                "account": scaling_result.account_id,
                "nodegroup": scaling_result.nodegroup_name,
                "success": scaling_result.success,
                "scaling_method": scaling_result.scaling_method,
                "changes": {
                    "previous": scaling_result.previous_config,
                    "new": scaling_result.new_config
                },
                "duration_seconds": scaling_result.duration_seconds,
                "warnings": scaling_result.warnings,
                "timestamp": scaling_result.timestamp
            }
            
            if scaling_result.error_message:
                message["error"] = scaling_result.error_message
            
            subject = f"EKS NodeGroup Scaling {'Completed' if scaling_result.success else 'Failed'}: {scaling_result.nodegroup_name}"
            
            if SNS_TOPIC_ARN:
                sns = self.hub_session.client('sns')
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=subject,
                    Message=json.dumps(message, indent=2)
                )
                
                self.logger.info(f"Sent scaling notification")
            
        except Exception as e:
            self.logger.error(f"Failed to send notifications: {str(e)}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for EKS nodegroup scaling operations
    
    Expected event format:
    {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "my-eks-cluster",
        "nodegroup": "my-nodegroup",
        "desired": 5,
        "min": 1,       # Optional
        "max": 10       # Optional
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting nodegroup scaling operation - Request ID: {request_id}")
    
    try:
        # Validate input
        required_fields = ["spoke_account_id", "region", "cluster", "nodegroup", "desired"]
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        spoke_account_id = event["spoke_account_id"]
        region = event["region"]
        cluster_name = event["cluster"]
        nodegroup_name = event["nodegroup"]
        desired_size = int(event["desired"])
        min_size = int(event["min"]) if "min" in event else None
        max_size = int(event["max"]) if "max" in event else None
        
        # Validate inputs
        if not spoke_account_id.isdigit() or len(spoke_account_id) != 12:
            raise ValueError("spoke_account_id must be a 12-digit AWS account ID")
        
        if desired_size < 0:
            raise ValueError("desired size cannot be negative")
        
        logger.info(f"Processing nodegroup scaling for {nodegroup_name} in {cluster_name}")
        logger.info(f"Target configuration: desired={desired_size}, min={min_size}, max={max_size}")
        
        # Create nodegroup scaler and perform scaling
        nodegroup_scaler = EKSNodeGroupScaler(HUB_SESSION)
        scaling_result = nodegroup_scaler.perform_nodegroup_scaling(
            spoke_account_id, region, cluster_name, nodegroup_name,
            desired_size, min_size, max_size
        )
        
        # Publish observability data
        nodegroup_scaler.publish_metrics(scaling_result)
        nodegroup_scaler.send_notifications(scaling_result)
        
        # Prepare response
        response = {
            "ok": scaling_result.success,
            "request_id": request_id,
            "scaling_result": asdict(scaling_result),
            "execution_time_ms": int(scaling_result.duration_seconds * 1000)
        }
        
        if not scaling_result.success:
            response["error"] = "ScalingFailed"
            response["message"] = scaling_result.error_message or "Nodegroup scaling operation failed"
        
        logger.info(f"Nodegroup scaling operation completed - Success: {scaling_result.success}")
        
        return response
        
    except ValueError as e:
        logger.error(f"Invalid input: {str(e)}")
        return {
            "ok": False,
            "error": "ValidationError",
            "message": str(e),
            "request_id": request_id
        }
        
    except Exception as e:
        logger.error(f"Nodegroup scaling operation failed: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "ok": False,
            "error": "InternalError",
            "message": f"Nodegroup scaling failed: {str(e)}",
            "request_id": request_id
        }


# For local testing
if __name__ == "__main__":
    test_event = {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "test-cluster",
        "nodegroup": "test-nodegroup",
        "desired": 3,
        "min": 1,
        "max": 5
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
        def get_remaining_time_in_millis(self):
            return 300000  # 5 minutes
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2, default=str))
