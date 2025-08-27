"""
EKS Doctor - Restart Workload Lambda Function
Production-grade workload restart with safety checks and rollout monitoring.
"""

import os
import json
import base64
import time
import boto3
import urllib3
from botocore.signers import RequestSigner
from botocore.exceptions import ClientError, BotoCoreError
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Configure urllib3
http = urllib3.PoolManager(
    timeout=urllib3.Timeout(connect=5.0, read=30.0),
    retries=urllib3.Retry(total=3, backoff_factor=0.3),
    cert_reqs='CERT_REQUIRED',
    ca_certs=None
)

# Environment variables
HUB_SESSION = boto3.Session()
EXTERNAL_ID = os.environ.get("EXTERNAL_ID")
SPOKE_ROLE_CHANGE = os.environ.get("SPOKE_ROLE_CHANGE", "eks-ops-change")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME")

# Constants
K8S_API_TIMEOUT = 30
ROLLOUT_CHECK_TIMEOUT = 300  # 5 minutes
ROLLOUT_CHECK_INTERVAL = 10  # 10 seconds
SUPPORTED_WORKLOAD_TYPES = ["Deployment", "StatefulSet", "DaemonSet"]


@dataclass
class WorkloadStatus:
    """Data class for workload status information"""
    name: str
    namespace: str
    kind: str
    replicas: int
    ready_replicas: int
    updated_replicas: int
    available_replicas: int
    generation: int
    observed_generation: int
    conditions: List[Dict]
    
    @property
    def is_ready(self) -> bool:
        """Check if workload is ready"""
        return self.replicas == self.ready_replicas and self.generation == self.observed_generation


@dataclass
class RestartResult:
    """Data class for workload restart results"""
    workload_name: str
    namespace: str
    kind: str
    cluster_name: str
    region: str
    account_id: str
    timestamp: str
    success: bool
    restart_method: str
    pre_restart_status: Dict
    post_restart_status: Dict
    rollout_successful: bool
    duration_seconds: float
    warnings: List[str]
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class EKSWorkloadRestarter:
    """Main class for EKS workload restart operations"""
    
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
                RoleSessionName=f"eks-restart-workload-{int(time.time())}",
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
    
    def get_kubernetes_token(self, session: boto3.Session, region: str, cluster_name: str) -> str:
        """Generate Kubernetes API token using AWS STS"""
        try:
            credentials = session.get_credentials()
            
            signer = RequestSigner(
                service_name="sts",
                region_name=region,
                signing_name="sts",
                signature_version="v4",
                credentials=credentials,
                event_emitter=session._session.get_component("event_emitter"),
            )
            
            params = {
                "method": "GET",
                "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
                "body": {},
                "headers": {"x-k8s-aws-id": cluster_name},
                "context": {},
            }
            
            signed_url = signer.generate_presigned_url(
                params, 
                region_name=region,
                expires_in=60, 
                operation_name=""
            )
            
            token = "k8s-aws-v1." + base64.urlsafe_b64encode(
                signed_url.encode()
            ).decode().rstrip("=")
            
            return token
            
        except Exception as e:
            self.logger.error(f"Failed to generate Kubernetes token: {str(e)}")
            raise
    
    def make_k8s_request(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        method: str,
        path: str,
        body: Optional[Dict] = None
    ) -> Dict:
        """Make authenticated request to Kubernetes API"""
        try:
            # Get cluster endpoint
            eks_client = session.client("eks", region_name=region)
            cluster_info = eks_client.describe_cluster(name=cluster_name)["cluster"]
            endpoint = cluster_info["endpoint"]
            
            # Generate authentication token
            token = self.get_kubernetes_token(session, region, cluster_name)
            
            # Prepare headers
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json"
            }
            
            if body is not None:
                headers["Content-Type"] = "application/json"
            
            # Make the request
            url = f"{endpoint}{path}"
            self.logger.debug(f"Making {method} request to {url}")
            
            request_body = json.dumps(body) if body else None
            
            response = http.request(
                method=method,
                url=url,
                body=request_body,
                headers=headers,
                timeout=urllib3.Timeout(connect=3.0, read=K8S_API_TIMEOUT),
                preload_content=True,
            )
            
            if response.status >= 400:
                error_msg = f"Kubernetes API {method} {path} failed: HTTP {response.status}"
                if response.data:
                    error_details = response.data.decode('utf-8')[:500]
                    error_msg += f" - {error_details}"
                
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Parse response
            if response.data:
                return json.loads(response.data.decode('utf-8'))
            else:
                return {}
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Kubernetes API response: {str(e)}")
            raise RuntimeError(f"Invalid JSON response from Kubernetes API: {str(e)}")
            
        except urllib3.exceptions.RequestException as e:
            self.logger.error(f"Network error accessing Kubernetes API: {str(e)}")
            raise RuntimeError(f"Network error accessing Kubernetes API: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Unexpected error in Kubernetes API request: {str(e)}")
            raise
    
    def get_workload_status(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        namespace: str,
        workload_name: str,
        workload_kind: str
    ) -> WorkloadStatus:
        """Get current status of workload"""
        try:
            # Build API path based on workload kind
            api_paths = {
                "Deployment": f"/apis/apps/v1/namespaces/{namespace}/deployments/{workload_name}",
                "StatefulSet": f"/apis/apps/v1/namespaces/{namespace}/statefulsets/{workload_name}",
                "DaemonSet": f"/apis/apps/v1/namespaces/{namespace}/daemonsets/{workload_name}"
            }
            
            if workload_kind not in api_paths:
                raise ValueError(f"Unsupported workload kind: {workload_kind}")
            
            response = self.make_k8s_request(
                session, region, cluster_name, "GET", api_paths[workload_kind]
            )
            
            # Extract status information
            status = response.get("status", {})
            spec = response.get("spec", {})
            metadata = response.get("metadata", {})
            
            return WorkloadStatus(
                name=workload_name,
                namespace=namespace,
                kind=workload_kind,
                replicas=spec.get("replicas", 0),
                ready_replicas=status.get("readyReplicas", 0),
                updated_replicas=status.get("updatedReplicas", 0),
                available_replicas=status.get("availableReplicas", 0),
                generation=metadata.get("generation", 0),
                observed_generation=status.get("observedGeneration", 0),
                conditions=status.get("conditions", [])
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get workload status: {str(e)}")
            raise
    
    def restart_deployment(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        namespace: str,
        deployment_name: str
    ) -> bool:
        """Restart deployment by patching restart annotation"""
        try:
            self.logger.info(f"Restarting deployment {deployment_name} in namespace {namespace}")
            
            # Add restart annotation to trigger rollout
            patch_body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "eks-doctor/restartedAt": str(int(time.time())),
                                "kubectl.kubernetes.io/restartedAt": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    }
                }
            }
            
            path = f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment_name}"
            
            response = self.make_k8s_request(
                session, region, cluster_name, "PATCH", path, body=patch_body
            )
            
            self.logger.info(f"Successfully triggered deployment restart")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restart deployment: {str(e)}")
            raise
    
    def restart_statefulset(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        namespace: str,
        statefulset_name: str
    ) -> bool:
        """Restart StatefulSet by patching restart annotation"""
        try:
            self.logger.info(f"Restarting StatefulSet {statefulset_name} in namespace {namespace}")
            
            # Add restart annotation to trigger rollout
            patch_body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "eks-doctor/restartedAt": str(int(time.time())),
                                "kubectl.kubernetes.io/restartedAt": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    }
                }
            }
            
            path = f"/apis/apps/v1/namespaces/{namespace}/statefulsets/{statefulset_name}"
            
            response = self.make_k8s_request(
                session, region, cluster_name, "PATCH", path, body=patch_body
            )
            
            self.logger.info(f"Successfully triggered StatefulSet restart")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restart StatefulSet: {str(e)}")
            raise
    
    def restart_daemonset(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        namespace: str,
        daemonset_name: str
    ) -> bool:
        """Restart DaemonSet by patching restart annotation"""
        try:
            self.logger.info(f"Restarting DaemonSet {daemonset_name} in namespace {namespace}")
            
            # Add restart annotation to trigger rollout
            patch_body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "eks-doctor/restartedAt": str(int(time.time())),
                                "kubectl.kubernetes.io/restartedAt": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    }
                }
            }
            
            path = f"/apis/apps/v1/namespaces/{namespace}/daemonsets/{daemonset_name}"
            
            response = self.make_k8s_request(
                session, region, cluster_name, "PATCH", path, body=patch_body
            )
            
            self.logger.info(f"Successfully triggered DaemonSet restart")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restart DaemonSet: {str(e)}")
            raise
    
    def wait_for_rollout(
        self,
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        namespace: str,
        workload_name: str,
        workload_kind: str,
        timeout_seconds: int = ROLLOUT_CHECK_TIMEOUT
    ) -> tuple[bool, List[str]]:
        """Wait for workload rollout to complete"""
        
        start_time = time.time()
        warnings = []
        
        self.logger.info(f"Waiting for rollout of {workload_kind} {workload_name} to complete")
        
        while (time.time() - start_time) < timeout_seconds:
            try:
                status = self.get_workload_status(
                    session, region, cluster_name, namespace, workload_name, workload_kind
                )
                
                self.logger.debug(f"Rollout status: replicas={status.replicas}, ready={status.ready_replicas}, "
                                f"updated={status.updated_replicas}, generation={status.generation}, "
                                f"observed={status.observed_generation}")
                
                # Check if rollout is complete
                if status.is_ready:
                    elapsed = time.time() - start_time
                    self.logger.info(f"Rollout completed successfully in {elapsed:.2f}s")
                    return True, warnings
                
                # Check for rollout issues
                for condition in status.conditions:
                    condition_type = condition.get("type", "")
                    condition_status = condition.get("status", "")
                    condition_reason = condition.get("reason", "")
                    condition_message = condition.get("message", "")
                    
                    if condition_type == "Progressing" and condition_status == "False":
                        if "ProgressDeadlineExceeded" in condition_reason:
                            warnings.append(f"Rollout progress deadline exceeded: {condition_message}")
                            return False, warnings
                    
                    if condition_type == "Available" and condition_status == "False":
                        warnings.append(f"Workload not available: {condition_message}")
                
                # Wait before next check
                time.sleep(ROLLOUT_CHECK_INTERVAL)
                
            except Exception as e:
                warnings.append(f"Error checking rollout status: {str(e)}")
                time.sleep(ROLLOUT_CHECK_INTERVAL)
                continue
        
        # Timeout reached
        elapsed = time.time() - start_time
        warnings.append(f"Rollout did not complete within {timeout_seconds}s timeout")
        return False, warnings
    
    def perform_workload_restart(
        self, 
        spoke_account_id: str, 
        region: str, 
        cluster_name: str, 
        namespace: str,
        workload_name: str,
        workload_kind: str,
        wait_for_completion: bool = True
    ) -> RestartResult:
        """Perform comprehensive workload restart operation"""
        start_time = time.time()
        warnings = []
        
        try:
            self.logger.info(f"Starting workload restart for {workload_kind} {workload_name} in {namespace}")
            
            # Validate workload kind
            if workload_kind not in SUPPORTED_WORKLOAD_TYPES:
                raise ValueError(f"Unsupported workload kind: {workload_kind}. Supported: {SUPPORTED_WORKLOAD_TYPES}")
            
            # Assume spoke role with change permissions
            spoke_session = self.assume_spoke_role(spoke_account_id, SPOKE_ROLE_CHANGE)
            
            # Get pre-restart status
            self.logger.info("Getting pre-restart workload status")
            pre_restart_status = self.get_workload_status(
                spoke_session, region, cluster_name, namespace, workload_name, workload_kind
            )
            
            self.logger.info(f"Pre-restart status: {pre_restart_status.replicas} replicas, "
                           f"{pre_restart_status.ready_replicas} ready")
            
            # Perform restart based on workload kind
            restart_methods = {
                "Deployment": self.restart_deployment,
                "StatefulSet": self.restart_statefulset,
                "DaemonSet": self.restart_daemonset
            }
            
            restart_method = restart_methods[workload_kind]
            restart_successful = restart_method(
                spoke_session, region, cluster_name, namespace, workload_name
            )
            
            if not restart_successful:
                raise RuntimeError("Failed to trigger workload restart")
            
            # Wait for rollout completion if requested
            rollout_successful = True
            if wait_for_completion:
                rollout_successful, rollout_warnings = self.wait_for_rollout(
                    spoke_session, region, cluster_name, namespace, workload_name, workload_kind
                )
                warnings.extend(rollout_warnings)
            
            # Get post-restart status
            post_restart_status = self.get_workload_status(
                spoke_session, region, cluster_name, namespace, workload_name, workload_kind
            )
            
            self.logger.info(f"Post-restart status: {post_restart_status.replicas} replicas, "
                           f"{post_restart_status.ready_replicas} ready")
            
            execution_time = time.time() - start_time
            overall_success = restart_successful and (rollout_successful if wait_for_completion else True)
            
            # Create result
            restart_result = RestartResult(
                workload_name=workload_name,
                namespace=namespace,
                kind=workload_kind,
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=overall_success,
                restart_method="annotation",
                pre_restart_status=asdict(pre_restart_status),
                post_restart_status=asdict(post_restart_status),
                rollout_successful=rollout_successful,
                duration_seconds=execution_time,
                warnings=warnings
            )
            
            self.logger.info(f"Workload restart completed in {execution_time:.2f}s - Success: {overall_success}")
            
            return restart_result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Workload restart failed after {execution_time:.2f}s: {str(e)}")
            
            # Return failed result
            return RestartResult(
                workload_name=workload_name,
                namespace=namespace,
                kind=workload_kind,
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=False,
                restart_method="annotation",
                pre_restart_status={},
                post_restart_status={},
                rollout_successful=False,
                duration_seconds=execution_time,
                warnings=warnings,
                error_message=str(e)
            )
    
    def publish_metrics(self, restart_result: RestartResult):
        """Publish restart metrics to CloudWatch"""
        try:
            cloudwatch = self.hub_session.client('cloudwatch')
            
            timestamp = datetime.now(timezone.utc)
            namespace_cw = 'EKSDoctor/WorkloadRestart'
            
            dimensions = [
                {'Name': 'ClusterName', 'Value': restart_result.cluster_name},
                {'Name': 'Region', 'Value': restart_result.region},
                {'Name': 'AccountId', 'Value': restart_result.account_id},
                {'Name': 'Namespace', 'Value': restart_result.namespace},
                {'Name': 'WorkloadKind', 'Value': restart_result.kind}
            ]
            
            metrics = [
                {
                    'MetricName': 'RestartSuccess',
                    'Dimensions': dimensions,
                    'Value': 1 if restart_result.success else 0,
                    'Unit': 'None',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'RestartDuration',
                    'Dimensions': dimensions,
                    'Value': restart_result.duration_seconds,
                    'Unit': 'Seconds',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'RolloutSuccess',
                    'Dimensions': dimensions,
                    'Value': 1 if restart_result.rollout_successful else 0,
                    'Unit': 'None',
                    'Timestamp': timestamp
                }
            ]
            
            cloudwatch.put_metric_data(
                Namespace=namespace_cw,
                MetricData=metrics
            )
            
            self.logger.info(f"Published restart metrics to CloudWatch")
            
        except Exception as e:
            self.logger.error(f"Failed to publish restart metrics: {str(e)}")
    
    def send_notifications(self, restart_result: RestartResult):
        """Send notifications about restart operation"""
        try:
            message = {
                "operation": "workload_restart",
                "cluster": restart_result.cluster_name,
                "region": restart_result.region,
                "account": restart_result.account_id,
                "workload": {
                    "name": restart_result.workload_name,
                    "namespace": restart_result.namespace,
                    "kind": restart_result.kind
                },
                "success": restart_result.success,
                "rollout_successful": restart_result.rollout_successful,
                "duration_seconds": restart_result.duration_seconds,
                "warnings": restart_result.warnings,
                "timestamp": restart_result.timestamp
            }
            
            if restart_result.error_message:
                message["error"] = restart_result.error_message
            
            subject = f"EKS Workload Restart {'Completed' if restart_result.success else 'Failed'}: {restart_result.workload_name}"
            
            if SNS_TOPIC_ARN:
                sns = self.hub_session.client('sns')
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=subject,
                    Message=json.dumps(message, indent=2)
                )
                
                self.logger.info(f"Sent restart notification")
            
        except Exception as e:
            self.logger.error(f"Failed to send notifications: {str(e)}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for EKS workload restart operations
    
    Expected event format:
    {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "my-eks-cluster",
        "namespace": "default",
        "workload": "my-deployment",
        "kind": "Deployment",
        "wait": true  # Optional, default true
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting workload restart operation - Request ID: {request_id}")
    
    try:
        # Validate input
        required_fields = ["spoke_account_id", "region", "cluster", "namespace", "workload", "kind"]
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        spoke_account_id = event["spoke_account_id"]
        region = event["region"]
        cluster_name = event["cluster"]
        namespace = event["namespace"]
        workload_name = event["workload"]
        workload_kind = event["kind"]
        wait_for_completion = event.get("wait", True)
        
        # Validate inputs
        if not spoke_account_id.isdigit() or len(spoke_account_id) != 12:
            raise ValueError("spoke_account_id must be a 12-digit AWS account ID")
        
        logger.info(f"Processing workload restart for {workload_kind} {workload_name} in {namespace}")
        logger.info(f"Wait for completion: {wait_for_completion}")
        
        # Create workload restarter and perform restart
        workload_restarter = EKSWorkloadRestarter(HUB_SESSION)
        restart_result = workload_restarter.perform_workload_restart(
            spoke_account_id, region, cluster_name, namespace, 
            workload_name, workload_kind, wait_for_completion
        )
        
        # Publish observability data
        workload_restarter.publish_metrics(restart_result)
        workload_restarter.send_notifications(restart_result)
        
        # Prepare response
        response = {
            "ok": restart_result.success,
            "request_id": request_id,
            "restart_result": asdict(restart_result),
            "execution_time_ms": int(restart_result.duration_seconds * 1000)
        }
        
        if not restart_result.success:
            response["error"] = "RestartFailed"
            response["message"] = restart_result.error_message or "Workload restart operation failed"
        
        logger.info(f"Workload restart operation completed - Success: {restart_result.success}")
        
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
        logger.error(f"Workload restart operation failed: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "ok": False,
            "error": "InternalError",
            "message": f"Workload restart failed: {str(e)}",
            "request_id": request_id
        }


# For local testing
if __name__ == "__main__":
    test_event = {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "test-cluster",
        "namespace": "default",
        "workload": "test-deployment",
        "kind": "Deployment",
        "wait": True
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
        def get_remaining_time_in_millis(self):
            return 300000  # 5 minutes
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2, default=str))
