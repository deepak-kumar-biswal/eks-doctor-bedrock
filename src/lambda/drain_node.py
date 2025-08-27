"""
EKS Doctor - Node Drain Lambda Function
Production-grade node draining with safety checks and comprehensive logging.
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

# Configure urllib3 with proper SSL and timeouts
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
MAX_EVICTION_ATTEMPTS = 3
EVICTION_BACKOFF_SECONDS = 5
DRAIN_TIMEOUT_MINUTES = 15
PROTECTED_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "amazon-cloudwatch"}


@dataclass
class PodEvictionResult:
    """Data class for pod eviction results"""
    pod_name: str
    namespace: str
    evicted: bool
    reason: str
    attempts: int
    skip_reason: Optional[str] = None


@dataclass
class DrainResult:
    """Data class for node drain results"""
    node_name: str
    cluster_name: str
    region: str
    account_id: str
    timestamp: str
    success: bool
    cordoned: bool
    pods_found: int
    pods_evicted: int
    pods_failed: int
    pods_skipped: int
    eviction_results: List[PodEvictionResult]
    duration_seconds: float
    error_message: Optional[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class EKSNodeDrainer:
    """Main class for EKS node draining operations"""
    
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
                RoleSessionName=f"eks-node-drain-{int(time.time())}",
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
            
            # Log response for debugging
            self.logger.debug(f"Kubernetes API response: {response.status}")
            
            if response.status >= 400:
                error_msg = f"Kubernetes API {method} {path} failed: HTTP {response.status}"
                if response.data:
                    error_details = response.data.decode('utf-8')[:500]
                    error_msg += f" - {error_details}"
                
                self.logger.error(error_msg)
                
                # For some operations, certain error codes are acceptable
                if method == "POST" and "/eviction" in path and response.status == 429:
                    # Too Many Requests - might be expected during eviction
                    self.logger.warning("Rate limited during eviction - this may be expected")
                    return {"status": "rate_limited"}
                
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
    
    def check_node_exists(self, session: boto3.Session, region: str, cluster_name: str, node_name: str) -> bool:
        """Check if node exists in the cluster"""
        try:
            response = self.make_k8s_request(
                session, region, cluster_name, "GET", f"/api/v1/nodes/{node_name}"
            )
            return "metadata" in response
        except Exception as e:
            if "404" in str(e):
                return False
            raise
    
    def cordon_node(self, session: boto3.Session, region: str, cluster_name: str, node_name: str) -> bool:
        """Cordon a node to prevent new pods from being scheduled"""
        try:
            self.logger.info(f"Cordoning node {node_name}")
            
            # Patch the node to set unschedulable=true
            patch_body = {
                "spec": {
                    "unschedulable": True
                }
            }
            
            response = self.make_k8s_request(
                session, region, cluster_name, "PATCH", 
                f"/api/v1/nodes/{node_name}",
                body=patch_body
            )
            
            self.logger.info(f"Successfully cordoned node {node_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cordon node {node_name}: {str(e)}")
            raise
    
    def get_pods_on_node(self, session: boto3.Session, region: str, cluster_name: str, node_name: str) -> List[Dict]:
        """Get all pods running on the specified node"""
        try:
            self.logger.info(f"Getting pods on node {node_name}")
            
            response = self.make_k8s_request(
                session, region, cluster_name, "GET", 
                f"/api/v1/pods?fieldSelector=spec.nodeName={node_name}"
            )
            
            pods = response.get("items", [])
            self.logger.info(f"Found {len(pods)} pods on node {node_name}")
            
            return pods
            
        except Exception as e:
            self.logger.error(f"Failed to get pods on node {node_name}: {str(e)}")
            raise
    
    def should_skip_pod(self, pod: Dict) -> tuple[bool, Optional[str]]:
        """Determine if a pod should be skipped during eviction"""
        
        metadata = pod.get("metadata", {})
        spec = pod.get("spec", {})
        status = pod.get("status", {})
        
        pod_name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        
        # Skip pods in protected namespaces (with exceptions for certain workloads)
        if namespace in PROTECTED_NAMESPACES:
            # Allow eviction of some system pods that can be safely recreated
            allowed_system_prefixes = ["aws-node", "ebs-csi", "efs-csi", "coredns"]
            if not any(pod_name.startswith(prefix) for prefix in allowed_system_prefixes):
                return True, f"Pod in protected namespace {namespace}"
        
        # Skip DaemonSet pods (they will be recreated automatically)
        owner_references = metadata.get("ownerReferences", [])
        for owner in owner_references:
            if owner.get("kind") == "DaemonSet":
                return True, "DaemonSet pod (will be automatically recreated)"
        
        # Skip static/mirror pods
        annotations = metadata.get("annotations", {})
        if "kubernetes.io/config.mirror" in annotations:
            return True, "Static/mirror pod"
        
        # Skip already completed/failed pods
        phase = status.get("phase", "")
        if phase in ["Succeeded", "Failed"]:
            return True, f"Pod already in {phase} phase"
        
        # Skip pods with local storage (unless it's emptyDir)
        volumes = spec.get("volumes", [])
        for volume in volumes:
            # Check for persistent volumes (dangerous to evict)
            if "persistentVolumeClaim" in volume:
                return True, "Pod has persistent volume claims"
            
            # Check for hostPath volumes (might be critical)
            if "hostPath" in volume:
                host_path = volume["hostPath"].get("path", "")
                # Some hostPath mounts are safe (like /dev/termination-log)
                safe_paths = ["/dev/termination-log", "/var/log", "/var/run/secrets/kubernetes.io"]
                if not any(host_path.startswith(safe) for safe in safe_paths):
                    return True, "Pod has hostPath volume mounts"
        
        # Check for critical system labels
        labels = metadata.get("labels", {})
        if labels.get("tier") == "control-plane":
            return True, "Control plane component"
        
        if labels.get("component") in ["kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"]:
            return True, "Critical Kubernetes component"
        
        return False, None
    
    def evict_pod(
        self, 
        session: boto3.Session, 
        region: str, 
        cluster_name: str, 
        namespace: str, 
        pod_name: str
    ) -> PodEvictionResult:
        """Evict a single pod with retries"""
        
        attempts = 0
        
        while attempts < MAX_EVICTION_ATTEMPTS:
            attempts += 1
            
            try:
                self.logger.info(f"Evicting pod {pod_name} in namespace {namespace} (attempt {attempts})")
                
                # Create eviction object
                eviction_body = {
                    "apiVersion": "policy/v1",
                    "kind": "Eviction",
                    "metadata": {
                        "name": pod_name,
                        "namespace": namespace
                    }
                }
                
                response = self.make_k8s_request(
                    session, region, cluster_name, "POST", 
                    f"/api/v1/namespaces/{namespace}/pods/{pod_name}/eviction",
                    body=eviction_body
                )
                
                # Check for rate limiting
                if response.get("status") == "rate_limited":
                    self.logger.warning(f"Rate limited evicting pod {pod_name}, attempt {attempts}")
                    if attempts < MAX_EVICTION_ATTEMPTS:
                        time.sleep(EVICTION_BACKOFF_SECONDS * attempts)
                        continue
                    else:
                        return PodEvictionResult(
                            pod_name=pod_name,
                            namespace=namespace,
                            evicted=False,
                            reason="Rate limited after maximum attempts",
                            attempts=attempts
                        )
                
                self.logger.info(f"Successfully evicted pod {pod_name}")
                
                return PodEvictionResult(
                    pod_name=pod_name,
                    namespace=namespace,
                    evicted=True,
                    reason="Successfully evicted",
                    attempts=attempts
                )
                
            except Exception as e:
                error_msg = str(e)
                
                # Check for specific error conditions
                if "404" in error_msg:
                    # Pod already deleted
                    return PodEvictionResult(
                        pod_name=pod_name,
                        namespace=namespace,
                        evicted=True,
                        reason="Pod already deleted",
                        attempts=attempts
                    )
                
                if "429" in error_msg or "Too Many Requests" in error_msg:
                    # Rate limited
                    self.logger.warning(f"Rate limited evicting pod {pod_name}, attempt {attempts}")
                    if attempts < MAX_EVICTION_ATTEMPTS:
                        time.sleep(EVICTION_BACKOFF_SECONDS * attempts)
                        continue
                
                if attempts >= MAX_EVICTION_ATTEMPTS:
                    self.logger.error(f"Failed to evict pod {pod_name} after {attempts} attempts: {error_msg}")
                    return PodEvictionResult(
                        pod_name=pod_name,
                        namespace=namespace,
                        evicted=False,
                        reason=f"Failed after {attempts} attempts: {error_msg[:100]}",
                        attempts=attempts
                    )
                
                # Retry on other errors
                self.logger.warning(f"Eviction attempt {attempts} failed for pod {pod_name}: {error_msg}")
                time.sleep(EVICTION_BACKOFF_SECONDS)
                
        # Should not reach here, but just in case
        return PodEvictionResult(
            pod_name=pod_name,
            namespace=namespace,
            evicted=False,
            reason="Maximum attempts exceeded",
            attempts=attempts
        )
    
    def perform_node_drain(
        self, 
        spoke_account_id: str, 
        region: str, 
        cluster_name: str, 
        node_name: str,
        force: bool = False
    ) -> DrainResult:
        """Perform comprehensive node drain operation"""
        start_time = time.time()
        warnings = []
        
        try:
            self.logger.info(f"Starting node drain for {node_name} in cluster {cluster_name} ({spoke_account_id}/{region})")
            
            # Assume spoke role with change permissions
            spoke_session = self.assume_spoke_role(spoke_account_id, SPOKE_ROLE_CHANGE)
            
            # Check if node exists
            if not self.check_node_exists(spoke_session, region, cluster_name, node_name):
                raise ValueError(f"Node {node_name} not found in cluster {cluster_name}")
            
            # Step 1: Cordon the node
            self.logger.info("Step 1: Cordoning node")
            cordoned = self.cordon_node(spoke_session, region, cluster_name, node_name)
            
            # Step 2: Get pods on the node
            self.logger.info("Step 2: Getting pods on node")
            pods = self.get_pods_on_node(spoke_session, region, cluster_name, node_name)
            
            # Step 3: Analyze pods and create eviction plan
            self.logger.info("Step 3: Analyzing pods and creating eviction plan")
            eviction_results = []
            pods_to_evict = []
            pods_to_skip = []
            
            for pod in pods:
                metadata = pod.get("metadata", {})
                pod_name = metadata.get("name", "unknown")
                namespace = metadata.get("namespace", "default")
                
                should_skip, skip_reason = self.should_skip_pod(pod)
                
                if should_skip and not force:
                    pods_to_skip.append((pod_name, namespace, skip_reason))
                    eviction_results.append(PodEvictionResult(
                        pod_name=pod_name,
                        namespace=namespace,
                        evicted=False,
                        reason="Skipped",
                        attempts=0,
                        skip_reason=skip_reason
                    ))
                else:
                    pods_to_evict.append((pod_name, namespace))
                    if should_skip and force:
                        warnings.append(f"Force evicting protected pod {pod_name} in {namespace}")
            
            self.logger.info(f"Eviction plan: {len(pods_to_evict)} pods to evict, {len(pods_to_skip)} pods to skip")
            
            # Step 4: Evict pods
            self.logger.info("Step 4: Starting pod eviction")
            pods_evicted = 0
            pods_failed = 0
            
            for pod_name, namespace in pods_to_evict:
                result = self.evict_pod(spoke_session, region, cluster_name, namespace, pod_name)
                eviction_results.append(result)
                
                if result.evicted:
                    pods_evicted += 1
                else:
                    pods_failed += 1
                    
                # Small delay between evictions to avoid overwhelming the API
                time.sleep(0.5)
            
            # Step 5: Verify drain completion
            self.logger.info("Step 5: Verifying drain completion")
            remaining_pods = []
            
            # Wait a bit for pods to be deleted
            time.sleep(5)
            
            try:
                current_pods = self.get_pods_on_node(spoke_session, region, cluster_name, node_name)
                for pod in current_pods:
                    metadata = pod.get("metadata", {})
                    pod_name = metadata.get("name", "unknown")
                    namespace = metadata.get("namespace", "default")
                    
                    # Check if this is a DaemonSet pod or other expected pod
                    should_skip, _ = self.should_skip_pod(pod)
                    if not should_skip:
                        remaining_pods.append(f"{namespace}/{pod_name}")
                
                if remaining_pods:
                    warnings.append(f"Some pods remain on node after drain: {', '.join(remaining_pods[:5])}")
                    if len(remaining_pods) > 5:
                        warnings.append(f"... and {len(remaining_pods) - 5} more pods")
                        
            except Exception as e:
                warnings.append(f"Could not verify drain completion: {str(e)}")
            
            # Create result
            execution_time = time.time() - start_time
            
            drain_result = DrainResult(
                node_name=node_name,
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=pods_failed == 0,
                cordoned=cordoned,
                pods_found=len(pods),
                pods_evicted=pods_evicted,
                pods_failed=pods_failed,
                pods_skipped=len(pods_to_skip),
                eviction_results=eviction_results,
                duration_seconds=execution_time,
                warnings=warnings
            )
            
            self.logger.info(f"Node drain completed in {execution_time:.2f}s - Success: {drain_result.success}")
            
            return drain_result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Node drain failed after {execution_time:.2f}s: {str(e)}")
            
            # Return failed result
            return DrainResult(
                node_name=node_name,
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=False,
                cordoned=False,
                pods_found=0,
                pods_evicted=0,
                pods_failed=0,
                pods_skipped=0,
                eviction_results=[],
                duration_seconds=execution_time,
                error_message=str(e),
                warnings=warnings
            )
    
    def publish_metrics(self, drain_result: DrainResult):
        """Publish drain metrics to CloudWatch"""
        try:
            cloudwatch = self.hub_session.client('cloudwatch')
            
            timestamp = datetime.now(timezone.utc)
            namespace = 'EKSDoctor/NodeDrain'
            
            dimensions = [
                {'Name': 'ClusterName', 'Value': drain_result.cluster_name},
                {'Name': 'Region', 'Value': drain_result.region},
                {'Name': 'AccountId', 'Value': drain_result.account_id},
                {'Name': 'NodeName', 'Value': drain_result.node_name}
            ]
            
            metrics = [
                {
                    'MetricName': 'DrainSuccess',
                    'Dimensions': dimensions,
                    'Value': 1 if drain_result.success else 0,
                    'Unit': 'None',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'DrainDuration',
                    'Dimensions': dimensions,
                    'Value': drain_result.duration_seconds,
                    'Unit': 'Seconds',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'PodsEvicted',
                    'Dimensions': dimensions,
                    'Value': drain_result.pods_evicted,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'PodsFailed',
                    'Dimensions': dimensions,
                    'Value': drain_result.pods_failed,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'PodsSkipped',
                    'Dimensions': dimensions,
                    'Value': drain_result.pods_skipped,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                }
            ]
            
            cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=metrics
            )
            
            self.logger.info(f"Published drain metrics to CloudWatch")
            
        except Exception as e:
            self.logger.error(f"Failed to publish drain metrics: {str(e)}")
    
    def send_notifications(self, drain_result: DrainResult):
        """Send notifications about drain operation"""
        try:
            message = {
                "operation": "node_drain",
                "cluster": drain_result.cluster_name,
                "region": drain_result.region,
                "account": drain_result.account_id,
                "node": drain_result.node_name,
                "success": drain_result.success,
                "summary": {
                    "pods_found": drain_result.pods_found,
                    "pods_evicted": drain_result.pods_evicted,
                    "pods_failed": drain_result.pods_failed,
                    "pods_skipped": drain_result.pods_skipped,
                    "duration_seconds": drain_result.duration_seconds
                },
                "warnings": drain_result.warnings,
                "timestamp": drain_result.timestamp
            }
            
            if drain_result.error_message:
                message["error"] = drain_result.error_message
            
            subject = f"EKS Node Drain {'Completed' if drain_result.success else 'Failed'}: {drain_result.node_name}"
            
            if SNS_TOPIC_ARN:
                sns = self.hub_session.client('sns')
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=subject,
                    Message=json.dumps(message, indent=2)
                )
                
                self.logger.info(f"Sent drain notification")
            
        except Exception as e:
            self.logger.error(f"Failed to send notifications: {str(e)}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for EKS node drain operations
    
    Expected event format:
    {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "my-eks-cluster",
        "node": "ip-10-1-23-45.ec2.internal",
        "force": false  # Optional, default false
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting node drain operation - Request ID: {request_id}")
    
    try:
        # Validate input
        required_fields = ["spoke_account_id", "region", "cluster", "node"]
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        spoke_account_id = event["spoke_account_id"]
        region = event["region"]
        cluster_name = event["cluster"]
        node_name = event["node"]
        force = event.get("force", False)
        
        # Validate inputs
        if not spoke_account_id.isdigit() or len(spoke_account_id) != 12:
            raise ValueError("spoke_account_id must be a 12-digit AWS account ID")
        
        logger.info(f"Processing node drain for {node_name} in {cluster_name} ({spoke_account_id}/{region})")
        logger.info(f"Force mode: {force}")
        
        # Create node drainer and perform drain
        node_drainer = EKSNodeDrainer(HUB_SESSION)
        drain_result = node_drainer.perform_node_drain(
            spoke_account_id, region, cluster_name, node_name, force
        )
        
        # Publish observability data
        node_drainer.publish_metrics(drain_result)
        node_drainer.send_notifications(drain_result)
        
        # Prepare response
        response = {
            "ok": drain_result.success,
            "request_id": request_id,
            "drain_result": asdict(drain_result),
            "execution_time_ms": int(drain_result.duration_seconds * 1000)
        }
        
        if not drain_result.success:
            response["error"] = "DrainFailed"
            response["message"] = drain_result.error_message or "Node drain operation failed"
        
        logger.info(f"Node drain operation completed - Success: {drain_result.success}")
        
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
        logger.error(f"Node drain operation failed: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "ok": False,
            "error": "InternalError",
            "message": f"Node drain failed: {str(e)}",
            "request_id": request_id
        }


# For local testing
if __name__ == "__main__":
    test_event = {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "test-cluster",
        "node": "ip-10-1-23-45.ec2.internal",
        "force": False
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
        def get_remaining_time_in_millis(self):
            return 300000  # 5 minutes
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2, default=str))
