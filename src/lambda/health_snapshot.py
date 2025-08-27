"""
EKS Doctor - Health Snapshot Lambda Function
Production-grade cluster health monitoring with comprehensive diagnostics.
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
SPOKE_ROLE_READONLY = os.environ.get("SPOKE_ROLE_READONLY", "eks-ops-readonly")
REGIONS = os.environ.get("REGIONS", "us-east-1,us-west-2").split(',')
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME")

# Constants
MAX_EVENTS_TO_ANALYZE = 50
HEALTH_CHECK_TIMEOUT = 30
K8S_API_TIMEOUT = 15
RETRY_ATTEMPTS = 3


@dataclass
class NodeHealth:
    """Data class for node health information"""
    name: str
    ready: bool
    schedulable: bool
    cpu_pressure: bool
    memory_pressure: bool
    disk_pressure: bool
    pid_pressure: bool
    instance_id: Optional[str] = None
    instance_type: Optional[str] = None
    availability_zone: Optional[str] = None
    kernel_version: Optional[str] = None
    kubelet_version: Optional[str] = None
    conditions: List[Dict] = None
    
    def __post_init__(self):
        if self.conditions is None:
            self.conditions = []


@dataclass
class PodHealth:
    """Data class for pod health information"""
    name: str
    namespace: str
    phase: str
    ready_containers: int
    total_containers: int
    restarts: int
    node: Optional[str] = None
    qos_class: Optional[str] = None
    creation_timestamp: Optional[str] = None
    conditions: List[Dict] = None
    container_statuses: List[Dict] = None
    
    def __post_init__(self):
        if self.conditions is None:
            self.conditions = []
        if self.container_statuses is None:
            self.container_statuses = []


@dataclass
class ClusterHealth:
    """Data class for overall cluster health"""
    cluster_name: str
    region: str
    account_id: str
    timestamp: str
    kubernetes_version: str
    status: str
    endpoint: str
    nodes_total: int
    nodes_ready: int
    nodes_not_ready: List[str]
    pods_total: int
    pods_running: int
    pods_pending: int
    pods_failed: int
    pods_crashloop: List[Dict]
    critical_events: List[Dict]
    warnings: List[str]
    recommendations: List[str]
    health_score: int  # 0-100
    nodes: List[NodeHealth] = None
    problematic_pods: List[PodHealth] = None
    
    def __post_init__(self):
        if self.nodes is None:
            self.nodes = []
        if self.problematic_pods is None:
            self.problematic_pods = []


class EKSHealthMonitor:
    """Main class for EKS cluster health monitoring"""
    
    def __init__(self, hub_session: boto3.Session):
        self.hub_session = hub_session
        self.logger = logger
        
    def assume_spoke_role(self, spoke_account_id: str, role_name: str) -> boto3.Session:
        """Assume role in spoke account with proper error handling and logging"""
        try:
            sts_client = self.hub_session.client("sts")
            
            self.logger.info(f"Assuming role {role_name} in account {spoke_account_id}")
            
            response = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{spoke_account_id}:role/{role_name}",
                RoleSessionName=f"eks-doctor-{int(time.time())}",
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
            
            if error_code == 'AccessDenied':
                raise ValueError(f"Access denied when assuming role. Check IAM permissions and ExternalId.")
            elif error_code == 'InvalidUserID.NotFound':
                raise ValueError(f"Role {role_name} not found in account {spoke_account_id}")
            else:
                raise
                
        except Exception as e:
            self.logger.error(f"Unexpected error assuming role: {str(e)}")
            raise
    
    def get_kubernetes_token(self, session: boto3.Session, region: str, cluster_name: str) -> str:
        """Generate Kubernetes API token using AWS STS"""
        try:
            # Use the session's credentials to create the signer
            credentials = session.get_credentials()
            
            signer = RequestSigner(
                service_name="sts",
                region_name=region,
                signing_name="sts",
                signature_version="v4",
                credentials=credentials,
                event_emitter=session._session.get_component("event_emitter"),
            )
            
            # Build the presigned URL for GetCallerIdentity with k8s header
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
            
            # Create the token
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
        path: str,
        method: str = "GET",
        body: Optional[Dict] = None
    ) -> Dict:
        """Make authenticated request to Kubernetes API"""
        try:
            # Get cluster endpoint and certificate
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
                    error_details = response.data.decode('utf-8')[:500]  # Limit error details
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
    
    def analyze_node_health(self, nodes_data: Dict) -> List[NodeHealth]:
        """Analyze node health from Kubernetes API data"""
        nodes = []
        
        for node_data in nodes_data.get("items", []):
            try:
                metadata = node_data.get("metadata", {})
                status = node_data.get("status", {})
                spec = node_data.get("spec", {})
                
                node_name = metadata.get("name", "unknown")
                conditions = status.get("conditions", [])
                
                # Determine node readiness and pressures
                ready = False
                cpu_pressure = False
                memory_pressure = False
                disk_pressure = False
                pid_pressure = False
                
                for condition in conditions:
                    condition_type = condition.get("type", "")
                    condition_status = condition.get("status", "Unknown")
                    
                    if condition_type == "Ready":
                        ready = (condition_status == "True")
                    elif condition_type == "MemoryPressure":
                        memory_pressure = (condition_status == "True")
                    elif condition_type == "DiskPressure":
                        disk_pressure = (condition_status == "True")
                    elif condition_type == "PIDPressure":
                        pid_pressure = (condition_status == "True")
                
                # Check if node is schedulable
                schedulable = not spec.get("unschedulable", False)
                
                # Extract node info
                node_info = status.get("nodeInfo", {})
                instance_id = None
                instance_type = None
                availability_zone = None
                
                # Try to get instance info from annotations or labels
                annotations = metadata.get("annotations", {})
                labels = metadata.get("labels", {})
                
                # Common ways instance info is stored
                for key, value in annotations.items():
                    if "instance-id" in key.lower():
                        instance_id = value
                    elif "instance-type" in key.lower():
                        instance_type = value
                
                for key, value in labels.items():
                    if "instance-type" in key.lower():
                        instance_type = value
                    elif "zone" in key.lower():
                        availability_zone = value
                
                node = NodeHealth(
                    name=node_name,
                    ready=ready,
                    schedulable=schedulable,
                    cpu_pressure=cpu_pressure,
                    memory_pressure=memory_pressure,
                    disk_pressure=disk_pressure,
                    pid_pressure=pid_pressure,
                    instance_id=instance_id,
                    instance_type=instance_type,
                    availability_zone=availability_zone,
                    kernel_version=node_info.get("kernelVersion"),
                    kubelet_version=node_info.get("kubeletVersion"),
                    conditions=conditions
                )
                
                nodes.append(node)
                
            except Exception as e:
                self.logger.warning(f"Failed to analyze node {node_data.get('metadata', {}).get('name', 'unknown')}: {str(e)}")
                continue
        
        return nodes
    
    def analyze_pod_health(self, pods_data: Dict) -> tuple[List[PodHealth], List[Dict]]:
        """Analyze pod health and identify problematic pods"""
        all_pods = []
        crashloop_pods = []
        
        for pod_data in pods_data.get("items", []):
            try:
                metadata = pod_data.get("metadata", {})
                spec = pod_data.get("spec", {})
                status = pod_data.get("status", {})
                
                pod_name = metadata.get("name", "unknown")
                namespace = metadata.get("namespace", "unknown")
                phase = status.get("phase", "Unknown")
                
                # Count containers and restarts
                container_statuses = status.get("containerStatuses", [])
                total_containers = len(spec.get("containers", []))
                ready_containers = sum(1 for cs in container_statuses if cs.get("ready", False))
                total_restarts = sum(cs.get("restartCount", 0) for cs in container_statuses)
                
                # Check for crash loop backoff
                is_crashloop = any(
                    cs.get("state", {}).get("waiting", {}).get("reason") == "CrashLoopBackOff"
                    for cs in container_statuses
                )
                
                pod = PodHealth(
                    name=pod_name,
                    namespace=namespace,
                    phase=phase,
                    ready_containers=ready_containers,
                    total_containers=total_containers,
                    restarts=total_restarts,
                    node=spec.get("nodeName"),
                    qos_class=status.get("qosClass"),
                    creation_timestamp=metadata.get("creationTimestamp"),
                    conditions=status.get("conditions", []),
                    container_statuses=container_statuses
                )
                
                all_pods.append(pod)
                
                # Track crashloop pods separately
                if is_crashloop:
                    crashloop_pods.append({
                        "namespace": namespace,
                        "name": pod_name,
                        "node": spec.get("nodeName"),
                        "containers": [
                            {
                                "name": cs.get("name"),
                                "image": cs.get("image"),
                                "reason": cs.get("state", {}).get("waiting", {}).get("reason"),
                                "message": cs.get("state", {}).get("waiting", {}).get("message", "")[:200],
                                "restart_count": cs.get("restartCount", 0)
                            }
                            for cs in container_statuses
                            if cs.get("state", {}).get("waiting", {}).get("reason") == "CrashLoopBackOff"
                        ]
                    })
                    
            except Exception as e:
                self.logger.warning(f"Failed to analyze pod {pod_data.get('metadata', {}).get('name', 'unknown')}: {str(e)}")
                continue
        
        return all_pods, crashloop_pods
    
    def analyze_events(self, events_data: Dict) -> tuple[List[Dict], List[str]]:
        """Analyze Kubernetes events for critical issues and warnings"""
        critical_events = []
        warnings = []
        
        events = events_data.get("items", [])
        
        # Sort events by last timestamp (newest first)
        try:
            events.sort(
                key=lambda e: e.get("lastTimestamp", e.get("eventTime", "1970-01-01T00:00:00Z")),
                reverse=True
            )
        except Exception as e:
            self.logger.warning(f"Failed to sort events: {str(e)}")
        
        # Analyze recent events
        for event in events[:MAX_EVENTS_TO_ANALYZE]:
            try:
                event_type = event.get("type", "Normal")
                reason = event.get("reason", "")
                message = event.get("message", "")
                namespace = event.get("metadata", {}).get("namespace")
                name = event.get("metadata", {}).get("name", "")
                
                # Critical event patterns
                critical_reasons = {
                    "FailedScheduling", "FailedMount", "FailedAttachVolume", 
                    "FailedCreatePodSandBox", "NetworkNotReady", "NodeNotReady",
                    "SystemOOM", "KubeletHasInsufficientMemory", "KubeletHasDiskPressure"
                }
                
                # Warning patterns
                warning_reasons = {
                    "BackOff", "Unhealthy", "ProbeWarning", "InspectFailed",
                    "DNSConfigForming", "FreeDiskSpaceFailed"
                }
                
                if event_type == "Warning" or reason in critical_reasons:
                    event_summary = {
                        "timestamp": event.get("lastTimestamp", event.get("eventTime")),
                        "type": event_type,
                        "reason": reason,
                        "message": message[:300],  # Truncate long messages
                        "namespace": namespace,
                        "name": name,
                        "count": event.get("count", 1),
                        "source": event.get("source", {}).get("component", "unknown")
                    }
                    
                    if reason in critical_reasons or event_type == "Warning":
                        critical_events.append(event_summary)
                    
                    if reason in warning_reasons:
                        warnings.append(f"{reason}: {message[:100]}")
                        
            except Exception as e:
                self.logger.warning(f"Failed to analyze event: {str(e)}")
                continue
        
        return critical_events[:20], warnings[:10]  # Limit the number of events/warnings
    
    def calculate_health_score(self, cluster_health: ClusterHealth) -> int:
        """Calculate overall cluster health score (0-100)"""
        score = 100
        
        # Node health impact (40 points)
        if cluster_health.nodes_total > 0:
            node_ready_ratio = cluster_health.nodes_ready / cluster_health.nodes_total
            score -= int((1 - node_ready_ratio) * 40)
        
        # Pod health impact (30 points)
        if cluster_health.pods_total > 0:
            pod_running_ratio = cluster_health.pods_running / cluster_health.pods_total
            score -= int((1 - pod_running_ratio) * 30)
            
            # Extra penalty for failed/crashloop pods
            failed_ratio = cluster_health.pods_failed / cluster_health.pods_total
            score -= int(failed_ratio * 10)
            
            crashloop_ratio = len(cluster_health.pods_crashloop) / cluster_health.pods_total
            score -= int(crashloop_ratio * 10)
        
        # Critical events impact (20 points)
        critical_event_count = len(cluster_health.critical_events)
        score -= min(critical_event_count * 2, 20)
        
        # Node pressure impact (10 points)
        pressure_nodes = sum(1 for node in cluster_health.nodes 
                           if node.memory_pressure or node.disk_pressure or node.pid_pressure)
        if cluster_health.nodes_total > 0:
            pressure_ratio = pressure_nodes / cluster_health.nodes_total
            score -= int(pressure_ratio * 10)
        
        return max(0, min(100, score))
    
    def generate_recommendations(self, cluster_health: ClusterHealth) -> List[str]:
        """Generate actionable recommendations based on cluster health"""
        recommendations = []
        
        # Node recommendations
        not_ready_count = len(cluster_health.nodes_not_ready)
        if not_ready_count > 0:
            recommendations.append(
                f"Investigate {not_ready_count} not ready nodes: {', '.join(cluster_health.nodes_not_ready[:3])}"
                + ("..." if not_ready_count > 3 else "")
            )
        
        # Check for node pressures
        pressure_nodes = [node for node in cluster_health.nodes 
                         if node.memory_pressure or node.disk_pressure or node.pid_pressure]
        if pressure_nodes:
            recommendations.append(
                f"Address resource pressure on {len(pressure_nodes)} nodes - consider scaling or resource optimization"
            )
        
        # Pod recommendations
        if cluster_health.pods_crashloop:
            recommendations.append(
                f"Fix {len(cluster_health.pods_crashloop)} crash-looping pods - check application logs and resource limits"
            )
        
        if cluster_health.pods_pending > 0:
            recommendations.append(
                f"Resolve {cluster_health.pods_pending} pending pods - check resource availability and scheduling constraints"
            )
        
        # Event-based recommendations
        if cluster_health.critical_events:
            event_reasons = {event['reason'] for event in cluster_health.critical_events}
            if 'FailedScheduling' in event_reasons:
                recommendations.append("Scale cluster nodes or optimize resource requests - pods cannot be scheduled")
            if 'FailedMount' in event_reasons:
                recommendations.append("Check storage and volume configurations - mount failures detected")
        
        # Health score recommendations
        if cluster_health.health_score < 70:
            recommendations.append("Cluster health is below optimal - prioritize addressing critical issues")
        elif cluster_health.health_score < 85:
            recommendations.append("Monitor cluster closely - some issues may impact performance")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def perform_health_check(
        self, 
        spoke_account_id: str, 
        region: str, 
        cluster_name: str
    ) -> ClusterHealth:
        """Perform comprehensive cluster health check"""
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting health check for cluster {cluster_name} in {spoke_account_id}/{region}")
            
            # Assume spoke role
            spoke_session = self.assume_spoke_role(spoke_account_id, SPOKE_ROLE_READONLY)
            
            # Get EKS cluster information
            eks_client = spoke_session.client("eks", region_name=region)
            cluster_info = eks_client.describe_cluster(name=cluster_name)["cluster"]
            
            # Gather Kubernetes API data
            self.logger.info("Fetching Kubernetes API data")
            nodes_data = self.make_k8s_request(spoke_session, region, cluster_name, "/api/v1/nodes")
            pods_data = self.make_k8s_request(spoke_session, region, cluster_name, "/api/v1/pods")
            events_data = self.make_k8s_request(spoke_session, region, cluster_name, "/api/v1/events")
            
            # Analyze the data
            self.logger.info("Analyzing cluster health data")
            nodes = self.analyze_node_health(nodes_data)
            all_pods, crashloop_pods = self.analyze_pod_health(pods_data)
            critical_events, warnings = self.analyze_events(events_data)
            
            # Calculate pod statistics
            pods_by_phase = {}
            for pod in all_pods:
                phase = pod.phase
                pods_by_phase[phase] = pods_by_phase.get(phase, 0) + 1
            
            # Identify problematic pods
            problematic_pods = [
                pod for pod in all_pods 
                if (pod.phase in ["Failed", "Pending"] or 
                    pod.restarts > 5 or 
                    pod.ready_containers < pod.total_containers)
            ][:20]  # Limit to top 20 problematic pods
            
            # Create cluster health object
            cluster_health = ClusterHealth(
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                kubernetes_version=cluster_info.get("version", "unknown"),
                status=cluster_info.get("status", "unknown"),
                endpoint=cluster_info.get("endpoint", ""),
                nodes_total=len(nodes),
                nodes_ready=sum(1 for node in nodes if node.ready),
                nodes_not_ready=[node.name for node in nodes if not node.ready],
                pods_total=len(all_pods),
                pods_running=pods_by_phase.get("Running", 0),
                pods_pending=pods_by_phase.get("Pending", 0),
                pods_failed=pods_by_phase.get("Failed", 0),
                pods_crashloop=crashloop_pods,
                critical_events=critical_events,
                warnings=warnings,
                recommendations=[],
                health_score=0,  # Will be calculated below
                nodes=nodes,
                problematic_pods=problematic_pods
            )
            
            # Calculate health score and recommendations
            cluster_health.health_score = self.calculate_health_score(cluster_health)
            cluster_health.recommendations = self.generate_recommendations(cluster_health)
            
            execution_time = time.time() - start_time
            self.logger.info(f"Health check completed in {execution_time:.2f}s - Health Score: {cluster_health.health_score}")
            
            return cluster_health
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Health check failed after {execution_time:.2f}s: {str(e)}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    def publish_metrics(self, cluster_health: ClusterHealth):
        """Publish custom metrics to CloudWatch"""
        try:
            cloudwatch = self.hub_session.client('cloudwatch')
            
            timestamp = datetime.now(timezone.utc)
            namespace = 'EKSDoctor/ClusterHealth'
            
            dimensions = [
                {'Name': 'ClusterName', 'Value': cluster_health.cluster_name},
                {'Name': 'Region', 'Value': cluster_health.region},
                {'Name': 'AccountId', 'Value': cluster_health.account_id}
            ]
            
            metrics = [
                {
                    'MetricName': 'HealthScore',
                    'Dimensions': dimensions,
                    'Value': cluster_health.health_score,
                    'Unit': 'None',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'NodesTotal',
                    'Dimensions': dimensions,
                    'Value': cluster_health.nodes_total,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'NodesReady',
                    'Dimensions': dimensions,
                    'Value': cluster_health.nodes_ready,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'PodsTotal',
                    'Dimensions': dimensions,
                    'Value': cluster_health.pods_total,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'PodsRunning',
                    'Dimensions': dimensions,
                    'Value': cluster_health.pods_running,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'PodsPending',
                    'Dimensions': dimensions,
                    'Value': cluster_health.pods_pending,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'PodsFailed',
                    'Dimensions': dimensions,
                    'Value': cluster_health.pods_failed,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'CrashLoopPods',
                    'Dimensions': dimensions,
                    'Value': len(cluster_health.pods_crashloop),
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'CriticalEvents',
                    'Dimensions': dimensions,
                    'Value': len(cluster_health.critical_events),
                    'Unit': 'Count',
                    'Timestamp': timestamp
                }
            ]
            
            # Send metrics in batches of 20 (CloudWatch limit)
            for i in range(0, len(metrics), 20):
                batch = metrics[i:i+20]
                cloudwatch.put_metric_data(
                    Namespace=namespace,
                    MetricData=batch
                )
            
            self.logger.info(f"Published {len(metrics)} metrics to CloudWatch")
            
        except Exception as e:
            self.logger.error(f"Failed to publish metrics: {str(e)}")
    
    def send_notifications(self, cluster_health: ClusterHealth):
        """Send notifications for critical issues"""
        try:
            if cluster_health.health_score < 70 or cluster_health.critical_events:
                message = {
                    "alert_type": "cluster_health_warning",
                    "cluster": cluster_health.cluster_name,
                    "region": cluster_health.region,
                    "account": cluster_health.account_id,
                    "health_score": cluster_health.health_score,
                    "issues": {
                        "nodes_not_ready": len(cluster_health.nodes_not_ready),
                        "pods_crashloop": len(cluster_health.pods_crashloop),
                        "pods_pending": cluster_health.pods_pending,
                        "critical_events": len(cluster_health.critical_events)
                    },
                    "recommendations": cluster_health.recommendations[:3],
                    "timestamp": cluster_health.timestamp
                }
                
                if SNS_TOPIC_ARN:
                    sns = self.hub_session.client('sns')
                    sns.publish(
                        TopicArn=SNS_TOPIC_ARN,
                        Subject=f"EKS Cluster Health Alert: {cluster_health.cluster_name}",
                        Message=json.dumps(message, indent=2)
                    )
                    
                    self.logger.info(f"Sent health alert notification for {cluster_health.cluster_name}")
                
        except Exception as e:
            self.logger.error(f"Failed to send notifications: {str(e)}")
    
    def publish_events(self, cluster_health: ClusterHealth):
        """Publish events to EventBridge for downstream processing"""
        try:
            if EVENT_BUS_NAME:
                events_client = self.hub_session.client('events')
                
                event_detail = {
                    "cluster_name": cluster_health.cluster_name,
                    "region": cluster_health.region,
                    "account_id": cluster_health.account_id,
                    "health_score": cluster_health.health_score,
                    "timestamp": cluster_health.timestamp,
                    "summary": {
                        "nodes_total": cluster_health.nodes_total,
                        "nodes_ready": cluster_health.nodes_ready,
                        "pods_total": cluster_health.pods_total,
                        "pods_running": cluster_health.pods_running,
                        "pods_pending": cluster_health.pods_pending,
                        "pods_failed": cluster_health.pods_failed,
                        "crashloop_count": len(cluster_health.pods_crashloop),
                        "critical_events_count": len(cluster_health.critical_events)
                    }
                }
                
                events_client.put_events(
                    Entries=[
                        {
                            'Source': 'eks-doctor.health-check',
                            'DetailType': 'EKS Cluster Health Check',
                            'Detail': json.dumps(event_detail),
                            'EventBusName': EVENT_BUS_NAME
                        }
                    ]
                )
                
                self.logger.info(f"Published health check event to EventBridge")
                
        except Exception as e:
            self.logger.error(f"Failed to publish events: {str(e)}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for EKS cluster health snapshot
    
    Expected event format:
    {
        "spoke_account_id": "123456789012",
        "region": "us-east-1", 
        "cluster": "my-eks-cluster"
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting health snapshot - Request ID: {request_id}")
    
    try:
        # Validate input
        required_fields = ["spoke_account_id", "region", "cluster"]
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        spoke_account_id = event["spoke_account_id"]
        region = event["region"]
        cluster_name = event["cluster"]
        
        # Validate inputs
        if not spoke_account_id.isdigit() or len(spoke_account_id) != 12:
            raise ValueError("spoke_account_id must be a 12-digit AWS account ID")
        
        if region not in REGIONS:
            logger.warning(f"Region {region} not in configured regions {REGIONS}")
        
        logger.info(f"Processing health check for {cluster_name} in {spoke_account_id}/{region}")
        
        # Create health monitor and perform check
        health_monitor = EKSHealthMonitor(HUB_SESSION)
        cluster_health = health_monitor.perform_health_check(spoke_account_id, region, cluster_name)
        
        # Publish observability data
        health_monitor.publish_metrics(cluster_health)
        health_monitor.send_notifications(cluster_health)
        health_monitor.publish_events(cluster_health)
        
        # Prepare response
        response = {
            "ok": True,
            "request_id": request_id,
            "cluster_health": asdict(cluster_health),
            "execution_time_ms": int((time.time() - context.get_remaining_time_in_millis() / 1000) * 1000) if context else 0
        }
        
        logger.info(f"Health snapshot completed successfully - Health Score: {cluster_health.health_score}")
        
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
        logger.error(f"Health snapshot failed: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "ok": False,
            "error": "InternalError", 
            "message": f"Health check failed: {str(e)}",
            "request_id": request_id
        }


# For local testing
if __name__ == "__main__":
    test_event = {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "test-cluster"
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
        def get_remaining_time_in_millis(self):
            return 30000
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2, default=str))
