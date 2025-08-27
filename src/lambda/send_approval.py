"""
EKS Doctor - Send Approval Request Lambda Function
Production-grade approval workflow with multiple notification channels.
"""

import os
import json
import boto3
import urllib3
import logging
import time
import traceback
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Configure urllib3
http = urllib3.PoolManager(
    timeout=urllib3.Timeout(connect=5.0, read=10.0),
    retries=urllib3.Retry(total=3, backoff_factor=0.3)
)

# Environment variables
HUB_SESSION = boto3.Session()
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
APPROVE_URL_BASE = os.environ.get("APPROVE_URL_BASE")  # API Gateway URL
APPROVAL_TIMEOUT_MINUTES = int(os.environ.get("APPROVAL_TIMEOUT_MINUTES", "60"))

# Constants
MAX_MESSAGE_LENGTH = 1000


class ApprovalRequestSender:
    """Main class for sending approval requests"""
    
    def __init__(self, hub_session: boto3.Session):
        self.hub_session = hub_session
        self.logger = logger
    
    def create_approval_urls(self, task_token: str) -> Dict[str, str]:
        """Create approval and rejection URLs"""
        try:
            import urllib.parse
            
            encoded_token = urllib.parse.quote(task_token, safe='')
            
            urls = {
                "approve": f"{APPROVE_URL_BASE}?token={encoded_token}&action=approve",
                "reject": f"{APPROVE_URL_BASE}?token={encoded_token}&action=reject"
            }
            
            return urls
            
        except Exception as e:
            self.logger.error(f"Failed to create approval URLs: {str(e)}")
            raise
    
    def format_approval_message(self, approval_request: Dict[str, Any]) -> Dict[str, str]:
        """Format approval message for different channels"""
        
        operation = approval_request.get("operation", "Unknown Operation")
        cluster = approval_request.get("cluster", "unknown")
        region = approval_request.get("region", "unknown")
        account = approval_request.get("account", "unknown")
        details = approval_request.get("details", {})
        reason = approval_request.get("reason", "Automated EKS Doctor operation")
        
        # Base message
        base_message = f"""
🔧 EKS Doctor Approval Request

Operation: {operation}
Cluster: {cluster}
Region: {region}
Account: {account}
Reason: {reason}

Details:
""".strip()
        
        # Add operation-specific details
        if operation == "drain_node":
            node = details.get("node", "unknown")
            base_message += f"""
• Node to drain: {node}
• Force mode: {details.get('force', False)}
• Estimated downtime: {details.get('estimated_downtime', 'Unknown')}
"""
        
        elif operation == "scale_nodegroup":
            nodegroup = details.get("nodegroup", "unknown")
            current_size = details.get("current_size", "unknown")
            desired_size = details.get("desired_size", "unknown")
            base_message += f"""
• NodeGroup: {nodegroup}
• Current size: {current_size}
• Desired size: {desired_size}
• Scale direction: {"Up" if desired_size > current_size else "Down"}
"""
        
        elif operation == "restart_workload":
            workload = details.get("workload", "unknown")
            namespace = details.get("namespace", "default")
            kind = details.get("kind", "Deployment")
            base_message += f"""
• Workload: {kind}/{workload}
• Namespace: {namespace}
• Restart method: Rolling update
"""
        
        # Truncate if too long
        if len(base_message) > MAX_MESSAGE_LENGTH:
            base_message = base_message[:MAX_MESSAGE_LENGTH - 3] + "..."
        
        return {
            "plain": base_message,
            "html": base_message.replace("\n", "<br>"),
            "markdown": base_message
        }
    
    def send_slack_approval(
        self, 
        approval_request: Dict[str, Any], 
        task_token: str,
        urls: Dict[str, str]
    ) -> bool:
        """Send approval request to Slack"""
        try:
            if not SLACK_WEBHOOK_URL:
                self.logger.warning("Slack webhook URL not configured")
                return False
            
            messages = self.format_approval_message(approval_request)
            
            # Create Slack blocks for rich formatting
            slack_payload = {
                "text": "EKS Doctor Approval Request",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🔧 EKS Doctor Approval Request"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": messages["markdown"]
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "✅ Approve"
                                },
                                "style": "primary",
                                "url": urls["approve"]
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "❌ Reject"
                                },
                                "style": "danger",
                                "url": urls["reject"]
                            }
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"⏰ Expires in {APPROVAL_TIMEOUT_MINUTES} minutes | 🔗 Request ID: {approval_request.get('request_id', 'unknown')}"
                            }
                        ]
                    }
                ]
            }
            
            response = http.request(
                "POST",
                SLACK_WEBHOOK_URL,
                body=json.dumps(slack_payload).encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status == 200:
                self.logger.info("Successfully sent Slack approval request")
                return True
            else:
                self.logger.error(f"Failed to send Slack message: HTTP {response.status} - {response.data}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send Slack approval: {str(e)}")
            return False
    
    def send_email_approval(
        self, 
        approval_request: Dict[str, Any], 
        task_token: str,
        urls: Dict[str, str]
    ) -> bool:
        """Send approval request via email (SNS)"""
        try:
            if not SNS_TOPIC_ARN:
                self.logger.warning("SNS topic ARN not configured")
                return False
            
            messages = self.format_approval_message(approval_request)
            
            # Create email content
            email_body = f"""{messages['plain']}

APPROVAL ACTIONS:
✅ Approve: {urls['approve']}
❌ Reject: {urls['reject']}

This request expires in {APPROVAL_TIMEOUT_MINUTES} minutes.
Request ID: {approval_request.get('request_id', 'unknown')}

---
EKS Doctor Automated System
"""
            
            subject = f"EKS Doctor Approval Required: {approval_request.get('operation', 'Unknown')} - {approval_request.get('cluster', 'Unknown')}"
            
            sns_client = self.hub_session.client('sns')
            response = sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=subject,
                Message=email_body
            )
            
            self.logger.info(f"Successfully sent email approval request: {response['MessageId']}")
            return True
            
        except ClientError as e:
            self.logger.error(f"Failed to send email approval: {e.response['Error']['Message']}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send email approval: {str(e)}")
            return False
    
    def store_approval_request(
        self, 
        approval_request: Dict[str, Any], 
        task_token: str
    ) -> bool:
        """Store approval request for tracking and audit"""
        try:
            # Store in DynamoDB for tracking (if table exists)
            table_name = os.environ.get("APPROVAL_REQUESTS_TABLE")
            if not table_name:
                self.logger.info("No approval requests table configured - skipping storage")
                return True
            
            dynamodb = self.hub_session.resource('dynamodb')
            table = dynamodb.Table(table_name)
            
            item = {
                'request_id': approval_request.get('request_id', f"req-{int(time.time())}"),
                'task_token': task_token,
                'operation': approval_request.get('operation', 'unknown'),
                'cluster': approval_request.get('cluster', 'unknown'),
                'region': approval_request.get('region', 'unknown'),
                'account': approval_request.get('account', 'unknown'),
                'details': json.dumps(approval_request.get('details', {})),
                'status': 'pending',
                'created_at': datetime.now(timezone.utc).isoformat(),
                'expires_at': datetime.fromtimestamp(
                    time.time() + (APPROVAL_TIMEOUT_MINUTES * 60), 
                    timezone.utc
                ).isoformat(),
                'full_request': json.dumps(approval_request)
            }
            
            table.put_item(Item=item)
            self.logger.info(f"Stored approval request: {item['request_id']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store approval request: {str(e)}")
            return False
    
    def send_approval_request(
        self, 
        approval_request: Dict[str, Any], 
        task_token: str
    ) -> Dict[str, Any]:
        """Send approval request via all configured channels"""
        
        self.logger.info(f"Sending approval request for {approval_request.get('operation', 'unknown')} operation")
        
        results = {
            "slack_sent": False,
            "email_sent": False,
            "stored": False,
            "urls_created": False
        }
        
        try:
            # Create approval URLs
            if APPROVE_URL_BASE:
                urls = self.create_approval_urls(task_token)
                results["urls_created"] = True
                self.logger.info("Created approval URLs")
            else:
                urls = {"approve": "Not configured", "reject": "Not configured"}
                self.logger.warning("Approval URL base not configured")
            
            # Store request for audit
            results["stored"] = self.store_approval_request(approval_request, task_token)
            
            # Send to Slack
            if SLACK_WEBHOOK_URL:
                results["slack_sent"] = self.send_slack_approval(approval_request, task_token, urls)
            
            # Send via email/SNS
            if SNS_TOPIC_ARN:
                results["email_sent"] = self.send_email_approval(approval_request, task_token, urls)
            
            # Log summary
            channels_sent = sum([results["slack_sent"], results["email_sent"]])
            if channels_sent > 0:
                self.logger.info(f"Approval request sent via {channels_sent} channels")
            else:
                self.logger.warning("No approval channels were successful")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to send approval request: {str(e)}")
            raise


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for sending approval requests
    
    Expected event format:
    {
        "taskToken": "STEP_FUNCTIONS_TASK_TOKEN",
        "approval_request": {
            "operation": "drain_node",
            "cluster": "my-cluster",
            "region": "us-east-1", 
            "account": "123456789012",
            "reason": "Node maintenance required",
            "request_id": "req-12345",
            "details": {
                "node": "ip-10-1-1-100.ec2.internal",
                "force": false
            }
        }
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting approval request sender - Request ID: {request_id}")
    
    try:
        # Validate input
        if "taskToken" not in event:
            raise ValueError("Missing required field: taskToken")
        
        if "approval_request" not in event:
            raise ValueError("Missing required field: approval_request")
        
        task_token = event["taskToken"]
        approval_request = event["approval_request"]
        
        # Add request ID if not present
        if "request_id" not in approval_request:
            approval_request["request_id"] = request_id
        
        # Validate approval request structure
        required_fields = ["operation", "cluster", "region", "account"]
        for field in required_fields:
            if field not in approval_request:
                raise ValueError(f"Missing required field in approval_request: {field}")
        
        logger.info(f"Processing approval request for {approval_request['operation']} on {approval_request['cluster']}")
        
        # Create approval request sender and send request
        sender = ApprovalRequestSender(HUB_SESSION)
        results = sender.send_approval_request(approval_request, task_token)
        
        # Prepare response
        response = {
            "ok": True,
            "request_id": request_id,
            "approval_request_id": approval_request["request_id"],
            "channels": results,
            "message": "Approval request sent successfully",
            "expires_in_minutes": APPROVAL_TIMEOUT_MINUTES
        }
        
        logger.info(f"Approval request sent successfully")
        
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
        logger.error(f"Failed to send approval request: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "ok": False,
            "error": "InternalError",
            "message": f"Failed to send approval request: {str(e)}",
            "request_id": request_id
        }


# For local testing
if __name__ == "__main__":
    test_event = {
        "taskToken": "test-task-token-123",
        "approval_request": {
            "operation": "drain_node",
            "cluster": "test-cluster",
            "region": "us-east-1",
            "account": "123456789012",
            "reason": "Node maintenance required for security patching",
            "details": {
                "node": "ip-10-1-1-100.ec2.internal",
                "force": False,
                "estimated_downtime": "5-10 minutes"
            }
        }
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2, default=str))
