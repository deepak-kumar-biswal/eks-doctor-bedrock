"""
EKS Doctor - Approval Callback Lambda Function
Production-grade approval response handler for Step Functions.
"""

import os
import json
import boto3
import logging
import traceback
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
HUB_SESSION = boto3.Session()

# Constants
VALID_ACTIONS = ["approve", "reject"]


class ApprovalCallbackHandler:
    """Main class for handling approval callbacks"""
    
    def __init__(self, hub_session: boto3.Session):
        self.hub_session = hub_session
        self.logger = logger
    
    def validate_token(self, task_token: str) -> bool:
        """Validate task token format"""
        try:
            if not task_token or len(task_token) < 10:
                return False
            
            # Basic format validation
            # Step Functions task tokens are base64-encoded JSON
            import base64
            decoded = base64.b64decode(task_token + '==')  # Add padding
            return True
            
        except Exception:
            return False
    
    def update_approval_record(
        self, 
        request_id: str, 
        action: str, 
        approver_info: Dict[str, Any]
    ) -> bool:
        """Update approval record in DynamoDB"""
        try:
            table_name = os.environ.get("APPROVAL_REQUESTS_TABLE")
            if not table_name:
                self.logger.info("No approval requests table configured - skipping update")
                return True
            
            dynamodb = self.hub_session.resource('dynamodb')
            table = dynamodb.Table(table_name)
            
            update_expression = "SET #status = :status, #processed_at = :processed_at, #approver_info = :approver_info"
            expression_attribute_names = {
                '#status': 'status',
                '#processed_at': 'processed_at',
                '#approver_info': 'approver_info'
            }
            expression_attribute_values = {
                ':status': action,
                ':processed_at': datetime.now(timezone.utc).isoformat(),
                ':approver_info': json.dumps(approver_info)
            }
            
            # Add approval reason if provided
            if 'reason' in approver_info:
                update_expression += ", #approval_reason = :approval_reason"
                expression_attribute_names['#approval_reason'] = 'approval_reason'
                expression_attribute_values[':approval_reason'] = approver_info['reason']
            
            table.update_item(
                Key={'request_id': request_id},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
            
            self.logger.info(f"Updated approval record: {request_id} -> {action}")
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.logger.warning(f"Approval request not found: {request_id}")
            else:
                self.logger.error(f"Failed to update approval record: {e.response['Error']['Message']}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to update approval record: {str(e)}")
            return False
    
    def send_step_functions_response(
        self, 
        task_token: str, 
        action: str, 
        approval_data: Dict[str, Any]
    ) -> bool:
        """Send response back to Step Functions"""
        try:
            stepfunctions = self.hub_session.client('stepfunctions')
            
            if action == "approve":
                # Send success response with approval data
                response_data = {
                    "approved": True,
                    "action": action,
                    "approval_data": approval_data,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                stepfunctions.send_task_success(
                    taskToken=task_token,
                    output=json.dumps(response_data)
                )
                
                self.logger.info("Sent approval success to Step Functions")
                
            else:  # reject
                # Send failure response with rejection reason
                error_data = {
                    "approved": False,
                    "action": action,
                    "reason": approval_data.get("reason", "Request rejected by user"),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                stepfunctions.send_task_failure(
                    taskToken=task_token,
                    error="ApprovalRejected",
                    cause=json.dumps(error_data)
                )
                
                self.logger.info("Sent approval rejection to Step Functions")
            
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidToken':
                self.logger.error("Invalid or expired task token")
            elif error_code == 'TaskDoesNotExist':
                self.logger.error("Task no longer exists (may have timed out)")
            else:
                self.logger.error(f"Step Functions error: {e.response['Error']['Message']}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send Step Functions response: {str(e)}")
            return False
    
    def send_notification(
        self, 
        approval_data: Dict[str, Any], 
        action: str
    ) -> bool:
        """Send notification about approval decision"""
        try:
            sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")
            if not sns_topic_arn:
                self.logger.info("No SNS topic configured - skipping notification")
                return True
            
            operation = approval_data.get("operation", "Unknown")
            cluster = approval_data.get("cluster", "Unknown")
            approver = approval_data.get("approver_email", "Unknown")
            
            if action == "approve":
                subject = f"✅ EKS Doctor Operation Approved: {operation}"
                message = f"""
EKS Doctor operation has been APPROVED:

Operation: {operation}
Cluster: {cluster}
Approver: {approver}
Approved At: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

The operation will now proceed automatically.

---
EKS Doctor Automated System
"""
            else:
                subject = f"❌ EKS Doctor Operation Rejected: {operation}"
                reason = approval_data.get("reason", "No reason provided")
                message = f"""
EKS Doctor operation has been REJECTED:

Operation: {operation}
Cluster: {cluster}
Rejector: {approver}
Reason: {reason}
Rejected At: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

The operation has been cancelled.

---
EKS Doctor Automated System
"""
            
            sns_client = self.hub_session.client('sns')
            response = sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject=subject,
                Message=message
            )
            
            self.logger.info(f"Sent approval notification: {response['MessageId']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {str(e)}")
            return False
    
    def process_approval_callback(
        self, 
        task_token: str, 
        action: str, 
        approver_info: Dict[str, Any],
        approval_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process the approval callback"""
        
        self.logger.info(f"Processing approval callback: {action}")
        
        results = {
            "token_valid": False,
            "record_updated": False,
            "stepfunctions_notified": False,
            "notification_sent": False
        }
        
        try:
            # Validate task token
            if not self.validate_token(task_token):
                raise ValueError("Invalid task token format")
            results["token_valid"] = True
            
            # Update approval record
            request_id = approval_context.get("request_id", f"unknown-{int(datetime.now().timestamp())}")
            results["record_updated"] = self.update_approval_record(
                request_id, action, approver_info
            )
            
            # Prepare approval data for Step Functions
            approval_data = {
                **approval_context,
                "approver_email": approver_info.get("email", "unknown"),
                "approver_ip": approver_info.get("ip_address", "unknown"),
                "approval_timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": approver_info.get("reason", "")
            }
            
            # Send response to Step Functions
            results["stepfunctions_notified"] = self.send_step_functions_response(
                task_token, action, approval_data
            )
            
            # Send notification
            results["notification_sent"] = self.send_notification(approval_data, action)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to process approval callback: {str(e)}")
            raise


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for approval callbacks
    
    Expected event format (API Gateway):
    {
        "queryStringParameters": {
            "token": "STEP_FUNCTIONS_TASK_TOKEN",
            "action": "approve|reject"
        },
        "requestContext": {
            "identity": {
                "sourceIp": "1.2.3.4"
            }
        },
        "body": "{\"reason\": \"Optional reason\", \"email\": \"user@example.com\"}"
    }
    
    Or direct invocation:
    {
        "taskToken": "STEP_FUNCTIONS_TASK_TOKEN",
        "action": "approve|reject",
        "approver_info": {
            "email": "user@example.com",
            "reason": "Optional reason"
        },
        "approval_context": {
            "operation": "drain_node",
            "cluster": "my-cluster",
            "request_id": "req-12345"
        }
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting approval callback handler - Request ID: {request_id}")
    
    try:
        # Handle API Gateway event
        if "queryStringParameters" in event:
            # Extract parameters from API Gateway event
            query_params = event.get("queryStringParameters") or {}
            task_token = query_params.get("token")
            action = query_params.get("action")
            
            # Extract approver info
            request_context = event.get("requestContext", {})
            identity = request_context.get("identity", {})
            
            # Parse body for additional info
            body = event.get("body", "{}")
            try:
                body_data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                body_data = {}
            
            approver_info = {
                "email": body_data.get("email", "api-user@unknown.com"),
                "ip_address": identity.get("sourceIp", "unknown"),
                "user_agent": request_context.get("identity", {}).get("userAgent", "unknown"),
                "reason": body_data.get("reason", "")
            }
            
            approval_context = body_data.get("approval_context", {})
            
        else:
            # Handle direct invocation
            task_token = event.get("taskToken")
            action = event.get("action")
            approver_info = event.get("approver_info", {})
            approval_context = event.get("approval_context", {})
        
        # Validate input
        if not task_token:
            raise ValueError("Missing task token")
        
        if not action or action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action. Must be one of: {VALID_ACTIONS}")
        
        logger.info(f"Processing {action} action for task token")
        
        # Process the callback
        handler = ApprovalCallbackHandler(HUB_SESSION)
        results = handler.process_approval_callback(
            task_token, action, approver_info, approval_context
        )
        
        # Prepare response
        response_data = {
            "ok": True,
            "action": action,
            "request_id": request_id,
            "results": results,
            "message": f"Approval {action} processed successfully"
        }
        
        # API Gateway needs specific response format
        if "queryStringParameters" in event:
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps(response_data)
            }
        
        logger.info(f"Approval {action} processed successfully")
        return response_data
        
    except ValueError as e:
        logger.error(f"Invalid input: {str(e)}")
        error_response = {
            "ok": False,
            "error": "ValidationError",
            "message": str(e),
            "request_id": request_id
        }
        
        # API Gateway error response
        if "queryStringParameters" in event:
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps(error_response)
            }
        
        return error_response
        
    except Exception as e:
        logger.error(f"Failed to process approval callback: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        error_response = {
            "ok": False,
            "error": "InternalError",
            "message": f"Failed to process approval: {str(e)}",
            "request_id": request_id
        }
        
        # API Gateway error response
        if "queryStringParameters" in event:
            return {
                "statusCode": 500,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps(error_response)
            }
        
        return error_response


# For local testing
if __name__ == "__main__":
    # Test direct invocation
    test_event = {
        "taskToken": "test-task-token-123",
        "action": "approve",
        "approver_info": {
            "email": "admin@example.com",
            "reason": "Emergency maintenance approved"
        },
        "approval_context": {
            "operation": "drain_node",
            "cluster": "test-cluster",
            "request_id": "req-12345"
        }
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2, default=str))
