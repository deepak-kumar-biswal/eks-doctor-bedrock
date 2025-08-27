"""
EKS Doctor - Approval Status Lambda Function
Production-grade approval status checker for tracking requests.
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
APPROVAL_REQUESTS_TABLE = os.environ.get("APPROVAL_REQUESTS_TABLE")

# Constants
VALID_STATUSES = ["pending", "approved", "rejected", "expired", "cancelled"]


class ApprovalStatusChecker:
    """Main class for checking approval status"""
    
    def __init__(self, hub_session: boto3.Session):
        self.hub_session = hub_session
        self.logger = logger
        self.dynamodb = hub_session.resource('dynamodb')
        
        if APPROVAL_REQUESTS_TABLE:
            self.table = self.dynamodb.Table(APPROVAL_REQUESTS_TABLE)
        else:
            self.table = None
            logger.warning("No approval requests table configured")
    
    def get_approval_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get approval request status from DynamoDB"""
        try:
            if not self.table:
                return None
            
            response = self.table.get_item(
                Key={'request_id': request_id}
            )
            
            if 'Item' not in response:
                self.logger.warning(f"Approval request not found: {request_id}")
                return None
            
            item = response['Item']
            
            # Parse the approval request data
            approval_data = {
                "request_id": item["request_id"],
                "operation": item.get("operation", "unknown"),
                "cluster": item.get("cluster", "unknown"),
                "region": item.get("region", "unknown"),
                "account": item.get("account", "unknown"),
                "status": item.get("status", "unknown"),
                "created_at": item.get("created_at"),
                "processed_at": item.get("processed_at"),
                "expires_at": item.get("expires_at"),
                "approver_info": json.loads(item.get("approver_info", "{}")) if item.get("approver_info") else None,
                "approval_reason": item.get("approval_reason"),
            }
            
            # Parse details if available
            if "details" in item:
                try:
                    approval_data["details"] = json.loads(item["details"])
                except (json.JSONDecodeError, TypeError):
                    approval_data["details"] = item["details"]
            
            # Parse full request if available
            if "full_request" in item:
                try:
                    approval_data["full_request"] = json.loads(item["full_request"])
                except (json.JSONDecodeError, TypeError):
                    approval_data["full_request"] = item["full_request"]
            
            # Add computed fields
            approval_data["is_expired"] = self.is_expired(item.get("expires_at"))
            approval_data["time_remaining"] = self.get_time_remaining(item.get("expires_at"))
            
            return approval_data
            
        except ClientError as e:
            self.logger.error(f"Failed to get approval status: {e.response['Error']['Message']}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to get approval status: {str(e)}")
            return None
    
    def is_expired(self, expires_at: Optional[str]) -> bool:
        """Check if the approval request has expired"""
        if not expires_at:
            return False
        
        try:
            expiry_time = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            current_time = datetime.now(timezone.utc)
            return current_time > expiry_time
        except (ValueError, TypeError):
            return False
    
    def get_time_remaining(self, expires_at: Optional[str]) -> Optional[str]:
        """Get human-readable time remaining until expiry"""
        if not expires_at:
            return None
        
        try:
            expiry_time = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            current_time = datetime.now(timezone.utc)
            
            if current_time > expiry_time:
                return "Expired"
            
            time_diff = expiry_time - current_time
            total_seconds = int(time_diff.total_seconds())
            
            if total_seconds < 60:
                return f"{total_seconds} seconds"
            elif total_seconds < 3600:
                minutes = total_seconds // 60
                return f"{minutes} minutes"
            else:
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                if minutes > 0:
                    return f"{hours} hours, {minutes} minutes"
                else:
                    return f"{hours} hours"
                    
        except (ValueError, TypeError):
            return None
    
    def list_approval_requests(
        self, 
        status_filter: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List approval requests with optional status filter"""
        try:
            if not self.table:
                return []
            
            if status_filter and status_filter in VALID_STATUSES:
                # Query using GSI for status
                response = self.table.query(
                    IndexName='StatusIndex',
                    KeyConditionExpression='#status = :status',
                    ExpressionAttributeNames={
                        '#status': 'status'
                    },
                    ExpressionAttributeValues={
                        ':status': status_filter
                    },
                    ScanIndexForward=False,  # Sort by created_at descending
                    Limit=limit
                )
            else:
                # Scan all items
                response = self.table.scan(
                    Limit=limit
                )
            
            items = []
            for item in response.get('Items', []):
                approval_data = {
                    "request_id": item["request_id"],
                    "operation": item.get("operation", "unknown"),
                    "cluster": item.get("cluster", "unknown"),
                    "status": item.get("status", "unknown"),
                    "created_at": item.get("created_at"),
                    "processed_at": item.get("processed_at"),
                    "is_expired": self.is_expired(item.get("expires_at")),
                    "time_remaining": self.get_time_remaining(item.get("expires_at"))
                }
                items.append(approval_data)
            
            # Sort by created_at if not using index
            if not status_filter:
                items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            
            return items
            
        except Exception as e:
            self.logger.error(f"Failed to list approval requests: {str(e)}")
            return []
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get summary statistics of approval requests"""
        try:
            if not self.table:
                return {"error": "No approval requests table configured"}
            
            summary = {
                "total_requests": 0,
                "by_status": {status: 0 for status in VALID_STATUSES},
                "by_operation": {},
                "recent_activity": []
            }
            
            # Scan table for summary (in production, consider using metrics instead)
            response = self.table.scan()
            
            for item in response.get('Items', []):
                summary["total_requests"] += 1
                
                status = item.get("status", "unknown")
                if status in summary["by_status"]:
                    summary["by_status"][status] += 1
                
                operation = item.get("operation", "unknown")
                if operation not in summary["by_operation"]:
                    summary["by_operation"][operation] = 0
                summary["by_operation"][operation] += 1
                
                # Collect recent activity (last 10 items)
                if len(summary["recent_activity"]) < 10:
                    summary["recent_activity"].append({
                        "request_id": item["request_id"],
                        "operation": operation,
                        "status": status,
                        "created_at": item.get("created_at")
                    })
            
            # Sort recent activity by created_at
            summary["recent_activity"].sort(
                key=lambda x: x.get("created_at", ""), 
                reverse=True
            )
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to get status summary: {str(e)}")
            return {"error": str(e)}


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for approval status checking
    
    Expected query parameters:
    - request_id: Specific request ID to check
    - status: Filter by status (optional)
    - action: "list" to list requests, "summary" for statistics
    - limit: Number of items to return (default 50)
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting approval status check - Request ID: {request_id}")
    
    try:
        # Extract query parameters from API Gateway event
        query_params = event.get("queryStringParameters") or {}
        
        # Handle different actions
        action = query_params.get("action", "get")
        
        # Create status checker
        checker = ApprovalStatusChecker(HUB_SESSION)
        
        if action == "get":
            # Get specific approval request status
            approval_request_id = query_params.get("request_id")
            if not approval_request_id:
                return {
                    "statusCode": 400,
                    "headers": {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*"
                    },
                    "body": json.dumps({
                        "ok": False,
                        "error": "ValidationError",
                        "message": "request_id parameter is required"
                    })
                }
            
            approval_data = checker.get_approval_status(approval_request_id)
            if not approval_data:
                return {
                    "statusCode": 404,
                    "headers": {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*"
                    },
                    "body": json.dumps({
                        "ok": False,
                        "error": "NotFound",
                        "message": f"Approval request not found: {approval_request_id}"
                    })
                }
            
            response_data = {
                "ok": True,
                "approval_data": approval_data,
                "request_id": request_id
            }
            
        elif action == "list":
            # List approval requests
            status_filter = query_params.get("status")
            limit = int(query_params.get("limit", "50"))
            
            if limit > 100:
                limit = 100  # Cap at 100 items
            
            approval_requests = checker.list_approval_requests(status_filter, limit)
            
            response_data = {
                "ok": True,
                "approval_requests": approval_requests,
                "count": len(approval_requests),
                "status_filter": status_filter,
                "request_id": request_id
            }
            
        elif action == "summary":
            # Get summary statistics
            summary = checker.get_status_summary()
            
            response_data = {
                "ok": True,
                "summary": summary,
                "request_id": request_id
            }
            
        else:
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({
                    "ok": False,
                    "error": "ValidationError",
                    "message": f"Invalid action: {action}. Must be 'get', 'list', or 'summary'"
                })
            }
        
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps(response_data, default=str)
        }
        
    except Exception as e:
        logger.error(f"Failed to check approval status: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({
                "ok": False,
                "error": "InternalError",
                "message": f"Failed to check approval status: {str(e)}",
                "request_id": request_id
            })
        }


# For local testing
if __name__ == "__main__":
    # Test cases
    test_events = [
        {
            "queryStringParameters": {
                "request_id": "req-12345",
                "action": "get"
            }
        },
        {
            "queryStringParameters": {
                "action": "list",
                "status": "pending",
                "limit": "10"
            }
        },
        {
            "queryStringParameters": {
                "action": "summary"
            }
        }
    ]
    
    class MockContext:
        aws_request_id = "test-request-123"
    
    for i, test_event in enumerate(test_events, 1):
        print(f"\n=== Test Case {i} ===")
        result = lambda_handler(test_event, MockContext())
        print(f"Status Code: {result['statusCode']}")
        print("Response:", json.dumps(json.loads(result['body']), indent=2, default=str))
