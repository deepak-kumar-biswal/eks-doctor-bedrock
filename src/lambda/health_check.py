"""
EKS Doctor - Health Check Lambda Function
Production-grade health check for API Gateway endpoints.
"""

import os
import json
import logging
import time
from typing import Dict, Any
from datetime import datetime, timezone

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
API_VERSION = os.environ.get("API_VERSION", "1.0.0")

# Health check data
HEALTH_CHECK_DATA = {
    "service": "eks-doctor-approval-api",
    "version": API_VERSION,
    "status": "healthy",
    "environment": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "local").split("-")[-2] if "-" in os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "") else "unknown"
}


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for health check endpoint
    
    Returns basic health information about the API
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Health check requested - Request ID: {request_id}")
    
    try:
        # Basic health check
        start_time = time.time()
        
        # Perform basic checks
        checks = {
            "lambda_function": "ok",
            "environment_variables": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_check": "ok"
        }
        
        # Check environment variables
        required_env_vars = ["AWS_REGION", "AWS_LAMBDA_FUNCTION_NAME"]
        missing_vars = []
        
        for var in required_env_vars:
            if not os.environ.get(var):
                missing_vars.append(var)
        
        if missing_vars:
            checks["environment_variables"] = f"missing: {', '.join(missing_vars)}"
            HEALTH_CHECK_DATA["status"] = "degraded"
        
        # Calculate response time
        response_time_ms = round((time.time() - start_time) * 1000, 2)
        
        # Build response
        response_data = {
            **HEALTH_CHECK_DATA,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "response_time_ms": response_time_ms,
            "checks": checks,
            "region": os.environ.get("AWS_REGION", "unknown"),
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown")
        }
        
        # Determine overall status
        if all(check == "ok" for check in checks.values() if isinstance(check, str)):
            response_data["status"] = "healthy"
            status_code = 200
        else:
            response_data["status"] = "degraded"
            status_code = 200  # Still return 200 for partial health
        
        logger.info(f"Health check completed - Status: {response_data['status']}")
        
        return {
            "statusCode": status_code,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-cache",
                "X-API-Version": API_VERSION
            },
            "body": json.dumps(response_data)
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        
        error_response = {
            **HEALTH_CHECK_DATA,
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "error": str(e)
        }
        
        return {
            "statusCode": 503,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-cache"
            },
            "body": json.dumps(error_response)
        }


# For local testing
if __name__ == "__main__":
    class MockContext:
        aws_request_id = "test-request-123"
    
    result = lambda_handler({}, MockContext())
    print(f"Status Code: {result['statusCode']}")
    print("Response:", json.dumps(json.loads(result['body']), indent=2))
