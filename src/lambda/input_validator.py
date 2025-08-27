"""
EKS Doctor - Input Validator Lambda Function
Production-grade input validation for workflow requests.
"""

import os
import json
import logging
import traceback
import re
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
MAX_CLUSTER_NAME_LENGTH = int(os.environ.get('MAX_CLUSTER_NAME_LENGTH', '100'))
ALLOWED_REGIONS = json.loads(os.environ.get('ALLOWED_REGIONS', '["us-east-1", "us-west-2"]'))
ALLOWED_OPERATIONS = json.loads(os.environ.get('ALLOWED_OPERATIONS', '[]'))

# Constants
AWS_ACCOUNT_ID_PATTERN = r'^[0-9]{12}$'
CLUSTER_NAME_PATTERN = r'^[a-zA-Z][a-zA-Z0-9-]{0,99}$'
NODE_NAME_PATTERN = r'^[a-zA-Z0-9][a-zA-Z0-9.-]*$'
NAMESPACE_PATTERN = r'^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
WORKLOAD_NAME_PATTERN = r'^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'

# Valid workload types
VALID_WORKLOAD_TYPES = ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"]

# Valid instance types (subset for validation)
VALID_INSTANCE_FAMILIES = [
    "t2", "t3", "t3a", "t4g",
    "m5", "m5a", "m5ad", "m5d", "m5dn", "m5n", "m5zn", "m6a", "m6i", "m6id", "m6idn", "m6in",
    "c5", "c5a", "c5ad", "c5d", "c5n", "c6a", "c6i", "c6id", "c6in",
    "r5", "r5a", "r5ad", "r5b", "r5d", "r5dn", "r5n", "r6a", "r6i", "r6id", "r6idn", "r6in",
    "x1", "x1e", "x2gd", "x2idn", "x2iedn", "x2iezn",
    "i3", "i3en", "i4i",
    "d2", "d3", "d3en",
    "h1",
    "z1d"
]


class InputValidationError(Exception):
    """Custom exception for input validation errors"""
    pass


class InputValidator:
    """Main class for input validation"""
    
    def __init__(self):
        self.logger = logger
    
    def validate_required_fields(self, data: Dict[str, Any], required_fields: List[str]) -> None:
        """Validate that all required fields are present"""
        missing_fields = []
        
        for field in required_fields:
            if field not in data or data[field] is None:
                missing_fields.append(field)
            elif isinstance(data[field], str) and not data[field].strip():
                missing_fields.append(field)
        
        if missing_fields:
            raise InputValidationError(f"Missing required fields: {', '.join(missing_fields)}")
    
    def validate_aws_account_id(self, account_id: str) -> None:
        """Validate AWS account ID format"""
        if not isinstance(account_id, str):
            raise InputValidationError("Account ID must be a string")
        
        if not re.match(AWS_ACCOUNT_ID_PATTERN, account_id):
            raise InputValidationError("Account ID must be a 12-digit number")
    
    def validate_aws_region(self, region: str) -> None:
        """Validate AWS region"""
        if not isinstance(region, str):
            raise InputValidationError("Region must be a string")
        
        if region not in ALLOWED_REGIONS:
            raise InputValidationError(f"Region must be one of: {', '.join(ALLOWED_REGIONS)}")
    
    def validate_cluster_name(self, cluster_name: str) -> None:
        """Validate EKS cluster name"""
        if not isinstance(cluster_name, str):
            raise InputValidationError("Cluster name must be a string")
        
        if len(cluster_name) > MAX_CLUSTER_NAME_LENGTH:
            raise InputValidationError(f"Cluster name exceeds maximum length of {MAX_CLUSTER_NAME_LENGTH}")
        
        if not re.match(CLUSTER_NAME_PATTERN, cluster_name):
            raise InputValidationError("Cluster name must start with a letter and contain only letters, numbers, and hyphens")
    
    def validate_operation(self, operation: str) -> None:
        """Validate operation type"""
        if not isinstance(operation, str):
            raise InputValidationError("Operation must be a string")
        
        if operation not in ALLOWED_OPERATIONS:
            raise InputValidationError(f"Operation must be one of: {', '.join(ALLOWED_OPERATIONS)}")
    
    def validate_node_name(self, node_name: str) -> None:
        """Validate Kubernetes node name"""
        if not isinstance(node_name, str):
            raise InputValidationError("Node name must be a string")
        
        if not re.match(NODE_NAME_PATTERN, node_name):
            raise InputValidationError("Invalid node name format")
        
        if len(node_name) > 253:
            raise InputValidationError("Node name exceeds maximum length of 253 characters")
    
    def validate_namespace(self, namespace: str) -> None:
        """Validate Kubernetes namespace"""
        if not isinstance(namespace, str):
            raise InputValidationError("Namespace must be a string")
        
        if namespace == "":
            return  # Empty namespace defaults to "default"
        
        if len(namespace) > 63:
            raise InputValidationError("Namespace exceeds maximum length of 63 characters")
        
        if not re.match(NAMESPACE_PATTERN, namespace):
            raise InputValidationError("Invalid namespace format")
    
    def validate_workload_name(self, workload_name: str) -> None:
        """Validate Kubernetes workload name"""
        if not isinstance(workload_name, str):
            raise InputValidationError("Workload name must be a string")
        
        if len(workload_name) > 63:
            raise InputValidationError("Workload name exceeds maximum length of 63 characters")
        
        if not re.match(WORKLOAD_NAME_PATTERN, workload_name):
            raise InputValidationError("Invalid workload name format")
    
    def validate_workload_type(self, workload_type: str) -> None:
        """Validate Kubernetes workload type"""
        if not isinstance(workload_type, str):
            raise InputValidationError("Workload type must be a string")
        
        if workload_type not in VALID_WORKLOAD_TYPES:
            raise InputValidationError(f"Workload type must be one of: {', '.join(VALID_WORKLOAD_TYPES)}")
    
    def validate_instance_type(self, instance_type: str) -> None:
        """Validate EC2 instance type"""
        if not isinstance(instance_type, str):
            raise InputValidationError("Instance type must be a string")
        
        # Parse instance type (e.g., m5.large -> family=m5, size=large)
        parts = instance_type.split('.')
        if len(parts) != 2:
            raise InputValidationError("Invalid instance type format")
        
        family, size = parts
        
        # Validate family
        if family not in VALID_INSTANCE_FAMILIES:
            raise InputValidationError(f"Unsupported instance family: {family}")
        
        # Validate size (basic check)
        valid_sizes = ["nano", "micro", "small", "medium", "large", "xlarge"]
        valid_sizes.extend([f"{i}xlarge" for i in range(2, 25)])  # 2xlarge to 24xlarge
        
        if size not in valid_sizes:
            raise InputValidationError(f"Invalid instance size: {size}")
    
    def validate_positive_integer(self, value: Union[int, str], field_name: str, min_value: int = 1, max_value: int = None) -> int:
        """Validate positive integer with optional bounds"""
        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise InputValidationError(f"{field_name} must be an integer")
        
        if int_value < min_value:
            raise InputValidationError(f"{field_name} must be at least {min_value}")
        
        if max_value is not None and int_value > max_value:
            raise InputValidationError(f"{field_name} must be at most {max_value}")
        
        return int_value
    
    def validate_boolean(self, value: Any, field_name: str) -> bool:
        """Validate boolean value"""
        if isinstance(value, bool):
            return value
        
        if isinstance(value, str):
            if value.lower() in ('true', '1', 'yes', 'on'):
                return True
            elif value.lower() in ('false', '0', 'no', 'off'):
                return False
        
        raise InputValidationError(f"{field_name} must be a boolean value")
    
    def validate_drain_node_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Validate details for drain_node operation"""
        self.validate_required_fields(details, ["node"])
        
        validated_details = {}
        
        # Validate node name
        self.validate_node_name(details["node"])
        validated_details["node"] = details["node"].strip()
        
        # Validate optional force parameter
        if "force" in details:
            validated_details["force"] = self.validate_boolean(details["force"], "force")
        else:
            validated_details["force"] = False
        
        # Validate optional timeout
        if "timeout" in details:
            validated_details["timeout"] = self.validate_positive_integer(
                details["timeout"], "timeout", min_value=60, max_value=3600
            )
        else:
            validated_details["timeout"] = 300  # Default 5 minutes
        
        # Validate optional grace period
        if "grace_period" in details:
            validated_details["grace_period"] = self.validate_positive_integer(
                details["grace_period"], "grace_period", min_value=0, max_value=300
            )
        else:
            validated_details["grace_period"] = 30
        
        return validated_details
    
    def validate_scale_nodegroup_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Validate details for scale_nodegroup operation"""
        self.validate_required_fields(details, ["nodegroup", "desired_size"])
        
        validated_details = {}
        
        # Validate nodegroup name
        if not isinstance(details["nodegroup"], str) or not details["nodegroup"].strip():
            raise InputValidationError("NodeGroup name must be a non-empty string")
        validated_details["nodegroup"] = details["nodegroup"].strip()
        
        # Validate desired size
        validated_details["desired_size"] = self.validate_positive_integer(
            details["desired_size"], "desired_size", min_value=0, max_value=1000
        )
        
        # Validate optional current size (for verification)
        if "current_size" in details:
            validated_details["current_size"] = self.validate_positive_integer(
                details["current_size"], "current_size", min_value=0, max_value=1000
            )
        
        # Validate optional instance types
        if "instance_types" in details:
            if not isinstance(details["instance_types"], list):
                raise InputValidationError("Instance types must be a list")
            
            validated_instance_types = []
            for instance_type in details["instance_types"]:
                self.validate_instance_type(instance_type)
                validated_instance_types.append(instance_type)
            
            validated_details["instance_types"] = validated_instance_types
        
        return validated_details
    
    def validate_restart_workload_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Validate details for restart_workload operation"""
        self.validate_required_fields(details, ["workload", "workload_type"])
        
        validated_details = {}
        
        # Validate workload name
        self.validate_workload_name(details["workload"])
        validated_details["workload"] = details["workload"].strip()
        
        # Validate workload type
        self.validate_workload_type(details["workload_type"])
        validated_details["workload_type"] = details["workload_type"]
        
        # Validate optional namespace
        namespace = details.get("namespace", "default")
        self.validate_namespace(namespace)
        validated_details["namespace"] = namespace or "default"
        
        # Validate optional strategy
        strategy = details.get("strategy", "rolling")
        if strategy not in ["rolling", "recreate"]:
            raise InputValidationError("Strategy must be 'rolling' or 'recreate'")
        validated_details["strategy"] = strategy
        
        return validated_details
    
    def validate_health_snapshot_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Validate details for health_snapshot operation"""
        validated_details = details.copy() if details else {}
        
        # Validate optional include_pods flag
        if "include_pods" in details:
            validated_details["include_pods"] = self.validate_boolean(details["include_pods"], "include_pods")
        else:
            validated_details["include_pods"] = True
        
        # Validate optional include_events flag
        if "include_events" in details:
            validated_details["include_events"] = self.validate_boolean(details["include_events"], "include_events")
        else:
            validated_details["include_events"] = True
        
        # Validate optional namespace filter
        if "namespace" in details:
            self.validate_namespace(details["namespace"])
            validated_details["namespace"] = details["namespace"]
        
        return validated_details
    
    def validate_network_triage_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Validate details for network_triage operation"""
        validated_details = details.copy() if details else {}
        
        # Validate optional check_connectivity flag
        if "check_connectivity" in details:
            validated_details["check_connectivity"] = self.validate_boolean(details["check_connectivity"], "check_connectivity")
        else:
            validated_details["check_connectivity"] = True
        
        # Validate optional target_service
        if "target_service" in details:
            if not isinstance(details["target_service"], str):
                raise InputValidationError("Target service must be a string")
            validated_details["target_service"] = details["target_service"].strip()
        
        return validated_details
    
    def validate_input(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main validation method"""
        self.logger.info("Starting input validation")
        
        try:
            # Validate required top-level fields
            self.validate_required_fields(event_data, ["operation", "cluster", "region", "account"])
            
            validated_data = {}
            
            # Validate operation
            self.validate_operation(event_data["operation"])
            validated_data["operation"] = event_data["operation"]
            
            # Validate cluster name
            self.validate_cluster_name(event_data["cluster"])
            validated_data["cluster"] = event_data["cluster"].strip()
            
            # Validate region
            self.validate_aws_region(event_data["region"])
            validated_data["region"] = event_data["region"]
            
            # Validate account ID
            self.validate_aws_account_id(event_data["account"])
            validated_data["account"] = event_data["account"]
            
            # Validate operation-specific details
            details = event_data.get("details", {})
            if not isinstance(details, dict):
                raise InputValidationError("Details must be a dictionary")
            
            operation = validated_data["operation"]
            
            if operation == "drain_node":
                validated_data["details"] = self.validate_drain_node_details(details)
            elif operation == "scale_nodegroup":
                validated_data["details"] = self.validate_scale_nodegroup_details(details)
            elif operation == "restart_workload":
                validated_data["details"] = self.validate_restart_workload_details(details)
            elif operation == "health_snapshot":
                validated_data["details"] = self.validate_health_snapshot_details(details)
            elif operation == "network_triage":
                validated_data["details"] = self.validate_network_triage_details(details)
            else:
                validated_data["details"] = details
            
            # Add metadata
            validated_data["validation_timestamp"] = datetime.utcnow().isoformat()
            validated_data["validator_version"] = "1.0.0"
            
            self.logger.info(f"Input validation successful for operation: {operation}")
            
            return validated_data
            
        except InputValidationError as e:
            self.logger.error(f"Input validation failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during validation: {str(e)}")
            raise InputValidationError(f"Validation failed: {str(e)}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for input validation
    
    Expected event format:
    {
        "operation": "drain_node|scale_nodegroup|restart_workload|health_snapshot|network_triage",
        "cluster": "cluster-name",
        "region": "us-east-1",
        "account": "123456789012",
        "details": {
            # Operation-specific details
        }
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting input validation - Request ID: {request_id}")
    
    try:
        # Validate input
        validator = InputValidator()
        validated_data = validator.validate_input(event)
        
        response = {
            "statusCode": 200,
            "ok": True,
            "validated_data": validated_data,
            "message": "Input validation successful",
            "request_id": request_id
        }
        
        logger.info("Input validation completed successfully")
        
        return response
        
    except InputValidationError as e:
        logger.error(f"Input validation failed: {str(e)}")
        
        return {
            "statusCode": 400,
            "ok": False,
            "error": "ValidationError",
            "message": str(e),
            "request_id": request_id
        }
        
    except Exception as e:
        logger.error(f"Input validation error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "statusCode": 500,
            "ok": False,
            "error": "InternalError",
            "message": f"Input validation failed: {str(e)}",
            "request_id": request_id
        }


# For local testing
if __name__ == "__main__":
    # Test cases
    test_events = [
        {
            "operation": "drain_node",
            "cluster": "test-cluster",
            "region": "us-east-1",
            "account": "123456789012",
            "details": {
                "node": "ip-10-1-1-100.ec2.internal",
                "force": False,
                "timeout": 300
            }
        },
        {
            "operation": "scale_nodegroup",
            "cluster": "prod-cluster",
            "region": "us-west-2",
            "account": "123456789012",
            "details": {
                "nodegroup": "primary-ng",
                "desired_size": 5,
                "current_size": 3
            }
        },
        {
            "operation": "restart_workload",
            "cluster": "staging-cluster",
            "region": "us-east-1",
            "account": "123456789012",
            "details": {
                "workload": "frontend-app",
                "workload_type": "Deployment",
                "namespace": "production"
            }
        }
    ]
    
    class MockContext:
        aws_request_id = "test-request-123"
    
    for i, test_event in enumerate(test_events, 1):
        print(f"\n=== Test Case {i} ===")
        result = lambda_handler(test_event, MockContext())
        print(json.dumps(result, indent=2, default=str))
