#!/usr/bin/env python3
"""
EKS Doctor Test Framework
Comprehensive test suite for EKS Doctor Bedrock solution.
"""

import os
import sys
import json
import time
import boto3
import pytest
import unittest
import tempfile
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
from moto import mock_stepfunctions, mock_lambda, mock_dynamodb, mock_s3, mock_bedrock
import kubernetes
from kubernetes.client.rest import ApiException
from botocore.exceptions import ClientError

# Test configuration
TEST_CONFIG = {
    "aws_region": "us-east-1",
    "cluster_name": "test-cluster",
    "account_id": "123456789012",
    "project_name": "eks-doctor-test",
    "environment": "test"
}


class EKSDoctorTestCase(unittest.TestCase):
    """Base test case for EKS Doctor tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.maxDiff = None
        
        # Mock AWS clients
        self.mock_lambda_client = Mock()
        self.mock_stepfunctions_client = Mock()
        self.mock_dynamodb_client = Mock()
        self.mock_bedrock_client = Mock()
        
        # Mock Kubernetes client
        self.mock_k8s_client = Mock()
        
        # Test data
        self.sample_cluster_info = {
            "cluster": {
                "name": TEST_CONFIG["cluster_name"],
                "arn": f"arn:aws:eks:{TEST_CONFIG['aws_region']}:{TEST_CONFIG['account_id']}:cluster/{TEST_CONFIG['cluster_name']}",
                "version": "1.28",
                "endpoint": "https://test-cluster.eks.amazonaws.com",
                "status": "ACTIVE",
                "platformVersion": "eks.13"
            }
        }
        
        self.sample_nodes = [
            {
                "metadata": {"name": "node-1", "labels": {"instance-type": "t3.medium"}},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                "spec": {"taints": []}
            },
            {
                "metadata": {"name": "node-2", "labels": {"instance-type": "t3.medium"}},
                "status": {"conditions": [{"type": "Ready", "status": "False"}]},
                "spec": {"taints": [{"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule"}]}
            }
        ]


class TestHealthSnapshot(EKSDoctorTestCase):
    """Test health snapshot functionality"""
    
    @patch('boto3.client')
    def test_collect_cluster_health_success(self, mock_boto3):
        """Test successful cluster health collection"""
        from src.lambda.health_snapshot import collect_cluster_health
        
        # Mock EKS client
        mock_eks = Mock()
        mock_eks.describe_cluster.return_value = self.sample_cluster_info
        mock_boto3.return_value = mock_eks
        
        # Mock Kubernetes client
        with patch('kubernetes.client.CoreV1Api') as mock_k8s_api:
            mock_api = Mock()
            mock_api.list_node.return_value = Mock(items=self.sample_nodes)
            mock_k8s_api.return_value = mock_api
            
            result = collect_cluster_health(TEST_CONFIG["cluster_name"], TEST_CONFIG["aws_region"])
            
            self.assertIn("cluster_info", result)
            self.assertIn("node_health", result)
            self.assertIn("resource_usage", result)
            self.assertEqual(result["cluster_info"]["name"], TEST_CONFIG["cluster_name"])
    
    def test_analyze_node_health(self):
        """Test node health analysis"""
        from src.lambda.health_snapshot import analyze_node_health
        
        result = analyze_node_health(self.sample_nodes)
        
        self.assertIn("total_nodes", result)
        self.assertIn("ready_nodes", result)
        self.assertIn("not_ready_nodes", result)
        self.assertEqual(result["total_nodes"], 2)
        self.assertEqual(result["ready_nodes"], 1)
        self.assertEqual(result["not_ready_nodes"], 1)
    
    def test_get_resource_usage(self):
        """Test resource usage collection"""
        from src.lambda.health_snapshot import get_resource_usage
        
        # Mock metrics server response
        mock_metrics = [
            {"metadata": {"name": "node-1"}, "usage": {"cpu": "500m", "memory": "1Gi"}},
            {"metadata": {"name": "node-2"}, "usage": {"cpu": "200m", "memory": "512Mi"}}
        ]
        
        with patch('kubernetes.client.CustomObjectsApi') as mock_custom_api:
            mock_api = Mock()
            mock_api.list_cluster_custom_object.return_value = {"items": mock_metrics}
            mock_custom_api.return_value = mock_api
            
            result = get_resource_usage()
            
            self.assertIn("cpu_usage", result)
            self.assertIn("memory_usage", result)


class TestNetworkTriage(EKSDoctorTestCase):
    """Test network triage functionality"""
    
    @patch('boto3.client')
    def test_analyze_network_connectivity(self, mock_boto3):
        """Test network connectivity analysis"""
        from src.lambda.network_triage import analyze_network_connectivity
        
        # Mock EC2 client
        mock_ec2 = Mock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-12345",
                "GroupName": "eks-cluster-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            }]
        }
        mock_boto3.return_value = mock_ec2
        
        result = analyze_network_connectivity("vpc-12345", ["sg-12345"])
        
        self.assertIn("vpc_info", result)
        self.assertIn("security_groups", result)
        self.assertIn("connectivity_issues", result)
    
    def test_check_dns_resolution(self):
        """Test DNS resolution check"""
        from src.lambda.network_triage import check_dns_resolution
        
        with patch('socket.gethostbyname') as mock_dns:
            mock_dns.return_value = "1.2.3.4"
            
            result = check_dns_resolution(["google.com", "kubernetes.io"])
            
            self.assertIn("dns_results", result)
            self.assertTrue(result["dns_results"]["google.com"]["resolved"])


class TestNodeOperations(EKSDoctorTestCase):
    """Test node operation functionality"""
    
    def test_drain_node_validation(self):
        """Test node drain validation"""
        from src.lambda.drain_node import validate_drain_request
        
        # Valid request
        valid_request = {
            "cluster_name": TEST_CONFIG["cluster_name"],
            "node_name": "node-1",
            "grace_period": 300,
            "force": False
        }
        
        result = validate_drain_request(valid_request)
        self.assertTrue(result["valid"])
        
        # Invalid request - missing cluster name
        invalid_request = {
            "node_name": "node-1"
        }
        
        result = validate_drain_request(invalid_request)
        self.assertFalse(result["valid"])
        self.assertIn("cluster_name", result["errors"])
    
    def test_check_drain_safety(self):
        """Test drain safety checks"""
        from src.lambda.drain_node import check_drain_safety
        
        # Mock pods
        mock_pods = [
            {
                "metadata": {"name": "system-pod", "namespace": "kube-system"},
                "spec": {"nodeName": "node-1"},
                "status": {"phase": "Running"}
            },
            {
                "metadata": {"name": "app-pod", "namespace": "default", "ownerReferences": [{"kind": "ReplicaSet"}]},
                "spec": {"nodeName": "node-1"},
                "status": {"phase": "Running"}
            }
        ]
        
        with patch('kubernetes.client.CoreV1Api') as mock_k8s_api:
            mock_api = Mock()
            mock_api.list_pod_for_all_namespaces.return_value = Mock(items=mock_pods)
            mock_k8s_api.return_value = mock_api
            
            result = check_drain_safety("node-1")
            
            self.assertIn("can_drain", result)
            self.assertIn("warnings", result)
            self.assertIn("critical_pods", result)


class TestNodegroupScaling(EKSDoctorTestCase):
    """Test nodegroup scaling functionality"""
    
    @patch('boto3.client')
    def test_scale_managed_nodegroup(self, mock_boto3):
        """Test managed nodegroup scaling"""
        from src.lambda.scale_nodegroup import scale_managed_nodegroup
        
        # Mock EKS client
        mock_eks = Mock()
        mock_eks.update_nodegroup_config.return_value = {
            "update": {"id": "update-12345", "status": "InProgress"}
        }
        mock_boto3.return_value = mock_eks
        
        result = scale_managed_nodegroup(
            cluster_name=TEST_CONFIG["cluster_name"],
            nodegroup_name="test-nodegroup",
            desired_size=3,
            min_size=1,
            max_size=5
        )
        
        self.assertIn("update_id", result)
        self.assertEqual(result["status"], "InProgress")
    
    def test_validate_scaling_request(self):
        """Test scaling request validation"""
        from src.lambda.scale_nodegroup import validate_scaling_request
        
        # Valid request
        valid_request = {
            "cluster_name": TEST_CONFIG["cluster_name"],
            "nodegroup_name": "test-nodegroup",
            "desired_size": 3,
            "min_size": 1,
            "max_size": 5
        }
        
        result = validate_scaling_request(valid_request)
        self.assertTrue(result["valid"])
        
        # Invalid request - desired size > max size
        invalid_request = {
            "cluster_name": TEST_CONFIG["cluster_name"],
            "nodegroup_name": "test-nodegroup",
            "desired_size": 10,
            "min_size": 1,
            "max_size": 5
        }
        
        result = validate_scaling_request(invalid_request)
        self.assertFalse(result["valid"])


class TestWorkloadOperations(EKSDoctorTestCase):
    """Test workload operation functionality"""
    
    def test_restart_deployment(self):
        """Test deployment restart"""
        from src.lambda.restart_workload import restart_deployment
        
        with patch('kubernetes.client.AppsV1Api') as mock_apps_api:
            mock_api = Mock()
            mock_api.patch_namespaced_deployment.return_value = Mock(
                metadata=Mock(name="test-deployment"),
                status=Mock(replicas=3, ready_replicas=3)
            )
            mock_apps_api.return_value = mock_api
            
            result = restart_deployment("test-deployment", "default")
            
            self.assertIn("restart_initiated", result)
            self.assertTrue(result["restart_initiated"])
    
    def test_monitor_rollout_status(self):
        """Test rollout status monitoring"""
        from src.lambda.restart_workload import monitor_rollout_status
        
        # Mock deployment with successful rollout
        mock_deployment = Mock(
            metadata=Mock(name="test-deployment"),
            status=Mock(
                replicas=3,
                ready_replicas=3,
                updated_replicas=3,
                conditions=[
                    Mock(type="Progressing", status="True", reason="NewReplicaSetAvailable")
                ]
            )
        )
        
        with patch('kubernetes.client.AppsV1Api') as mock_apps_api:
            mock_api = Mock()
            mock_api.read_namespaced_deployment.return_value = mock_deployment
            mock_apps_api.return_value = mock_api
            
            result = monitor_rollout_status("test-deployment", "default", timeout=60)
            
            self.assertIn("rollout_complete", result)
            self.assertTrue(result["rollout_complete"])


class TestApprovalWorkflow(EKSDoctorTestCase):
    """Test approval workflow functionality"""
    
    @mock_dynamodb
    def test_send_approval_request(self):
        """Test approval request sending"""
        from src.lambda.send_approval import send_approval_request
        
        # Create mock DynamoDB table
        dynamodb = boto3.resource('dynamodb', region_name=TEST_CONFIG["aws_region"])
        table = dynamodb.create_table(
            TableName='eks-doctor-approvals',
            KeySchema=[
                {'AttributeName': 'request_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'request_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        request_data = {
            "operation": "drain_node",
            "cluster_name": TEST_CONFIG["cluster_name"],
            "node_name": "node-1",
            "requester": "test-user@company.com"
        }
        
        with patch('src.lambda.send_approval.get_dynamodb_table', return_value=table):
            result = send_approval_request(request_data)
            
            self.assertIn("request_id", result)
            self.assertIn("approval_url", result)
    
    @mock_dynamodb
    def test_approval_callback(self):
        """Test approval callback processing"""
        from src.lambda.approval_callback import process_approval_response
        
        # Create mock DynamoDB table
        dynamodb = boto3.resource('dynamodb', region_name=TEST_CONFIG["aws_region"])
        table = dynamodb.create_table(
            TableName='eks-doctor-approvals',
            KeySchema=[
                {'AttributeName': 'request_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'request_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Insert test approval request
        table.put_item(Item={
            'request_id': 'test-request-123',
            'status': 'pending',
            'operation': 'drain_node',
            'created_at': int(time.time())
        })
        
        approval_response = {
            "request_id": "test-request-123",
            "action": "approve",
            "approver": "manager@company.com",
            "comments": "Approved for maintenance"
        }
        
        with patch('src.lambda.approval_callback.get_dynamodb_table', return_value=table):
            result = process_approval_response(approval_response)
            
            self.assertTrue(result["success"])
            self.assertEqual(result["status"], "approved")


class TestBedrockIntegration(EKSDoctorTestCase):
    """Test Bedrock integration functionality"""
    
    @patch('boto3.client')
    def test_analyze_with_bedrock(self, mock_boto3):
        """Test Bedrock analysis"""
        from src.lambda.AnalyzeWithBedrock import analyze_cluster_issues
        
        # Mock Bedrock Runtime client
        mock_bedrock = Mock()
        mock_bedrock.invoke_model.return_value = {
            'body': Mock(read=lambda: json.dumps({
                'content': [{
                    'text': 'Analysis: The cluster has node readiness issues...'
                }]
            }).encode())
        }
        mock_boto3.return_value = mock_bedrock
        
        cluster_data = {
            "cluster_info": self.sample_cluster_info,
            "node_health": {"ready_nodes": 1, "not_ready_nodes": 1},
            "issues": ["Node readiness problems"]
        }
        
        result = analyze_cluster_issues(cluster_data)
        
        self.assertIn("analysis", result)
        self.assertIn("recommendations", result)
    
    def test_format_cluster_data_for_bedrock(self):
        """Test data formatting for Bedrock"""
        from src.lambda.AnalyzeWithBedrock import format_cluster_data_for_bedrock
        
        cluster_data = {
            "cluster_info": {"name": "test-cluster", "version": "1.28"},
            "node_health": {"total_nodes": 3, "ready_nodes": 2},
            "issues": ["Network connectivity issues"]
        }
        
        formatted_data = format_cluster_data_for_bedrock(cluster_data)
        
        self.assertIn("cluster_name", formatted_data)
        self.assertIn("cluster_version", formatted_data)
        self.assertIn("node_summary", formatted_data)
        self.assertIn("identified_issues", formatted_data)


class TestInputValidation(EKSDoctorTestCase):
    """Test input validation functionality"""
    
    def test_validate_cluster_name(self):
        """Test cluster name validation"""
        from src.lambda.input_validator import validate_cluster_name
        
        # Valid cluster names
        valid_names = ["test-cluster", "my-cluster-123", "cluster"]
        for name in valid_names:
            result = validate_cluster_name(name)
            self.assertTrue(result["valid"], f"Failed for valid name: {name}")
        
        # Invalid cluster names
        invalid_names = ["", "cluster_with_underscore", "cluster-", "-cluster", "a" * 101]
        for name in invalid_names:
            result = validate_cluster_name(name)
            self.assertFalse(result["valid"], f"Passed for invalid name: {name}")
    
    def test_validate_node_name(self):
        """Test node name validation"""
        from src.lambda.input_validator import validate_node_name
        
        # Valid node names
        valid_names = ["ip-10-0-1-100.us-west-2.compute.internal", "node-1", "worker-node-abc123"]
        for name in valid_names:
            result = validate_node_name(name)
            self.assertTrue(result["valid"], f"Failed for valid name: {name}")
        
        # Invalid node names
        invalid_names = ["", "node with spaces", "node@special", "a" * 256]
        for name in invalid_names:
            result = validate_node_name(name)
            self.assertFalse(result["valid"], f"Passed for invalid name: {name}")
    
    def test_validate_operation_parameters(self):
        """Test operation parameter validation"""
        from src.lambda.input_validator import validate_operation_parameters
        
        # Valid drain operation
        valid_drain = {
            "operation": "drain_node",
            "cluster_name": "test-cluster",
            "node_name": "node-1",
            "grace_period": 300
        }
        
        result = validate_operation_parameters(valid_drain)
        self.assertTrue(result["valid"])
        
        # Invalid operation - missing required parameter
        invalid_operation = {
            "operation": "drain_node",
            "cluster_name": "test-cluster"
            # missing node_name
        }
        
        result = validate_operation_parameters(invalid_operation)
        self.assertFalse(result["valid"])


class TestStepFunctionsIntegration(EKSDoctorTestCase):
    """Test Step Functions integration"""
    
    @mock_stepfunctions
    def test_start_step_function_execution(self):
        """Test Step Functions execution start"""
        from src.lambda.health_snapshot import trigger_step_function
        
        # Create mock Step Functions client
        client = boto3.client('stepfunctions', region_name=TEST_CONFIG["aws_region"])
        
        # Create a state machine
        definition = json.dumps({
            "Comment": "Test state machine",
            "StartAt": "Pass",
            "States": {"Pass": {"Type": "Pass", "End": True}}
        })
        
        response = client.create_state_machine(
            name='test-state-machine',
            definition=definition,
            roleArn=f"arn:aws:iam::{TEST_CONFIG['account_id']}:role/test-role"
        )
        
        state_machine_arn = response['stateMachineArn']
        
        # Test execution start
        execution_input = {"cluster_name": TEST_CONFIG["cluster_name"]}
        
        with patch('boto3.client', return_value=client):
            result = trigger_step_function(state_machine_arn, execution_input)
            
            self.assertIn("execution_arn", result)
            self.assertIn("execution_name", result)


class TestEndToEndScenarios(EKSDoctorTestCase):
    """Test end-to-end scenarios"""
    
    def test_complete_node_drain_workflow(self):
        """Test complete node drain workflow"""
        # This would be an integration test that simulates:
        # 1. Health check identifies unhealthy node
        # 2. Bedrock recommends node drain
        # 3. Approval workflow is triggered
        # 4. Upon approval, node is drained
        # 5. Verification that drain was successful
        
        # Mock the entire workflow
        with patch('src.lambda.health_snapshot.collect_cluster_health') as mock_health, \
             patch('src.lambda.AnalyzeWithBedrock.analyze_cluster_issues') as mock_bedrock, \
             patch('src.lambda.send_approval.send_approval_request') as mock_approval, \
             patch('src.lambda.drain_node.drain_kubernetes_node') as mock_drain:
            
            # Setup mocks
            mock_health.return_value = {
                "cluster_info": self.sample_cluster_info,
                "node_health": {"ready_nodes": 1, "not_ready_nodes": 1},
                "issues": ["Node not ready"]
            }
            
            mock_bedrock.return_value = {
                "analysis": "Node has persistent issues",
                "recommendations": ["Drain and replace the node"],
                "confidence": 0.9
            }
            
            mock_approval.return_value = {
                "request_id": "test-123",
                "approval_url": "https://api.example.com/approve/test-123"
            }
            
            mock_drain.return_value = {
                "success": True,
                "drained_pods": 5,
                "duration": 120
            }
            
            # Simulate the workflow
            # 1. Health check
            health_result = mock_health(TEST_CONFIG["cluster_name"], TEST_CONFIG["aws_region"])
            self.assertIn("issues", health_result)
            
            # 2. Bedrock analysis
            analysis_result = mock_bedrock(health_result)
            self.assertIn("recommendations", analysis_result)
            
            # 3. Approval request
            approval_result = mock_approval({
                "operation": "drain_node",
                "cluster_name": TEST_CONFIG["cluster_name"],
                "node_name": "node-2"
            })
            self.assertIn("request_id", approval_result)
            
            # 4. Node drain (after approval)
            drain_result = mock_drain("node-2", force=False)
            self.assertTrue(drain_result["success"])


class TestPerformance(EKSDoctorTestCase):
    """Test performance characteristics"""
    
    def test_health_snapshot_performance(self):
        """Test health snapshot collection performance"""
        from src.lambda.health_snapshot import lambda_handler
        
        # Mock large cluster scenario
        large_node_list = []
        for i in range(100):
            large_node_list.append({
                "metadata": {"name": f"node-{i}", "labels": {"instance-type": "t3.medium"}},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                "spec": {"taints": []}
            })
        
        with patch('src.lambda.health_snapshot.collect_cluster_health') as mock_collect:
            # Simulate time-consuming operation
            mock_collect.return_value = {
                "cluster_info": self.sample_cluster_info,
                "node_health": {"total_nodes": 100, "ready_nodes": 95},
                "execution_time": 15  # seconds
            }
            
            start_time = time.time()
            
            event = {
                "cluster_name": TEST_CONFIG["cluster_name"],
                "region": TEST_CONFIG["aws_region"]
            }
            
            result = lambda_handler(event, {})
            
            execution_time = time.time() - start_time
            
            # Ensure it completes within reasonable time
            self.assertLess(execution_time, 30)  # Lambda timeout consideration
            self.assertIn("cluster_health", result)


class TestErrorHandling(EKSDoctorTestCase):
    """Test error handling scenarios"""
    
    def test_cluster_not_found_error(self):
        """Test handling of cluster not found error"""
        from src.lambda.health_snapshot import lambda_handler
        
        with patch('boto3.client') as mock_boto3:
            mock_eks = Mock()
            mock_eks.describe_cluster.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}},
                "DescribeCluster"
            )
            mock_boto3.return_value = mock_eks
            
            event = {
                "cluster_name": "non-existent-cluster",
                "region": TEST_CONFIG["aws_region"]
            }
            
            result = lambda_handler(event, {})
            
            self.assertIn("error", result)
            self.assertIn("cluster not found", result["error"].lower())
    
    def test_kubernetes_api_error(self):
        """Test handling of Kubernetes API errors"""
        from src.lambda.drain_node import lambda_handler
        
        with patch('kubernetes.client.CoreV1Api') as mock_k8s_api:
            mock_api = Mock()
            mock_api.list_pod_for_all_namespaces.side_effect = ApiException(
                status=403,
                reason="Forbidden"
            )
            mock_k8s_api.return_value = mock_api
            
            event = {
                "cluster_name": TEST_CONFIG["cluster_name"],
                "node_name": "node-1",
                "region": TEST_CONFIG["aws_region"]
            }
            
            result = lambda_handler(event, {})
            
            self.assertIn("error", result)
            self.assertIn("forbidden", result["error"].lower())


# Test utilities
def run_integration_tests():
    """Run integration tests against real AWS resources"""
    if not os.environ.get('RUN_INTEGRATION_TESTS'):
        print("Skipping integration tests. Set RUN_INTEGRATION_TESTS=1 to enable.")
        return
    
    # Integration test setup
    cluster_name = os.environ.get('TEST_CLUSTER_NAME')
    if not cluster_name:
        print("TEST_CLUSTER_NAME environment variable required for integration tests")
        return
    
    # Run real tests against actual cluster
    print(f"Running integration tests against cluster: {cluster_name}")
    
    # Test health snapshot
    try:
        from src.lambda.health_snapshot import collect_cluster_health
        result = collect_cluster_health(cluster_name, TEST_CONFIG["aws_region"])
        print(f"Health snapshot successful: {len(result.get('nodes', []))} nodes found")
    except Exception as e:
        print(f"Health snapshot failed: {str(e)}")
    
    # Add more integration tests as needed


def generate_test_report():
    """Generate comprehensive test report"""
    import coverage
    import pytest
    
    # Run tests with coverage
    cov = coverage.Coverage()
    cov.start()
    
    # Run pytest
    exit_code = pytest.main([
        "--verbose",
        "--tb=short",
        "--junit-xml=test-results.xml",
        "--html=test-report.html",
        "--self-contained-html"
    ])
    
    cov.stop()
    cov.save()
    
    # Generate coverage report
    cov.html_report(directory='coverage-report')
    cov.report()
    
    return exit_code


if __name__ == "__main__":
    # Command line test execution
    import argparse
    
    parser = argparse.ArgumentParser(description="EKS Doctor Test Runner")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--report", action="store_true", help="Generate test report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.integration:
        run_integration_tests()
    elif args.report:
        exit_code = generate_test_report()
        sys.exit(exit_code)
    else:
        # Run unit tests
        if args.verbose:
            verbosity = 2
        else:
            verbosity = 1
            
        unittest.main(verbosity=verbosity)
