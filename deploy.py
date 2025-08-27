#!/usr/bin/env python3
"""
EKS Doctor Bedrock Deployment Script
Production-grade deployment automation for EKS Doctor solution.
"""

import os
import sys
import json
import subprocess
import argparse
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, ProfileNotFound

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
SCRIPT_DIR = Path(__file__).parent
TERRAFORM_DIR = SCRIPT_DIR / "terraform"
REQUIRED_TOOLS = ["terraform", "aws", "python"]
MIN_TERRAFORM_VERSION = "1.5.0"
SUPPORTED_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1"]


class DeploymentError(Exception):
    """Custom exception for deployment errors"""
    pass


class EKSDoctorDeployer:
    """Main deployment orchestrator"""
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.logger = logger
        self.validate_prerequisites()
        
        # Initialize AWS session
        try:
            if args.profile:
                self.session = boto3.Session(profile_name=args.profile)
            else:
                self.session = boto3.Session()
                
            # Test AWS credentials
            sts = self.session.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
            self.logger.info(f"Using AWS Account: {self.account_id}")
            
        except (ClientError, ProfileNotFound) as e:
            raise DeploymentError(f"AWS authentication failed: {str(e)}")
    
    def validate_prerequisites(self) -> None:
        """Validate that required tools are available"""
        self.logger.info("Validating prerequisites...")
        
        missing_tools = []
        for tool in REQUIRED_TOOLS:
            if not self.check_command_exists(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            raise DeploymentError(f"Missing required tools: {', '.join(missing_tools)}")
        
        # Check Terraform version
        try:
            result = subprocess.run(
                ["terraform", "version", "-json"],
                capture_output=True,
                text=True,
                check=True
            )
            version_info = json.loads(result.stdout)
            tf_version = version_info["terraform_version"]
            
            if self.compare_versions(tf_version, MIN_TERRAFORM_VERSION) < 0:
                raise DeploymentError(
                    f"Terraform version {tf_version} is too old. "
                    f"Minimum required: {MIN_TERRAFORM_VERSION}"
                )
                
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
            raise DeploymentError(f"Failed to check Terraform version: {str(e)}")
        
        self.logger.info("Prerequisites validated successfully")
    
    def check_command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run(
                ["which", command] if os.name != 'nt' else ["where", command],
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings"""
        def normalize(v):
            return [int(x) for x in v.replace('v', '').split('.')]
        
        v1_parts = normalize(version1)
        v2_parts = normalize(version2)
        
        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        if v1_parts < v2_parts:
            return -1
        elif v1_parts > v2_parts:
            return 1
        else:
            return 0
    
    def validate_region(self, region: str) -> None:
        """Validate AWS region"""
        if region not in SUPPORTED_REGIONS:
            self.logger.warning(
                f"Region {region} is not in the tested regions: {SUPPORTED_REGIONS}"
            )
            
            # Check if region exists
            ec2 = self.session.client('ec2', region_name=region)
            try:
                ec2.describe_regions(RegionNames=[region])
            except ClientError:
                raise DeploymentError(f"Invalid AWS region: {region}")
    
    def generate_terraform_vars(self) -> Dict[str, Any]:
        """Generate Terraform variables from command line arguments"""
        terraform_vars = {
            "project_name": self.args.project_name,
            "environment": self.args.environment,
            "primary_region": self.args.primary_region,
            "secondary_region": self.args.secondary_region,
            "hub_account_id": self.args.hub_account_id or self.account_id,
            
            # Security settings
            "external_id": self.args.external_id,
            "enable_encryption": self.args.enable_encryption,
            "enable_backup": self.args.enable_backup,
            
            # Networking
            "trusted_ip_ranges": self.args.trusted_ip_ranges,
            "create_vpc_endpoints": self.args.create_vpc_endpoints,
            
            # Monitoring
            "enable_xray_tracing": self.args.enable_xray_tracing,
            "log_retention_days": self.args.log_retention_days,
            "log_level": self.args.log_level,
            
            # Notifications
            "notification_email": self.args.notification_email,
            "slack_webhook_url": self.args.slack_webhook_url,
            
            # Bedrock
            "bedrock_model_id": self.args.bedrock_model_id,
            
            # API Gateway
            "create_api_key": self.args.create_api_key,
            "api_domain_name": self.args.api_domain_name,
            "api_certificate_arn": self.args.api_certificate_arn,
            
            # Tags
            "default_tags": {
                "Project": "EKS-Doctor",
                "Environment": self.args.environment,
                "ManagedBy": "Terraform",
                "Repository": "eks-doctor-bedrock",
                "DeployedBy": os.environ.get("USER", "unknown"),
                "DeploymentTime": subprocess.check_output(["date", "-Iseconds"], text=True).strip()
            }
        }
        
        # Filter None values
        return {k: v for k, v in terraform_vars.items() if v is not None}
    
    def write_terraform_vars(self, vars_dict: Dict[str, Any]) -> Path:
        """Write Terraform variables to file"""
        vars_file = TERRAFORM_DIR / f"{self.args.environment}.auto.tfvars.json"
        
        with open(vars_file, 'w') as f:
            json.dump(vars_dict, f, indent=2)
        
        self.logger.info(f"Terraform variables written to: {vars_file}")
        return vars_file
    
    def run_terraform_command(self, command: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        """Run Terraform command with error handling"""
        if cwd is None:
            cwd = TERRAFORM_DIR
            
        self.logger.info(f"Running: terraform {' '.join(command)}")
        
        try:
            result = subprocess.run(
                ["terraform"] + command,
                cwd=cwd,
                check=True,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                self.logger.info(result.stdout)
            
            return result
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Terraform command failed: {e.stderr}")
            raise DeploymentError(f"Terraform command failed: {e.stderr}")
    
    def terraform_init(self) -> None:
        """Initialize Terraform"""
        self.logger.info("Initializing Terraform...")
        
        init_args = ["init"]
        
        # Add backend configuration if provided
        if self.args.backend_bucket:
            init_args.extend([
                "-backend-config", f"bucket={self.args.backend_bucket}",
                "-backend-config", f"key={self.args.project_name}/{self.args.environment}/terraform.tfstate",
                "-backend-config", f"region={self.args.primary_region}"
            ])
            
            if self.args.backend_dynamodb_table:
                init_args.extend([
                    "-backend-config", f"dynamodb_table={self.args.backend_dynamodb_table}"
                ])
        
        self.run_terraform_command(init_args)
    
    def terraform_validate(self) -> None:
        """Validate Terraform configuration"""
        self.logger.info("Validating Terraform configuration...")
        self.run_terraform_command(["validate"])
    
    def terraform_plan(self) -> None:
        """Create Terraform execution plan"""
        self.logger.info("Creating Terraform execution plan...")
        
        plan_args = ["plan", "-detailed-exitcode"]
        
        if self.args.target:
            plan_args.extend(["-target", self.args.target])
        
        try:
            self.run_terraform_command(plan_args)
        except DeploymentError as e:
            # Terraform plan returns exit code 2 when changes are detected
            if "exit status 2" in str(e):
                self.logger.info("Terraform plan shows changes to apply")
            else:
                raise
    
    def terraform_apply(self) -> None:
        """Apply Terraform configuration"""
        self.logger.info("Applying Terraform configuration...")
        
        apply_args = ["apply"]
        
        if self.args.auto_approve:
            apply_args.append("-auto-approve")
        
        if self.args.target:
            apply_args.extend(["-target", self.args.target])
        
        self.run_terraform_command(apply_args)
    
    def terraform_destroy(self) -> None:
        """Destroy Terraform-managed infrastructure"""
        self.logger.warning("Destroying Terraform-managed infrastructure...")
        
        destroy_args = ["destroy"]
        
        if self.args.auto_approve:
            destroy_args.append("-auto-approve")
        
        if self.args.target:
            destroy_args.extend(["-target", self.args.target])
        
        self.run_terraform_command(destroy_args)
    
    def deploy_hub_account(self) -> None:
        """Deploy hub account infrastructure"""
        self.logger.info("Deploying hub account infrastructure...")
        
        # Change to hub module directory
        hub_dir = TERRAFORM_DIR / "environments" / "hub"
        hub_dir.mkdir(parents=True, exist_ok=True)
        
        # Create hub-specific main.tf if it doesn't exist
        hub_main_tf = hub_dir / "main.tf"
        if not hub_main_tf.exists():
            with open(hub_main_tf, 'w') as f:
                f.write(self.generate_hub_terraform_config())
        
        # Generate variables file
        terraform_vars = self.generate_terraform_vars()
        self.write_terraform_vars(terraform_vars)
        
        # Run Terraform commands
        self.terraform_init()
        self.terraform_validate()
        self.terraform_plan()
        self.terraform_apply()
        
        self.logger.info("Hub account deployment completed successfully")
    
    def deploy_spoke_account(self, spoke_account_id: str) -> None:
        """Deploy spoke account infrastructure"""
        self.logger.info(f"Deploying spoke account infrastructure for account: {spoke_account_id}")
        
        # Change to spoke module directory
        spoke_dir = TERRAFORM_DIR / "environments" / f"spoke-{spoke_account_id}"
        spoke_dir.mkdir(parents=True, exist_ok=True)
        
        # Create spoke-specific main.tf
        spoke_main_tf = spoke_dir / "main.tf"
        if not spoke_main_tf.exists():
            with open(spoke_main_tf, 'w') as f:
                f.write(self.generate_spoke_terraform_config(spoke_account_id))
        
        # Generate variables file with spoke-specific settings
        terraform_vars = self.generate_terraform_vars()
        terraform_vars["spoke_account_id"] = spoke_account_id
        
        vars_file = spoke_dir / f"{self.args.environment}.auto.tfvars.json"
        with open(vars_file, 'w') as f:
            json.dump(terraform_vars, f, indent=2)
        
        # Run Terraform commands in spoke directory
        self.run_terraform_command(["init"], cwd=spoke_dir)
        self.run_terraform_command(["validate"], cwd=spoke_dir)
        self.run_terraform_command(["plan", "-detailed-exitcode"], cwd=spoke_dir)
        self.run_terraform_command(["apply", "-auto-approve" if self.args.auto_approve else ""], cwd=spoke_dir)
        
        self.logger.info(f"Spoke account deployment completed for account: {spoke_account_id}")
    
    def generate_hub_terraform_config(self) -> str:
        """Generate hub account Terraform configuration"""
        return f'''# Hub Account Configuration
terraform {{
  required_version = ">= 1.5"
  
  backend "s3" {{
    # Backend configuration provided via CLI args or backend.tf
  }}
  
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

module "eks_doctor_hub" {{
  source = "../../modules/hub"
  
  # All variables will be loaded from auto.tfvars.json
}}

# Outputs
output "hub_outputs" {{
  description = "Hub account outputs"
  value       = module.eks_doctor_hub
  sensitive   = true
}}
'''
    
    def generate_spoke_terraform_config(self, spoke_account_id: str) -> str:
        """Generate spoke account Terraform configuration"""
        return f'''# Spoke Account Configuration - {spoke_account_id}
terraform {{
  required_version = ">= 1.5"
  
  backend "s3" {{
    # Backend configuration provided via CLI args or backend.tf
  }}
  
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

module "eks_doctor_spoke" {{
  source = "../../modules/spoke"
  
  # All variables will be loaded from auto.tfvars.json
  spoke_account_id = "{spoke_account_id}"
}}

# Outputs
output "spoke_outputs" {{
  description = "Spoke account outputs"
  value       = module.eks_doctor_spoke
}}
'''
    
    def validate_bedrock_access(self) -> None:
        """Validate access to Amazon Bedrock"""
        self.logger.info("Validating Bedrock access...")
        
        try:
            bedrock = self.session.client('bedrock', region_name=self.args.primary_region)
            
            # List available foundation models
            models = bedrock.list_foundation_models()
            
            # Check if requested model is available
            model_ids = [model['modelId'] for model in models.get('modelSummaries', [])]
            
            if self.args.bedrock_model_id not in model_ids:
                self.logger.warning(
                    f"Model {self.args.bedrock_model_id} may not be available. "
                    f"Available models: {model_ids[:5]}..."
                )
            else:
                self.logger.info(f"Bedrock model {self.args.bedrock_model_id} is available")
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'UnauthorizedOperation':
                raise DeploymentError(
                    "Access to Amazon Bedrock is not authorized. "
                    "Please ensure your AWS credentials have the necessary permissions."
                )
            else:
                self.logger.warning(f"Could not validate Bedrock access: {str(e)}")
    
    def run_deployment(self) -> None:
        """Run the complete deployment process"""
        try:
            self.logger.info(f"Starting EKS Doctor deployment - Environment: {self.args.environment}")
            
            # Validate regions
            self.validate_region(self.args.primary_region)
            self.validate_region(self.args.secondary_region)
            
            # Validate Bedrock access
            self.validate_bedrock_access()
            
            if self.args.action == "deploy":
                if self.args.deployment_type in ["hub", "all"]:
                    self.deploy_hub_account()
                
                if self.args.deployment_type in ["spoke", "all"] and self.args.spoke_accounts:
                    for spoke_account in self.args.spoke_accounts:
                        self.deploy_spoke_account(spoke_account)
                        
            elif self.args.action == "destroy":
                if self.args.deployment_type in ["spoke", "all"] and self.args.spoke_accounts:
                    for spoke_account in self.args.spoke_accounts:
                        spoke_dir = TERRAFORM_DIR / "environments" / f"spoke-{spoke_account}"
                        if spoke_dir.exists():
                            self.run_terraform_command(["destroy", "-auto-approve" if self.args.auto_approve else ""], cwd=spoke_dir)
                
                if self.args.deployment_type in ["hub", "all"]:
                    self.terraform_destroy()
            
            self.logger.info("Deployment completed successfully!")
            
        except KeyboardInterrupt:
            self.logger.warning("Deployment interrupted by user")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Deployment failed: {str(e)}")
            sys.exit(1)


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Deploy EKS Doctor Bedrock solution",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Action
    parser.add_argument(
        "action",
        choices=["deploy", "destroy", "plan"],
        help="Action to perform"
    )
    
    # Deployment type
    parser.add_argument(
        "--type",
        dest="deployment_type",
        choices=["hub", "spoke", "all"],
        default="all",
        help="Deployment type"
    )
    
    # Basic configuration
    parser.add_argument(
        "--project-name",
        default="eks-doctor",
        help="Project name"
    )
    
    parser.add_argument(
        "--environment",
        required=True,
        choices=["dev", "staging", "prod"],
        help="Environment name"
    )
    
    # AWS configuration
    parser.add_argument(
        "--profile",
        help="AWS profile to use"
    )
    
    parser.add_argument(
        "--primary-region",
        default="us-east-1",
        help="Primary AWS region"
    )
    
    parser.add_argument(
        "--secondary-region",
        default="us-west-2",
        help="Secondary AWS region"
    )
    
    parser.add_argument(
        "--hub-account-id",
        help="Hub account ID (defaults to current account)"
    )
    
    parser.add_argument(
        "--spoke-accounts",
        nargs="+",
        help="List of spoke account IDs"
    )
    
    # Security
    parser.add_argument(
        "--external-id",
        required=True,
        help="External ID for cross-account roles"
    )
    
    parser.add_argument(
        "--enable-encryption",
        action="store_true",
        default=True,
        help="Enable encryption"
    )
    
    parser.add_argument(
        "--enable-backup",
        action="store_true",
        default=True,
        help="Enable backup"
    )
    
    parser.add_argument(
        "--trusted-ip-ranges",
        nargs="+",
        help="Trusted IP ranges for access"
    )
    
    # Monitoring
    parser.add_argument(
        "--enable-xray-tracing",
        action="store_true",
        default=True,
        help="Enable X-Ray tracing"
    )
    
    parser.add_argument(
        "--log-retention-days",
        type=int,
        default=30,
        help="Log retention period in days"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Log level"
    )
    
    # Notifications
    parser.add_argument(
        "--notification-email",
        help="Email for notifications"
    )
    
    parser.add_argument(
        "--slack-webhook-url",
        help="Slack webhook URL"
    )
    
    # Bedrock
    parser.add_argument(
        "--bedrock-model-id",
        default="anthropic.claude-3-5-sonnet-20241022-v2:0",
        help="Bedrock model ID"
    )
    
    # API Gateway
    parser.add_argument(
        "--create-api-key",
        action="store_true",
        help="Create API Gateway API key"
    )
    
    parser.add_argument(
        "--api-domain-name",
        help="Custom domain name for API Gateway"
    )
    
    parser.add_argument(
        "--api-certificate-arn",
        help="SSL certificate ARN for custom domain"
    )
    
    # Terraform backend
    parser.add_argument(
        "--backend-bucket",
        help="S3 bucket for Terraform backend"
    )
    
    parser.add_argument(
        "--backend-dynamodb-table",
        help="DynamoDB table for Terraform state locking"
    )
    
    # Deployment options
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto-approve Terraform changes"
    )
    
    parser.add_argument(
        "--target",
        help="Target specific resource for Terraform operations"
    )
    
    parser.add_argument(
        "--create-vpc-endpoints",
        action="store_true",
        default=True,
        help="Create VPC endpoints"
    )
    
    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        deployer = EKSDoctorDeployer(args)
        deployer.run_deployment()
    except DeploymentError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
