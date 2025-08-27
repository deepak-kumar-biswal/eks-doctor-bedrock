# Terraform Configuration
terraform {
  required_version = ">= 1.5"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.2"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.1"
    }
  }

  # Uncomment and configure for remote state
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "eks-doctor/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-state-lock"
  #   encrypt        = true
  # }
}

# Primary AWS Provider (Hub Account)
provider "aws" {
  region = var.primary_region
  
  default_tags {
    tags = merge(var.common_tags, {
      ManagedBy = "terraform"
      Solution  = "eks-doctor-bedrock"
    })
  }
}

# Secondary Region Provider
provider "aws" {
  alias  = "secondary"
  region = length(var.regions) > 1 ? var.regions[1] : var.primary_region
  
  default_tags {
    tags = merge(var.common_tags, {
      ManagedBy = "terraform"
      Solution  = "eks-doctor-bedrock"
    })
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_partition" "current" {}

# Random Resources
resource "random_id" "unique_suffix" {
  byte_length = 4
}

resource "random_string" "external_id" {
  count   = var.external_id == "" ? 1 : 0
  length  = 32
  special = true
  upper   = true
  lower   = true
  numeric = true
}

# Local Values
locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
  
  # Generate unique suffix for resources
  unique_suffix = random_id.unique_suffix.hex
  
  # External ID for cross-account trust
  external_id = var.external_id != "" ? var.external_id : random_string.external_id[0].result
  
  # Resource naming
  name_prefix = "${var.project_name}-${var.environment}"
  
  # Lambda function names
  lambda_functions = {
    health_snapshot   = "${local.name_prefix}-health-snapshot"
    network_triage   = "${local.name_prefix}-network-triage"
    drain_node       = "${local.name_prefix}-drain-node"
    scale_nodegroup  = "${local.name_prefix}-scale-nodegroup"
    restart_workload = "${local.name_prefix}-restart-workload"
    send_approval    = "${local.name_prefix}-send-approval"
    handle_approval  = "${local.name_prefix}-handle-approval"
  }
  
  # S3 bucket names
  s3_buckets = {
    for region in var.regions : region => {
      knowledge_base = "${var.project_name}-kb-${local.account_id}-${region}-${local.unique_suffix}"
      logs          = "${var.project_name}-logs-${local.account_id}-${region}-${local.unique_suffix}"
      artifacts     = "${var.project_name}-artifacts-${local.account_id}-${region}-${local.unique_suffix}"
    }
  }
  
  # IAM role names
  iam_roles = {
    hub = {
      lambda_execution  = "${local.name_prefix}-lambda-execution"
      bedrock_agent     = "${local.name_prefix}-bedrock-agent"
      step_functions    = "${local.name_prefix}-step-functions"
    }
    spoke = {
      readonly = "eks-ops-readonly"
      change   = "eks-ops-change"
    }
  }
  
  # Common tags for all resources
  common_tags = merge(var.common_tags, {
    Project     = var.project_name
    Environment = var.environment
    Region      = local.region
    AccountId   = local.account_id
    Terraform   = "true"
    CreatedDate = formatdate("YYYY-MM-DD", timestamp())
  })
}
