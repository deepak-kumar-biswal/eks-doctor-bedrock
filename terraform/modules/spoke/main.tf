# Spoke Account Configuration
terraform {
  required_version = ">= 1.5"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure providers for spoke account
provider "aws" {
  region = var.primary_region
  
  default_tags {
    tags = merge(var.default_tags, {
      "EKSDoctor:Account"     = "spoke"
      "EKSDoctor:Region"      = var.primary_region
      "EKSDoctor:Environment" = var.environment
    })
  }
}

# Optional secondary region provider
provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
  
  default_tags {
    tags = merge(var.default_tags, {
      "EKSDoctor:Account"     = "spoke"
      "EKSDoctor:Region"      = var.secondary_region
      "EKSDoctor:Environment" = var.environment
    })
  }
}

# Local values for naming and configuration
locals {
  name_prefix = "${var.project_name}-${var.environment}"
  
  # Hub account cross-account role ARNs
  hub_lambda_role_arn       = "arn:aws:iam::${var.hub_account_id}:role/${var.project_name}-${var.environment}-lambda-role"
  hub_bedrock_agent_role_arn = "arn:aws:iam::${var.hub_account_id}:role/${var.project_name}-${var.environment}-bedrock-agent-role"
  
  # Common tags for all resources
  common_tags = merge(var.default_tags, {
    "EKSDoctor:Component" = "spoke-infrastructure"
    "EKSDoctor:Version"   = var.solution_version
  })
}

# Cross-account role for hub account to assume in spoke account
resource "aws_iam_role" "hub_cross_account_role" {
  name = "${local.name_prefix}-hub-cross-account-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            local.hub_lambda_role_arn,
            local.hub_bedrock_agent_role_arn
          ]
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
          StringLike = {
            "aws:userid" = [
              "*:${var.project_name}-*",
              "AIDACKCEVSQ6C2EXAMPLE"  # Replace with actual trusted user IDs
            ]
          }
          IpAddress = var.trusted_ip_ranges != null ? {
            "aws:SourceIp" = var.trusted_ip_ranges
          } : null
          DateGreaterThan = {
            "aws:CurrentTime" = "2024-01-01T00:00:00Z"
          }
        }
      }
    ]
  })
  
  managed_policy_arns = [
    aws_iam_policy.spoke_eks_access.arn,
    aws_iam_policy.spoke_monitoring.arn
  ]
  
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-hub-cross-account-role"
  })
}

# EKS access policy for spoke account
resource "aws_iam_policy" "spoke_eks_access" {
  name        = "${local.name_prefix}-spoke-eks-access"
  description = "EKS Doctor spoke account access policy for EKS operations"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EKS cluster operations
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:DescribeNodegroup",
          "eks:ListNodegroups",
          "eks:DescribeUpdate",
          "eks:ListUpdates",
          "eks:DescribeAddon",
          "eks:ListAddons",
          "eks:UpdateAddon",
          "eks:DescribeFargateProfile",
          "eks:ListFargateProfiles",
          "eks:ListIdentityProviderConfigs",
          "eks:DescribeIdentityProviderConfig",
          
          # EKS cluster authentication
          "eks:AccessKubernetesApi",
          
          # EKS nodegroup operations (limited)
          "eks:UpdateNodegroupVersion",
          "eks:UpdateNodegroupConfig"
        ]
        Resource = var.allowed_cluster_arns != null ? var.allowed_cluster_arns : [
          "arn:aws:eks:${var.primary_region}:${data.aws_caller_identity.current.account_id}:cluster/*",
          "arn:aws:eks:${var.secondary_region}:${data.aws_caller_identity.current.account_id}:cluster/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # EC2 operations for node management
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstanceAttribute",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeRouteTables",
          "ec2:DescribeNatGateways",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeTransitGateways",
          "ec2:DescribeTransitGatewayAttachments",
          
          # ASG operations for nodegroup scaling
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeLaunchTemplates",
          "autoscaling:DescribeScalingActivities",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:SuspendProcesses",
          "autoscaling:ResumeProcesses",
          
          # Launch template operations
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # Systems Manager for node operations
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceInformation",
          "ssm:ListCommandInvocations"
        ]
        Resource = [
          "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:document/AWS-RunShellScript",
          "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:document/${var.project_name}-*",
          "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
        Condition = {
          StringEquals = {
            "ssm:ResourceTag/EKSDoctor" = "managed"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          # Application Load Balancer operations
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeRules"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-spoke-eks-access"
  })
}

# Monitoring and logging policy for spoke account
resource "aws_iam_policy" "spoke_monitoring" {
  name        = "${local.name_prefix}-spoke-monitoring"
  description = "EKS Doctor spoke account monitoring and logging policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # CloudWatch metrics
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics",
          
          # CloudWatch logs
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/eks/*",
          "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:${var.project_name}-*",
          "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # EventBridge for notifications
          "events:PutEvents"
        ]
        Resource = [
          "arn:aws:events:*:${var.hub_account_id}:event-bus/${var.project_name}-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # X-Ray tracing
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-spoke-monitoring"
  })
}

# Service-linked role for EKS if it doesn't exist
resource "aws_iam_service_linked_role" "eks" {
  count            = var.create_eks_service_role ? 1 : 0
  aws_service_name = "eks.amazonaws.com"
  description      = "Service-linked role for Amazon EKS"
  
  tags = merge(local.common_tags, {
    "Name" = "AWSServiceRoleForAmazonEKS"
  })
}

# Service-linked role for EKS Fargate if enabled
resource "aws_iam_service_linked_role" "eks_fargate" {
  count            = var.enable_fargate ? 1 : 0
  aws_service_name = "eks-fargate-pods.amazonaws.com"
  description      = "Service-linked role for Amazon EKS Fargate"
  
  tags = merge(local.common_tags, {
    "Name" = "AWSServiceRoleForAmazonEKSForFargate"
  })
}

# Service-linked role for EKS NodeGroup
resource "aws_iam_service_linked_role" "eks_nodegroup" {
  count            = var.create_nodegroup_service_role ? 1 : 0
  aws_service_name = "eks-nodegroup.amazonaws.com"
  description      = "Service-linked role for Amazon EKS NodeGroup"
  
  tags = merge(local.common_tags, {
    "Name" = "AWSServiceRoleForAmazonEKSNodegroup"
  })
}

# CloudWatch Log Group for EKS cluster logs (if enabled)
resource "aws_cloudwatch_log_group" "eks_cluster_logs" {
  for_each = var.enable_cluster_logging ? toset(var.cluster_log_types) : []
  
  name              = "/aws/eks/${var.cluster_name}/${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.enable_log_encryption ? aws_kms_key.spoke_logs[0].arn : null
  
  tags = merge(local.common_tags, {
    "Name"       = "/aws/eks/${var.cluster_name}/${each.key}"
    "LogType"    = each.key
    "Component"  = "eks-logging"
  })
}

# KMS key for log encryption
resource "aws_kms_key" "spoke_logs" {
  count = var.enable_log_encryption ? 1 : 0
  
  description = "EKS Doctor spoke account logs encryption key"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.primary_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.primary_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/eks/${var.cluster_name}/*"
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-spoke-logs-key"
  })
}

resource "aws_kms_alias" "spoke_logs" {
  count = var.enable_log_encryption ? 1 : 0
  
  name          = "alias/${local.name_prefix}-spoke-logs"
  target_key_id = aws_kms_key.spoke_logs[0].key_id
}

# EventBridge custom bus for cross-account events (optional)
resource "aws_cloudwatch_event_bus" "spoke_events" {
  count = var.create_spoke_event_bus ? 1 : 0
  
  name = "${local.name_prefix}-spoke-events"
  
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-spoke-events"
  })
}

# EventBridge rule to forward EKS events to hub account
resource "aws_cloudwatch_event_rule" "forward_eks_events" {
  count = var.forward_eks_events ? 1 : 0
  
  name        = "${local.name_prefix}-forward-eks-events"
  description = "Forward EKS events to hub account"
  
  event_pattern = jsonencode({
    source      = ["aws.eks"]
    detail-type = [
      "EKS Cluster State Change",
      "EKS Nodegroup State Change",
      "EKS Addon State Change"
    ]
    detail = {
      clusterName = var.monitored_cluster_names != null ? var.monitored_cluster_names : [var.cluster_name]
    }
  })
  
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-forward-eks-events"
  })
}

resource "aws_cloudwatch_event_target" "hub_account_target" {
  count = var.forward_eks_events ? 1 : 0
  
  rule     = aws_cloudwatch_event_rule.forward_eks_events[0].name
  arn      = "arn:aws:events:${var.primary_region}:${var.hub_account_id}:event-bus/${var.project_name}-${var.environment}-hub-events"
  target_id = "HubAccountTarget"
  
  role_arn = aws_iam_role.event_bridge_cross_account[0].arn
}

# IAM role for cross-account EventBridge
resource "aws_iam_role" "event_bridge_cross_account" {
  count = var.forward_eks_events ? 1 : 0
  
  name = "${local.name_prefix}-eventbridge-cross-account"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  inline_policy {
    name = "CrossAccountEventPolicy"
    
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "events:PutEvents"
          ]
          Resource = [
            "arn:aws:events:${var.primary_region}:${var.hub_account_id}:event-bus/${var.project_name}-${var.environment}-hub-events"
          ]
        }
      ]
    })
  }
  
  tags = merge(local.common_tags, {
    "Name" = "${local.name_prefix}-eventbridge-cross-account"
  })
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Outputs for reference
output "cross_account_role_arn" {
  description = "ARN of the cross-account role for hub account to assume"
  value       = aws_iam_role.hub_cross_account_role.arn
}

output "spoke_account_id" {
  description = "AWS account ID of the spoke account"
  value       = data.aws_caller_identity.current.account_id
}

output "spoke_region" {
  description = "Primary region of the spoke account"
  value       = data.aws_region.current.name
}

output "log_groups" {
  description = "CloudWatch log groups created for EKS cluster logging"
  value = var.enable_cluster_logging ? {
    for log_type in var.cluster_log_types : log_type => aws_cloudwatch_log_group.eks_cluster_logs[log_type].name
  } : {}
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for log encryption"
  value       = var.enable_log_encryption ? aws_kms_key.spoke_logs[0].arn : null
}

output "event_bus_name" {
  description = "Name of the EventBridge custom bus (if created)"
  value       = var.create_spoke_event_bus ? aws_cloudwatch_event_bus.spoke_events[0].name : null
}
