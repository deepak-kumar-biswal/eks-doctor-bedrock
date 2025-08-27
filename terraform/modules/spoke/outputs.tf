# Spoke Module Outputs

# Account Information
output "account_id" {
  description = "AWS account ID of the spoke account"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "Primary AWS region of the spoke account"
  value       = data.aws_region.current.name
}

output "secondary_region" {
  description = "Secondary AWS region configured for the spoke account"
  value       = var.secondary_region
}

# Cross-Account Role
output "cross_account_role_arn" {
  description = "ARN of the cross-account role for hub account to assume"
  value       = aws_iam_role.hub_cross_account_role.arn
}

output "cross_account_role_name" {
  description = "Name of the cross-account role"
  value       = aws_iam_role.hub_cross_account_role.name
}

output "external_id" {
  description = "External ID used for cross-account role assumption"
  value       = var.external_id
  sensitive   = true
}

# IAM Policies
output "eks_access_policy_arn" {
  description = "ARN of the EKS access policy"
  value       = aws_iam_policy.spoke_eks_access.arn
}

output "monitoring_policy_arn" {
  description = "ARN of the monitoring policy"
  value       = aws_iam_policy.spoke_monitoring.arn
}

# Service-Linked Roles
output "service_linked_roles" {
  description = "Service-linked roles created in the spoke account"
  value = {
    eks          = var.create_eks_service_role ? aws_iam_service_linked_role.eks[0].arn : null
    eks_fargate  = var.enable_fargate ? aws_iam_service_linked_role.eks_fargate[0].arn : null
    eks_nodegroup = var.create_nodegroup_service_role ? aws_iam_service_linked_role.eks_nodegroup[0].arn : null
  }
}

# Logging Resources
output "log_groups" {
  description = "CloudWatch log groups created for EKS cluster logging"
  value = var.enable_cluster_logging ? {
    for log_type in var.cluster_log_types : log_type => {
      name = aws_cloudwatch_log_group.eks_cluster_logs[log_type].name
      arn  = aws_cloudwatch_log_group.eks_cluster_logs[log_type].arn
    }
  } : {}
}

output "log_encryption_key" {
  description = "KMS key information for log encryption"
  value = var.enable_log_encryption ? {
    key_id    = aws_kms_key.spoke_logs[0].key_id
    arn       = aws_kms_key.spoke_logs[0].arn
    alias     = aws_kms_alias.spoke_logs[0].name
  } : null
}

# EventBridge Resources
output "event_bus" {
  description = "EventBridge custom bus information"
  value = var.create_spoke_event_bus ? {
    name = aws_cloudwatch_event_bus.spoke_events[0].name
    arn  = aws_cloudwatch_event_bus.spoke_events[0].arn
  } : null
}

output "event_forwarding" {
  description = "EventBridge event forwarding configuration"
  value = var.forward_eks_events ? {
    rule_name    = aws_cloudwatch_event_rule.forward_eks_events[0].name
    rule_arn     = aws_cloudwatch_event_rule.forward_eks_events[0].arn
    target_arn   = "arn:aws:events:${var.primary_region}:${var.hub_account_id}:event-bus/${var.project_name}-${var.environment}-hub-events"
    role_arn     = aws_iam_role.event_bridge_cross_account[0].arn
  } : null
}

# Configuration Summary
output "configuration" {
  description = "Summary of spoke account configuration"
  value = {
    project_name     = var.project_name
    environment      = var.environment
    cluster_name     = var.cluster_name
    hub_account_id   = var.hub_account_id
    logging_enabled  = var.enable_cluster_logging
    log_encryption   = var.enable_log_encryption
    fargate_enabled  = var.enable_fargate
    event_forwarding = var.forward_eks_events
  }
}

# Hub Account Integration
output "hub_integration" {
  description = "Information needed for hub account integration"
  value = {
    cross_account_role_arn = aws_iam_role.hub_cross_account_role.arn
    external_id           = var.external_id
    account_id           = data.aws_caller_identity.current.account_id
    primary_region       = data.aws_region.current.name
    secondary_region     = var.secondary_region
    cluster_name         = var.cluster_name
    allowed_clusters     = var.allowed_cluster_arns
    monitored_clusters   = var.monitored_cluster_names != null ? var.monitored_cluster_names : [var.cluster_name]
  }
  sensitive = true
}

# Resource ARNs for Cross-Reference
output "resource_arns" {
  description = "ARNs of all created resources for cross-reference"
  value = {
    cross_account_role = aws_iam_role.hub_cross_account_role.arn
    eks_access_policy  = aws_iam_policy.spoke_eks_access.arn
    monitoring_policy  = aws_iam_policy.spoke_monitoring.arn
    log_groups = var.enable_cluster_logging ? [
      for log_type in var.cluster_log_types : aws_cloudwatch_log_group.eks_cluster_logs[log_type].arn
    ] : []
    kms_key = var.enable_log_encryption ? aws_kms_key.spoke_logs[0].arn : null
    event_bus = var.create_spoke_event_bus ? aws_cloudwatch_event_bus.spoke_events[0].arn : null
    event_rule = var.forward_eks_events ? aws_cloudwatch_event_rule.forward_eks_events[0].arn : null
  }
}

# Tagging Information
output "tags" {
  description = "Tags applied to resources"
  value = merge(var.default_tags, {
    "EKSDoctor:Account"     = "spoke"
    "EKSDoctor:Region"      = data.aws_region.current.name
    "EKSDoctor:Environment" = var.environment
    "EKSDoctor:Version"     = var.solution_version
  })
}
