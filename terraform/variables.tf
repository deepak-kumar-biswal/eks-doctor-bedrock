# Hub Account Configuration
variable "hub_account_id" {
  description = "AWS Account ID for the hub account (AI control plane)"
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.hub_account_id))
    error_message = "Hub account ID must be a 12-digit number."
  }
}

# Spoke Account Configuration
variable "spoke_accounts" {
  description = "List of spoke account IDs (up to 5 accounts)"
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.spoke_accounts) <= 5
    error_message = "Maximum of 5 spoke accounts supported."
  }
  validation {
    condition = alltrue([
      for account in var.spoke_accounts : can(regex("^[0-9]{12}$", account))
    ])
    error_message = "All spoke account IDs must be 12-digit numbers."
  }
}

# Regional Configuration  
variable "regions" {
  description = "List of AWS regions to deploy to"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
  validation {
    condition     = length(var.regions) >= 1 && length(var.regions) <= 5
    error_message = "Must specify between 1 and 5 regions."
  }
}

variable "primary_region" {
  description = "Primary region for global resources"
  type        = string
  default     = "us-east-1"
}

# Security Configuration
variable "external_id" {
  description = "External ID for cross-account IAM trust relationships"
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.external_id) >= 16
    error_message = "External ID must be at least 16 characters for security."
  }
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 7
  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

# Resource Naming
variable "project_name" {
  description = "Project name prefix for resources"
  type        = string
  default     = "eks-doctor"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*$", var.project_name))
    error_message = "Project name must start with a letter and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# Networking Configuration
variable "vpc_cidr" {
  description = "CIDR block for Lambda VPC (if using private endpoints)"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "private_subnets" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
  validation {
    condition = alltrue([
      for subnet in var.private_subnets : can(cidrhost(subnet, 0))
    ])
    error_message = "All private subnets must be valid IPv4 CIDR blocks."
  }
}

# Lambda Configuration
variable "lambda_runtime" {
  description = "Lambda runtime version"
  type        = string
  default     = "python3.12"
  validation {
    condition     = contains(["python3.11", "python3.12"], var.lambda_runtime)
    error_message = "Lambda runtime must be python3.11 or python3.12."
  }
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
  validation {
    condition     = var.lambda_timeout >= 30 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 30 and 900 seconds."
  }
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency for Lambda functions"
  type        = number
  default     = 10
  validation {
    condition     = var.lambda_reserved_concurrency >= 1 && var.lambda_reserved_concurrency <= 100
    error_message = "Reserved concurrency must be between 1 and 100."
  }
}

# Bedrock Configuration
variable "bedrock_model_id" {
  description = "Bedrock foundation model ID"
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}

variable "bedrock_embedding_model_id" {
  description = "Bedrock embedding model ID for Knowledge Base"
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "bedrock_guardrail_name" {
  description = "Name for Bedrock guardrail"
  type        = string
  default     = "eks-doctor-guardrail"
}

variable "bedrock_knowledge_base_name" {
  description = "Name for Bedrock Knowledge Base"
  type        = string
  default     = "EKSDoctorKB"
}

# Step Functions Configuration
variable "step_functions_log_level" {
  description = "Step Functions log level (ALL, ERROR, FATAL, OFF)"
  type        = string
  default     = "ERROR"
  validation {
    condition     = contains(["ALL", "ERROR", "FATAL", "OFF"], var.step_functions_log_level)
    error_message = "Step Functions log level must be one of: ALL, ERROR, FATAL, OFF."
  }
}

# Monitoring Configuration
variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 14
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.cloudwatch_log_retention_days)
    error_message = "CloudWatch log retention must be a valid retention period."
  }
}

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray tracing"
  type        = bool
  default     = true
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring with custom metrics"
  type        = bool
  default     = true
}

# Notification Configuration
variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "notification_email" {
  description = "Email address for critical notifications"
  type        = string
  default     = ""
  validation {
    condition     = var.notification_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address or empty string."
  }
}

# Security and Compliance
variable "enable_guardduty_integration" {
  description = "Enable GuardDuty integration for security monitoring"
  type        = bool
  default     = true
}

variable "enable_config_rules" {
  description = "Enable AWS Config rules for compliance"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub integration"
  type        = bool
  default     = true
}

# Backup and Disaster Recovery
variable "enable_backup" {
  description = "Enable AWS Backup for stateful resources"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 365
    error_message = "Backup retention must be between 1 and 365 days."
  }
}

# Cost Optimization
variable "enable_cost_optimization" {
  description = "Enable cost optimization features"
  type        = bool
  default     = true
}

variable "lambda_architecture" {
  description = "Lambda function architecture (x86_64 or arm64)"
  type        = string
  default     = "arm64"
  validation {
    condition     = contains(["x86_64", "arm64"], var.lambda_architecture)
    error_message = "Lambda architecture must be either x86_64 or arm64."
  }
}

# Development and Testing
variable "enable_development_features" {
  description = "Enable development and debugging features"
  type        = bool
  default     = false
}

variable "allowed_debug_ips" {
  description = "IP addresses allowed for debugging access"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.allowed_debug_ips : can(cidrhost(ip, 0))
    ])
    error_message = "All debug IPs must be valid IPv4 CIDR blocks."
  }
}

# Tags
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "eks-doctor"
    Terraform   = "true"
    Environment = "prod"
    Owner       = "devops-team"
  }
}
