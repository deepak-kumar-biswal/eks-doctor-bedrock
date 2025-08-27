# Hub Module Variables
variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "region" {
  description = "AWS Region"
  type        = string
}

variable "partition" {
  description = "AWS Partition"
  type        = string
  default     = "aws"
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "spoke_accounts" {
  description = "List of spoke account IDs"
  type        = list(string)
}

variable "external_id" {
  description = "External ID for cross-account trust"
  type        = string
  sensitive   = true
}

variable "lambda_functions" {
  description = "Map of lambda function names"
  type        = map(string)
}

variable "s3_buckets" {
  description = "S3 bucket configuration"
  type = object({
    knowledge_base = string
    logs          = string
    artifacts     = string
  })
}

variable "iam_roles" {
  description = "IAM role configuration"
  type = object({
    hub = object({
      lambda_execution = string
      bedrock_agent   = string
      step_functions  = string
    })
    spoke = object({
      readonly = string
      change   = string
    })
  })
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 7
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 14
}

variable "notification_email" {
  description = "Email address for notifications"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "lambda_runtime" {
  description = "Lambda runtime version"
  type        = string
  default     = "python3.12"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
}

variable "lambda_architecture" {
  description = "Lambda function architecture"
  type        = string
  default     = "arm64"
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency for Lambda functions"
  type        = number
  default     = 10
}

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray tracing"
  type        = bool
  default     = true
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring"
  type        = bool
  default     = true
}

variable "bedrock_model_id" {
  description = "Bedrock foundation model ID"
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}

variable "bedrock_embedding_model_id" {
  description = "Bedrock embedding model ID"
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "bedrock_guardrail_name" {
  description = "Bedrock guardrail name"
  type        = string
  default     = "eks-doctor-guardrail"
}

variable "bedrock_knowledge_base_name" {
  description = "Bedrock Knowledge Base name"
  type        = string
  default     = "EKSDoctorKB"
}

variable "step_functions_log_level" {
  description = "Step Functions log level"
  type        = string
  default     = "ERROR"
}

variable "enable_development_features" {
  description = "Enable development features"
  type        = bool
  default     = false
}

variable "allowed_debug_ips" {
  description = "IP addresses allowed for debugging"
  type        = list(string)
  default     = []
}
