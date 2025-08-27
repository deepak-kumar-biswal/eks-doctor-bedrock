# Hub Module Outputs
output "kms_key_id" {
  description = "KMS key ID for encryption"
  value       = aws_kms_key.main.id
}

output "kms_key_arn" {
  description = "KMS key ARN for encryption"
  value       = aws_kms_key.main.arn
}

output "s3_buckets" {
  description = "S3 bucket information"
  value = {
    knowledge_base = {
      id   = aws_s3_bucket.knowledge_base.id
      arn  = aws_s3_bucket.knowledge_base.arn
      name = aws_s3_bucket.knowledge_base.bucket
    }
    logs = {
      id   = aws_s3_bucket.logs.id
      arn  = aws_s3_bucket.logs.arn
      name = aws_s3_bucket.logs.bucket
    }
    artifacts = {
      id   = aws_s3_bucket.artifacts.id
      arn  = aws_s3_bucket.artifacts.arn
      name = aws_s3_bucket.artifacts.bucket
    }
  }
}

output "cloudwatch_log_groups" {
  description = "CloudWatch log group information"
  value = {
    lambda_logs        = { for k, v in aws_cloudwatch_log_group.lambda_logs : k => v.arn }
    step_functions_logs = aws_cloudwatch_log_group.step_functions_logs.arn
    bedrock_logs       = aws_cloudwatch_log_group.bedrock_logs.arn
  }
}

output "sns_topic_arn" {
  description = "SNS topic ARN for notifications"
  value       = aws_sns_topic.notifications.arn
}

output "event_bus_name" {
  description = "EventBridge custom bus name"
  value       = aws_cloudwatch_event_bus.eks_doctor.name
}

output "event_bus_arn" {
  description = "EventBridge custom bus ARN"
  value       = aws_cloudwatch_event_bus.eks_doctor.arn
}
