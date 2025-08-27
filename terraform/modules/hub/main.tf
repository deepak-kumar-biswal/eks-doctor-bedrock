# Hub Module - Main Infrastructure
# This module creates all hub account resources including:
# - IAM roles and policies
# - Lambda functions
# - Step Functions
# - Bedrock Agent and Knowledge Base
# - Monitoring and logging
# - API Gateway for approvals

# KMS Key for Encryption
resource "aws_kms_key" "main" {
  description             = "EKS Doctor encryption key"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${var.partition}:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-kms-key"
  })
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name_prefix}-key"
  target_key_id = aws_kms_key.main.key_id
}

# S3 Buckets
resource "aws_s3_bucket" "knowledge_base" {
  bucket        = var.s3_buckets.knowledge_base
  force_destroy = var.environment != "prod"
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-knowledge-base"
    Type = "knowledge-base"
  })
}

resource "aws_s3_bucket_versioning" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "logs" {
  bucket        = var.s3_buckets.logs
  force_destroy = var.environment != "prod"
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-logs"
    Type = "logs"
  })
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = var.s3_buckets.artifacts
  force_destroy = var.environment != "prod"
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-artifacts"
    Type = "artifacts"
  })
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "lambda_logs" {
  for_each = var.lambda_functions
  
  name              = "/aws/lambda/${each.value}"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = aws_kms_key.main.arn
  
  tags = merge(var.common_tags, {
    Name     = "${var.name_prefix}-lambda-logs-${each.key}"
    Function = each.value
  })
}

resource "aws_cloudwatch_log_group" "step_functions_logs" {
  name              = "/aws/stepfunctions/${var.name_prefix}"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = aws_kms_key.main.arn
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-step-functions-logs"
  })
}

resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = "/aws/bedrock/agent/${var.name_prefix}"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = aws_kms_key.main.arn
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-bedrock-logs"
  })
}

# SNS Topic for Notifications
resource "aws_sns_topic" "notifications" {
  name            = "${var.name_prefix}-notifications"
  kms_master_key_id = aws_kms_key.main.arn
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-notifications"
  })
}

resource "aws_sns_topic_policy" "notifications" {
  arn = aws_sns_topic.notifications.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowServices"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "states.amazonaws.com",
            "events.amazonaws.com"
          ]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.notifications.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })
}

# SNS Topic Subscription for Email (if configured)
resource "aws_sns_topic_subscription" "email" {
  count = var.notification_email != "" ? 1 : 0
  
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# EventBridge Custom Bus for EKS Doctor Events
resource "aws_cloudwatch_event_bus" "eks_doctor" {
  name = "${var.name_prefix}-events"
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-event-bus"
  })
}

# IAM Roles will be created in separate files
# Lambda functions will be created in separate files  
# Step Functions will be created in separate files
# Bedrock resources will be created in separate files
