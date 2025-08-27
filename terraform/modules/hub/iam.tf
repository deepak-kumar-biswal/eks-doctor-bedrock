# IAM Roles and Policies for Hub Account

# Lambda Execution Role
resource "aws_iam_role" "lambda_execution" {
  name = var.iam_roles.hub.lambda_execution
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = merge(var.common_tags, {
    Name = var.iam_roles.hub.lambda_execution
    Type = "lambda-execution-role"
  })
}

# Lambda Execution Policy
resource "aws_iam_role_policy" "lambda_execution" {
  name = "${var.iam_roles.hub.lambda_execution}-policy"
  role = aws_iam_role.lambda_execution.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:${var.partition}:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*",
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.notifications.arn
      },
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = aws_cloudwatch_event_bus.eks_doctor.arn
      },
      {
        Effect = "Allow"
        Action = [
          "states:SendTaskSuccess",
          "states:SendTaskFailure",
          "states:SendTaskHeartbeat"
        ]
        Resource = "arn:${var.partition}:states:${var.region}:${var.account_id}:stateMachine:${var.name_prefix}-*"
      }
    ]
  })
}

# Cross-Account Assume Role Policy for Lambda
resource "aws_iam_role_policy" "lambda_cross_account" {
  name = "${var.iam_roles.hub.lambda_execution}-cross-account"
  role = aws_iam_role.lambda_execution.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = flatten([
          for account in var.spoke_accounts : [
            "arn:${var.partition}:iam::${account}:role/${var.iam_roles.spoke.readonly}",
            "arn:${var.partition}:iam::${account}:role/${var.iam_roles.spoke.change}"
          ]
        ])
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}

# Bedrock Agent Service Role
resource "aws_iam_role" "bedrock_agent" {
  name = var.iam_roles.hub.bedrock_agent
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = merge(var.common_tags, {
    Name = var.iam_roles.hub.bedrock_agent
    Type = "bedrock-agent-role"
  })
}

# Bedrock Agent Policy
resource "aws_iam_role_policy" "bedrock_agent" {
  name = "${var.iam_roles.hub.bedrock_agent}-policy"
  role = aws_iam_role.bedrock_agent.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:Retrieve",
          "bedrock:RetrieveAndGenerate",
          "bedrock:StartInferenceExperiment",
          "bedrock:ApplyGuardrail"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:${var.partition}:logs:${var.region}:${var.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.knowledge_base.arn,
          "${aws_s3_bucket.knowledge_base.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          for func_name in values(var.lambda_functions) :
          "arn:${var.partition}:lambda:${var.region}:${var.account_id}:function:${func_name}"
        ]
      }
    ]
  })
}

# Step Functions Service Role
resource "aws_iam_role" "step_functions" {
  name = var.iam_roles.hub.step_functions
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = merge(var.common_tags, {
    Name = var.iam_roles.hub.step_functions
    Type = "step-functions-role"
  })
}

# Step Functions Policy
resource "aws_iam_role_policy" "step_functions" {
  name = "${var.iam_roles.hub.step_functions}-policy"
  role = aws_iam_role.step_functions.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          for func_name in values(var.lambda_functions) :
          "arn:${var.partition}:lambda:${var.region}:${var.account_id}:function:${func_name}"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.notifications.arn
      },
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = aws_cloudwatch_event_bus.eks_doctor.arn
      }
    ]
  })
}

# API Gateway Execution Role (for approval workflow)
resource "aws_iam_role" "api_gateway" {
  name = "${var.name_prefix}-api-gateway-execution"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-api-gateway-execution"
    Type = "api-gateway-role"
  })
}

resource "aws_iam_role_policy" "api_gateway" {
  name = "${var.name_prefix}-api-gateway-policy"
  role = aws_iam_role.api_gateway.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "arn:${var.partition}:lambda:${var.region}:${var.account_id}:function:${var.lambda_functions.handle_approval}"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ]
        Resource = "arn:${var.partition}:logs:${var.region}:${var.account_id}:*"
      }
    ]
  })
}
