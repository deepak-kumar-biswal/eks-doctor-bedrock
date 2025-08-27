# API Gateway Configuration for EKS Doctor Approval Workflow

# API Gateway for approval callbacks
resource "aws_api_gateway_rest_api" "approval_api" {
  name        = "${local.name_prefix}-approval-api"
  description = "EKS Doctor approval workflow API"
  
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-approval-api"
    "Component" = "api-gateway"
  })
}

# API Gateway deployment
resource "aws_api_gateway_deployment" "approval_api" {
  depends_on = [
    aws_api_gateway_method.approval_callback_post,
    aws_api_gateway_method.approval_callback_get,
    aws_api_gateway_method.approval_status_get,
    aws_api_gateway_integration.approval_callback_post,
    aws_api_gateway_integration.approval_callback_get,
    aws_api_gateway_integration.approval_status_get,
  ]
  
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.approval.id,
      aws_api_gateway_resource.status.id,
      aws_api_gateway_method.approval_callback_post.id,
      aws_api_gateway_method.approval_callback_get.id,
      aws_api_gateway_method.approval_status_get.id,
      aws_api_gateway_integration.approval_callback_post.id,
      aws_api_gateway_integration.approval_callback_get.id,
      aws_api_gateway_integration.approval_status_get.id,
    ]))
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "approval_api" {
  deployment_id = aws_api_gateway_deployment.approval_api.id
  rest_api_id   = aws_api_gateway_rest_api.approval_api.id
  stage_name    = var.environment
  
  xray_tracing_enabled = var.enable_xray_tracing
  
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_access_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      error          = "$context.error.message"
      errorType      = "$context.error.messageString"
    })
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-approval-api-${var.environment}"
    "Component" = "api-gateway-stage"
  })
}

# Custom domain (optional)
resource "aws_api_gateway_domain_name" "approval_api" {
  count           = var.api_domain_name != null ? 1 : 0
  domain_name     = var.api_domain_name
  certificate_arn = var.api_certificate_arn
  
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  
  tags = merge(var.default_tags, {
    "Name"      = var.api_domain_name
    "Component" = "api-gateway-domain"
  })
}

resource "aws_api_gateway_base_path_mapping" "approval_api" {
  count       = var.api_domain_name != null ? 1 : 0
  api_id      = aws_api_gateway_rest_api.approval_api.id
  stage_name  = aws_api_gateway_stage.approval_api.stage_name
  domain_name = aws_api_gateway_domain_name.approval_api[0].domain_name
  base_path   = "approval"
}

# API Gateway resources
resource "aws_api_gateway_resource" "approval" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  parent_id   = aws_api_gateway_rest_api.approval_api.root_resource_id
  path_part   = "approval"
}

resource "aws_api_gateway_resource" "status" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  parent_id   = aws_api_gateway_rest_api.approval_api.root_resource_id
  path_part   = "status"
}

# Health check resource
resource "aws_api_gateway_resource" "health" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  parent_id   = aws_api_gateway_rest_api.approval_api.root_resource_id
  path_part   = "health"
}

# CORS support
resource "aws_api_gateway_method" "approval_options" {
  rest_api_id   = aws_api_gateway_rest_api.approval_api.id
  resource_id   = aws_api_gateway_resource.approval.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "approval_options" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  resource_id = aws_api_gateway_resource.approval.id
  http_method = aws_api_gateway_method.approval_options.http_method
  
  type = "MOCK"
  
  request_templates = {
    "application/json" = jsonencode({
      statusCode = 200
    })
  }
}

resource "aws_api_gateway_method_response" "approval_options" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  resource_id = aws_api_gateway_resource.approval.id
  http_method = aws_api_gateway_method.approval_options.http_method
  status_code = "200"
  
  response_headers = {
    "Access-Control-Allow-Headers" = true
    "Access-Control-Allow-Methods" = true
    "Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "approval_options" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  resource_id = aws_api_gateway_resource.approval.id
  http_method = aws_api_gateway_method.approval_options.http_method
  status_code = "200"
  
  response_headers = {
    "Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "Access-Control-Allow-Methods" = "'GET,POST,PUT,DELETE,OPTIONS'"
    "Access-Control-Allow-Origin"  = "'*'"
  }
}

# Approval callback methods
resource "aws_api_gateway_method" "approval_callback_post" {
  rest_api_id   = aws_api_gateway_rest_api.approval_api.id
  resource_id   = aws_api_gateway_resource.approval.id
  http_method   = "POST"
  authorization = "NONE"  # Using query parameters for security
  
  request_parameters = {
    "method.request.querystring.token"  = true
    "method.request.querystring.action" = true
  }
  
  request_validator_id = aws_api_gateway_request_validator.approval_validator.id
}

resource "aws_api_gateway_method" "approval_callback_get" {
  rest_api_id   = aws_api_gateway_rest_api.approval_api.id
  resource_id   = aws_api_gateway_resource.approval.id
  http_method   = "GET"
  authorization = "NONE"
  
  request_parameters = {
    "method.request.querystring.token"  = true
    "method.request.querystring.action" = true
  }
  
  request_validator_id = aws_api_gateway_request_validator.approval_validator.id
}

# Approval status method
resource "aws_api_gateway_method" "approval_status_get" {
  rest_api_id   = aws_api_gateway_rest_api.approval_api.id
  resource_id   = aws_api_gateway_resource.status.id
  http_method   = "GET"
  authorization = "NONE"
  
  request_parameters = {
    "method.request.querystring.request_id" = true
  }
}

# Health check method
resource "aws_api_gateway_method" "health_get" {
  rest_api_id   = aws_api_gateway_rest_api.approval_api.id
  resource_id   = aws_api_gateway_resource.health.id
  http_method   = "GET"
  authorization = "NONE"
}

# Request validator
resource "aws_api_gateway_request_validator" "approval_validator" {
  name                        = "${local.name_prefix}-approval-validator"
  rest_api_id                = aws_api_gateway_rest_api.approval_api.id
  validate_request_body       = false
  validate_request_parameters = true
}

# Lambda integrations
resource "aws_api_gateway_integration" "approval_callback_post" {
  rest_api_id             = aws_api_gateway_rest_api.approval_api.id
  resource_id             = aws_api_gateway_resource.approval.id
  http_method             = aws_api_gateway_method.approval_callback_post.http_method
  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = aws_lambda_function.approval_callback.invoke_arn
}

resource "aws_api_gateway_integration" "approval_callback_get" {
  rest_api_id             = aws_api_gateway_rest_api.approval_api.id
  resource_id             = aws_api_gateway_resource.approval.id
  http_method             = aws_api_gateway_method.approval_callback_get.http_method
  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = aws_lambda_function.approval_callback.invoke_arn
}

resource "aws_api_gateway_integration" "approval_status_get" {
  rest_api_id             = aws_api_gateway_rest_api.approval_api.id
  resource_id             = aws_api_gateway_resource.status.id
  http_method             = aws_api_gateway_method.approval_status_get.http_method
  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = aws_lambda_function.approval_status.invoke_arn
}

resource "aws_api_gateway_integration" "health_get" {
  rest_api_id             = aws_api_gateway_rest_api.approval_api.id
  resource_id             = aws_api_gateway_resource.health.id
  http_method             = aws_api_gateway_method.health_get.http_method
  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = aws_lambda_function.health_check.invoke_arn
}

# Method responses
resource "aws_api_gateway_method_response" "approval_callback_200" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  resource_id = aws_api_gateway_resource.approval.id
  http_method = aws_api_gateway_method.approval_callback_post.http_method
  status_code = "200"
  
  response_headers = {
    "Access-Control-Allow-Origin" = true
  }
}

resource "aws_api_gateway_method_response" "approval_callback_400" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  resource_id = aws_api_gateway_resource.approval.id
  http_method = aws_api_gateway_method.approval_callback_post.http_method
  status_code = "400"
  
  response_headers = {
    "Access-Control-Allow-Origin" = true
  }
}

resource "aws_api_gateway_method_response" "approval_callback_500" {
  rest_api_id = aws_api_gateway_rest_api.approval_api.id
  resource_id = aws_api_gateway_resource.approval.id
  http_method = aws_api_gateway_method.approval_callback_post.http_method
  status_code = "500"
  
  response_headers = {
    "Access-Control-Allow-Origin" = true
  }
}

# Lambda permissions for API Gateway
resource "aws_lambda_permission" "approval_callback_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.approval_api.execution_arn}/*/*"
}

resource "aws_lambda_permission" "approval_status_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_status.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.approval_api.execution_arn}/*/*"
}

resource "aws_lambda_permission" "health_check_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health_check.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.approval_api.execution_arn}/*/*"
}

# CloudWatch Log Group for API Gateway access logs
resource "aws_cloudwatch_log_group" "api_gateway_access_logs" {
  name              = "/aws/apigateway/${local.name_prefix}-approval-api"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.enable_encryption ? aws_kms_key.hub_key.arn : null
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-api-gateway-logs"
    "Component" = "api-gateway-logging"
  })
}

# API Gateway account settings (for CloudWatch logging)
resource "aws_api_gateway_account" "approval_api" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_cloudwatch.arn
}

# API Gateway throttling
resource "aws_api_gateway_usage_plan" "approval_api" {
  name         = "${local.name_prefix}-approval-api-plan"
  description  = "Usage plan for EKS Doctor approval API"
  
  api_stages {
    api_id = aws_api_gateway_rest_api.approval_api.id
    stage  = aws_api_gateway_stage.approval_api.stage_name
  }
  
  quota_settings {
    limit  = 10000  # 10,000 requests per period
    period = "DAY"
  }
  
  throttle_settings {
    rate_limit  = 100  # 100 requests per second
    burst_limit = 200  # 200 concurrent requests
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-approval-api-plan"
    "Component" = "api-gateway-usage-plan"
  })
}

# API Key for additional security (optional)
resource "aws_api_gateway_api_key" "approval_api" {
  count = var.create_api_key ? 1 : 0
  
  name        = "${local.name_prefix}-approval-api-key"
  description = "API key for EKS Doctor approval API"
  enabled     = true
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-approval-api-key"
    "Component" = "api-gateway-api-key"
  })
}

resource "aws_api_gateway_usage_plan_key" "approval_api" {
  count = var.create_api_key ? 1 : 0
  
  key_id        = aws_api_gateway_api_key.approval_api[0].id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.approval_api.id
}

# Additional Lambda functions for API Gateway
resource "aws_lambda_function" "approval_status" {
  filename         = data.archive_file.approval_status.output_path
  function_name    = "${local.name_prefix}-approval-status"
  role            = aws_iam_role.lambda.arn
  handler         = "approval_status.lambda_handler"
  runtime         = "python3.12"
  timeout         = 30
  memory_size     = 256
  
  source_code_hash = data.archive_file.approval_status.output_base64sha256
  
  environment {
    variables = {
      LOG_LEVEL                = var.log_level
      POWERTOOLS_SERVICE_NAME  = "eks-doctor-approval-status"
      APPROVAL_REQUESTS_TABLE  = aws_dynamodb_table.approval_requests.name
    }
  }
  
  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-approval-status"
    "Component" = "lambda-function"
    "Purpose"   = "approval-status"
  })
}

resource "aws_lambda_function" "health_check" {
  filename         = data.archive_file.health_check.output_path
  function_name    = "${local.name_prefix}-health-check"
  role            = aws_iam_role.lambda.arn
  handler         = "health_check.lambda_handler"
  runtime         = "python3.12"
  timeout         = 10
  memory_size     = 128
  
  source_code_hash = data.archive_file.health_check.output_base64sha256
  
  environment {
    variables = {
      LOG_LEVEL               = var.log_level
      POWERTOOLS_SERVICE_NAME = "eks-doctor-health-check"
      API_VERSION             = "1.0.0"
    }
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-health-check"
    "Component" = "lambda-function"
    "Purpose"   = "health-check"
  })
}

# Package additional Lambda functions
data "archive_file" "approval_status" {
  type        = "zip"
  output_path = "${path.module}/../../dist/approval_status.zip"
  
  source {
    content = templatefile("${path.module}/../../src/lambda/approval_status.py", {
      # Template variables if needed
    })
    filename = "approval_status.py"
  }
}

data "archive_file" "health_check" {
  type        = "zip"
  output_path = "${path.module}/../../dist/health_check.zip"
  
  source {
    content = templatefile("${path.module}/../../src/lambda/health_check.py", {
      # Template variables if needed
    })
    filename = "health_check.py"
  }
}

# DynamoDB table for approval requests tracking
resource "aws_dynamodb_table" "approval_requests" {
  name           = "${local.name_prefix}-approval-requests"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "request_id"
  
  attribute {
    name = "request_id"
    type = "S"
  }
  
  attribute {
    name = "status"
    type = "S"
  }
  
  attribute {
    name = "created_at"
    type = "S"
  }
  
  global_secondary_index {
    name     = "StatusIndex"
    hash_key = "status"
    range_key = "created_at"
    projection_type = "ALL"
  }
  
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  
  point_in_time_recovery {
    enabled = var.enable_backup
  }
  
  server_side_encryption {
    enabled     = var.enable_encryption
    kms_key_id  = var.enable_encryption ? aws_kms_key.hub_key.arn : null
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-approval-requests"
    "Component" = "dynamodb-table"
    "Purpose"   = "approval-tracking"
  })
}

# CloudWatch Alarms for API Gateway
resource "aws_cloudwatch_metric_alarm" "api_gateway_4xx_errors" {
  alarm_name          = "${local.name_prefix}-api-gateway-4xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "4XXError"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "API Gateway 4XX errors"
  
  dimensions = {
    ApiName = aws_api_gateway_rest_api.approval_api.name
    Stage   = aws_api_gateway_stage.approval_api.stage_name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-api-gateway-4xx-errors"
    "Component" = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "api_gateway_5xx_errors" {
  alarm_name          = "${local.name_prefix}-api-gateway-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "5XXError"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "API Gateway 5XX errors"
  
  dimensions = {
    ApiName = aws_api_gateway_rest_api.approval_api.name
    Stage   = aws_api_gateway_stage.approval_api.stage_name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-api-gateway-5xx-errors"
    "Component" = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "api_gateway_latency" {
  alarm_name          = "${local.name_prefix}-api-gateway-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Latency"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Average"
  threshold           = "5000"  # 5 seconds
  alarm_description   = "API Gateway high latency"
  
  dimensions = {
    ApiName = aws_api_gateway_rest_api.approval_api.name
    Stage   = aws_api_gateway_stage.approval_api.stage_name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-api-gateway-latency"
    "Component" = "cloudwatch-alarm"
  })
}
