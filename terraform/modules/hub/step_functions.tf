# Step Functions Workflow Configuration

# Step Functions for EKS Doctor Approval Workflow
resource "aws_sfn_state_machine" "eks_doctor_approval_workflow" {
  name     = "${local.name_prefix}-approval-workflow"
  role_arn = aws_iam_role.step_functions.arn
  
  definition = jsonencode({
    Comment = "EKS Doctor approval-based remediation workflow"
    StartAt = "ValidateInput"
    
    States = {
      
      # Input validation step
      ValidateInput = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.input_validator.arn
          Payload = {
            "operation.$" = "$.operation"
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
          }
        }
        ResultPath = "$.validation"
        Next = "CheckOperationType"
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "ValidationFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      # Determine operation type
      CheckOperationType = {
        Type = "Choice"
        Choices = [
          {
            Variable = "$.operation"
            StringEquals = "health_snapshot"
            Next = "ExecuteHealthSnapshot"
          },
          {
            Variable = "$.operation"
            StringEquals = "network_triage"
            Next = "ExecuteNetworkTriage"
          },
          {
            Variable = "$.operation"
            StringEquals = "drain_node"
            Next = "RequestApprovalForDrainNode"
          },
          {
            Variable = "$.operation"
            StringEquals = "scale_nodegroup"
            Next = "RequestApprovalForScaling"
          },
          {
            Variable = "$.operation"
            StringEquals = "restart_workload"
            Next = "RequestApprovalForRestart"
          }
        ]
        Default = "UnsupportedOperation"
      }
      
      # Non-destructive operations (no approval needed)
      ExecuteHealthSnapshot = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.health_snapshot.arn
          Payload = {
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
          }
        }
        ResultPath = "$.result"
        Next = "SuccessResponse"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts = 3
            BackoffRate = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "OperationFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      ExecuteNetworkTriage = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.network_triage.arn
          Payload = {
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
          }
        }
        ResultPath = "$.result"
        Next = "SuccessResponse"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts = 3
            BackoffRate = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "OperationFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      # Approval-required operations
      RequestApprovalForDrainNode = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.send_approval.arn
          Payload = {
            "taskToken.$" = "$$.Task.Token"
            "approval_request" = {
              "operation" = "drain_node"
              "cluster.$" = "$.cluster"
              "region.$" = "$.region"
              "account.$" = "$.account"
              "reason" = "Node maintenance or troubleshooting requires draining"
              "details.$" = "$.details"
              "request_id.$" = "$$.Execution.Name"
            }
          }
        }
        ResultPath = "$.approval_request"
        Next = "WaitForApprovalDrainNode"
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "ApprovalRequestFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      WaitForApprovalDrainNode = {
        Type = "Task"
        Resource = "arn:aws:states:::aws-sdk:stepfunctions:sendTaskSuccess"
        Parameters = {
          "TaskToken.$" = "$$.Task.Token"
        }
        TimeoutSeconds = 3600  # 1 hour timeout
        Next = "ExecuteDrainNode"
        Catch = [
          {
            ErrorEquals = ["States.Timeout", "States.TaskFailed"]
            Next = "ApprovalTimeout"
            ResultPath = "$.error"
          },
          {
            ErrorEquals = ["ApprovalRejected"]
            Next = "ApprovalRejected"
            ResultPath = "$.error"
          }
        ]
      }
      
      ExecuteDrainNode = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.drain_node.arn
          Payload = {
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
            "approved" = true
            "approval_data.$" = "$.approval_data"
          }
        }
        ResultPath = "$.result"
        Next = "NotifyOperationSuccess"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts = 2
            BackoffRate = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "OperationFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      RequestApprovalForScaling = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.send_approval.arn
          Payload = {
            "taskToken.$" = "$$.Task.Token"
            "approval_request" = {
              "operation" = "scale_nodegroup"
              "cluster.$" = "$.cluster"
              "region.$" = "$.region"
              "account.$" = "$.account"
              "reason" = "NodeGroup scaling required for capacity adjustment"
              "details.$" = "$.details"
              "request_id.$" = "$$.Execution.Name"
            }
          }
        }
        ResultPath = "$.approval_request"
        Next = "WaitForApprovalScaling"
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "ApprovalRequestFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      WaitForApprovalScaling = {
        Type = "Task"
        Resource = "arn:aws:states:::aws-sdk:stepfunctions:sendTaskSuccess"
        Parameters = {
          "TaskToken.$" = "$$.Task.Token"
        }
        TimeoutSeconds = 3600
        Next = "ExecuteScaleNodeGroup"
        Catch = [
          {
            ErrorEquals = ["States.Timeout", "States.TaskFailed"]
            Next = "ApprovalTimeout"
            ResultPath = "$.error"
          },
          {
            ErrorEquals = ["ApprovalRejected"]
            Next = "ApprovalRejected"
            ResultPath = "$.error"
          }
        ]
      }
      
      ExecuteScaleNodeGroup = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.scale_nodegroup.arn
          Payload = {
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
            "approved" = true
            "approval_data.$" = "$.approval_data"
          }
        }
        ResultPath = "$.result"
        Next = "NotifyOperationSuccess"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts = 2
            BackoffRate = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "OperationFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      RequestApprovalForRestart = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.send_approval.arn
          Payload = {
            "taskToken.$" = "$$.Task.Token"
            "approval_request" = {
              "operation" = "restart_workload"
              "cluster.$" = "$.cluster"
              "region.$" = "$.region"
              "account.$" = "$.account"
              "reason" = "Workload restart required for troubleshooting or recovery"
              "details.$" = "$.details"
              "request_id.$" = "$$.Execution.Name"
            }
          }
        }
        ResultPath = "$.approval_request"
        Next = "WaitForApprovalRestart"
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "ApprovalRequestFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      WaitForApprovalRestart = {
        Type = "Task"
        Resource = "arn:aws:states:::aws-sdk:stepfunctions:sendTaskSuccess"
        Parameters = {
          "TaskToken.$" = "$$.Task.Token"
        }
        TimeoutSeconds = 3600
        Next = "ExecuteRestartWorkload"
        Catch = [
          {
            ErrorEquals = ["States.Timeout", "States.TaskFailed"]
            Next = "ApprovalTimeout"
            ResultPath = "$.error"
          },
          {
            ErrorEquals = ["ApprovalRejected"]
            Next = "ApprovalRejected"
            ResultPath = "$.error"
          }
        ]
      }
      
      ExecuteRestartWorkload = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.restart_workload.arn
          Payload = {
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
            "approved" = true
            "approval_data.$" = "$.approval_data"
          }
        }
        ResultPath = "$.result"
        Next = "NotifyOperationSuccess"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 2
            MaxAttempts = 2
            BackoffRate = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "OperationFailed"
            ResultPath = "$.error"
          }
        ]
      }
      
      # Success notification
      NotifyOperationSuccess = {
        Type = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.notifications.arn
          Subject = "EKS Doctor Operation Completed Successfully"
          Message = {
            "execution_id.$" = "$$.Execution.Name"
            "operation.$" = "$.operation"
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "status" = "success"
            "timestamp.$" = "$$.State.EnteredTime"
            "result.$" = "$.result"
          }
        }
        Next = "SuccessResponse"
      }
      
      # Success response
      SuccessResponse = {
        Type = "Pass"
        Parameters = {
          "status" = "success"
          "execution_id.$" = "$$.Execution.Name"
          "operation.$" = "$.operation"
          "cluster.$" = "$.cluster"
          "timestamp.$" = "$$.State.EnteredTime"
          "result.$" = "$.result"
        }
        End = true
      }
      
      # Error states
      ValidationFailed = {
        Type = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.notifications.arn
          Subject = "EKS Doctor Validation Failed"
          Message = {
            "execution_id.$" = "$$.Execution.Name"
            "status" = "validation_failed"
            "error.$" = "$.error"
            "timestamp.$" = "$$.State.EnteredTime"
          }
        }
        Next = "FailResponse"
      }
      
      ApprovalRequestFailed = {
        Type = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.notifications.arn
          Subject = "EKS Doctor Approval Request Failed"
          Message = {
            "execution_id.$" = "$$.Execution.Name"
            "status" = "approval_request_failed"
            "error.$" = "$.error"
            "timestamp.$" = "$$.State.EnteredTime"
          }
        }
        Next = "FailResponse"
      }
      
      ApprovalTimeout = {
        Type = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.notifications.arn
          Subject = "EKS Doctor Approval Timeout"
          Message = {
            "execution_id.$" = "$$.Execution.Name"
            "status" = "approval_timeout"
            "message" = "Operation approval timed out after 1 hour"
            "timestamp.$" = "$$.State.EnteredTime"
          }
        }
        Next = "FailResponse"
      }
      
      ApprovalRejected = {
        Type = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.notifications.arn
          Subject = "EKS Doctor Operation Rejected"
          Message = {
            "execution_id.$" = "$$.Execution.Name"
            "status" = "approval_rejected"
            "error.$" = "$.error"
            "timestamp.$" = "$$.State.EnteredTime"
          }
        }
        Next = "FailResponse"
      }
      
      OperationFailed = {
        Type = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.notifications.arn
          Subject = "EKS Doctor Operation Failed"
          Message = {
            "execution_id.$" = "$$.Execution.Name"
            "status" = "operation_failed"
            "operation.$" = "$.operation"
            "error.$" = "$.error"
            "timestamp.$" = "$$.State.EnteredTime"
          }
        }
        Next = "FailResponse"
      }
      
      UnsupportedOperation = {
        Type = "Fail"
        Error = "UnsupportedOperation"
        Cause = "The specified operation is not supported by this workflow"
      }
      
      FailResponse = {
        Type = "Pass"
        Parameters = {
          "status" = "failed"
          "execution_id.$" = "$$.Execution.Name"
          "error.$" = "$.error"
          "timestamp.$" = "$$.State.EnteredTime"
        }
        End = true
      }
    }
  })
  
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions.arn}:*"
    include_execution_data = true
    level                 = "ALL"
  }
  
  tracing_configuration {
    enabled = var.enable_xray_tracing
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-approval-workflow"
    "Component" = "step-functions"
  })
}

# Express workflow for high-throughput, non-approval operations
resource "aws_sfn_state_machine" "eks_doctor_express_workflow" {
  name     = "${local.name_prefix}-express-workflow"
  role_arn = aws_iam_role.step_functions.arn
  type     = "EXPRESS"
  
  definition = jsonencode({
    Comment = "EKS Doctor express workflow for diagnostic operations"
    StartAt = "ValidateInput"
    
    States = {
      ValidateInput = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.input_validator.arn
          Payload = {
            "operation.$" = "$.operation"
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
          }
        }
        ResultPath = "$.validation"
        Next = "ExecuteOperation"
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next = "FailResponse"
            ResultPath = "$.error"
          }
        ]
      }
      
      ExecuteOperation = {
        Type = "Choice"
        Choices = [
          {
            Variable = "$.operation"
            StringEquals = "health_snapshot"
            Next = "ExecuteHealthSnapshot"
          },
          {
            Variable = "$.operation"
            StringEquals = "network_triage"
            Next = "ExecuteNetworkTriage"
          }
        ]
        Default = "UnsupportedOperation"
      }
      
      ExecuteHealthSnapshot = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.health_snapshot.arn
          Payload = {
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
          }
        }
        ResultPath = "$.result"
        Next = "SuccessResponse"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 1
            MaxAttempts = 2
            BackoffRate = 2.0
          }
        ]
      }
      
      ExecuteNetworkTriage = {
        Type = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.network_triage.arn
          Payload = {
            "cluster.$" = "$.cluster"
            "region.$" = "$.region"
            "account.$" = "$.account"
            "details.$" = "$.details"
          }
        }
        ResultPath = "$.result"
        Next = "SuccessResponse"
        Retry = [
          {
            ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 1
            MaxAttempts = 2
            BackoffRate = 2.0
          }
        ]
      }
      
      SuccessResponse = {
        Type = "Pass"
        Parameters = {
          "status" = "success"
          "execution_id.$" = "$$.Execution.Name"
          "operation.$" = "$.operation"
          "cluster.$" = "$.cluster"
          "result.$" = "$.result"
        }
        End = true
      }
      
      UnsupportedOperation = {
        Type = "Fail"
        Error = "UnsupportedOperation"
        Cause = "The specified operation is not supported by the express workflow"
      }
      
      FailResponse = {
        Type = "Pass"
        Parameters = {
          "status" = "failed"
          "execution_id.$" = "$$.Execution.Name"
          "error.$" = "$.error"
        }
        End = true
      }
    }
  })
  
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions_express.arn}:*"
    include_execution_data = true
    level                 = "ERROR"
  }
  
  tracing_configuration {
    enabled = var.enable_xray_tracing
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-express-workflow"
    "Component" = "step-functions-express"
  })
}

# CloudWatch Log Groups for Step Functions
resource "aws_cloudwatch_log_group" "step_functions" {
  name              = "/aws/stepfunctions/${local.name_prefix}-approval-workflow"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.enable_encryption ? aws_kms_key.hub_key.arn : null
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-step-functions-logs"
    "Component" = "step-functions-logging"
  })
}

resource "aws_cloudwatch_log_group" "step_functions_express" {
  name              = "/aws/stepfunctions/${local.name_prefix}-express-workflow"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.enable_encryption ? aws_kms_key.hub_key.arn : null
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-step-functions-express-logs"
    "Component" = "step-functions-express-logging"
  })
}

# Input validator Lambda function
resource "aws_lambda_function" "input_validator" {
  filename         = data.archive_file.input_validator.output_path
  function_name    = "${local.name_prefix}-input-validator"
  role            = aws_iam_role.lambda.arn
  handler         = "input_validator.lambda_handler"
  runtime         = "python3.12"
  timeout         = 30
  memory_size     = 256
  
  source_code_hash = data.archive_file.input_validator.output_base64sha256
  
  environment {
    variables = {
      LOG_LEVEL           = var.log_level
      POWERTOOLS_SERVICE_NAME = "eks-doctor-input-validator"
      
      # Validation settings
      MAX_CLUSTER_NAME_LENGTH = "100"
      ALLOWED_REGIONS = jsonencode(var.allowed_regions)
      ALLOWED_OPERATIONS = jsonencode([
        "health_snapshot",
        "network_triage", 
        "drain_node",
        "scale_nodegroup",
        "restart_workload"
      ])
    }
  }
  
  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-input-validator"
    "Component" = "lambda-function"
    "Purpose"   = "input-validation"
  })
}

# Package input validator Lambda function
data "archive_file" "input_validator" {
  type        = "zip"
  output_path = "${path.module}/../../dist/input_validator.zip"
  
  source {
    content = templatefile("${path.module}/../../src/lambda/input_validator.py", {
      # Template variables if needed
    })
    filename = "input_validator.py"
  }
}

# EventBridge rule to trigger workflows
resource "aws_cloudwatch_event_rule" "eks_doctor_trigger" {
  name        = "${local.name_prefix}-workflow-trigger"
  description = "Trigger EKS Doctor workflows from external events"
  
  event_pattern = jsonencode({
    source      = ["aws.eks", "custom.eks-doctor"]
    detail-type = [
      "EKS Doctor Operation Request",
      "EKS Cluster State Change",
      "EKS Nodegroup State Change"
    ]
  })
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-workflow-trigger"
    "Component" = "eventbridge-rule"
  })
}

resource "aws_cloudwatch_event_target" "step_functions_target" {
  rule      = aws_cloudwatch_event_rule.eks_doctor_trigger.name
  target_id = "StepFunctionsTarget"
  arn       = aws_sfn_state_machine.eks_doctor_approval_workflow.arn
  role_arn  = aws_iam_role.eventbridge.arn
  
  input_transformer {
    input_paths = {
      operation = "$.detail.operation"
      cluster   = "$.detail.cluster"
      region    = "$.detail.region"
      account   = "$.detail.account"
      details   = "$.detail"
    }
    
    input_template = jsonencode({
      operation = "<operation>"
      cluster   = "<cluster>"
      region    = "<region>"
      account   = "<account>"
      details   = "<details>"
      source    = "eventbridge"
      timestamp = "$AWS_EVENT_TIMESTAMP"
    })
  }
}

# CloudWatch Alarms for Step Functions monitoring
resource "aws_cloudwatch_metric_alarm" "step_functions_failed_executions" {
  alarm_name          = "${local.name_prefix}-step-functions-failed-executions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ExecutionsFailed"
  namespace           = "AWS/States"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Step Functions execution failures"
  
  dimensions = {
    StateMachineArn = aws_sfn_state_machine.eks_doctor_approval_workflow.arn
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-step-functions-failed-executions"
    "Component" = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "step_functions_execution_time" {
  alarm_name          = "${local.name_prefix}-step-functions-execution-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ExecutionTime"
  namespace           = "AWS/States"
  period              = "300"
  statistic           = "Average"
  threshold           = "1800000" # 30 minutes in milliseconds
  alarm_description   = "Step Functions execution time too long"
  
  dimensions = {
    StateMachineArn = aws_sfn_state_machine.eks_doctor_approval_workflow.arn
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.name_prefix}-step-functions-execution-time"
    "Component" = "cloudwatch-alarm"
  })
}
