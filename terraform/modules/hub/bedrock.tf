"""
EKS Doctor - Bedrock Agent Configuration
Production-grade Bedrock Agent setup for EKS cluster management.
"""

# Bedrock Agent Configuration
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Local values for Bedrock configuration
locals {
  agent_name = "${var.project_name}-${var.environment}-agent"
  
  # Knowledge base configuration
  knowledge_base_name = "${var.project_name}-${var.environment}-knowledge-base"
  
  # Agent instructions - comprehensive EKS troubleshooting guidance
  agent_instructions = <<-EOT
    You are EKS Doctor, an expert AWS EKS (Elastic Kubernetes Service) troubleshooting and remediation agent. 
    
    Your primary responsibilities include:
    
    1. **Cluster Health Assessment**: Analyze EKS cluster health, node status, pod conditions, and system components.
    
    2. **Issue Diagnosis**: Identify root causes of EKS-related issues including:
       - Node problems (NotReady, resource exhaustion, network issues)
       - Pod failures (CrashLoopBackOff, ImagePullBackOff, OOMKilled)
       - Service connectivity issues
       - Ingress and load balancer problems
       - Persistent volume and storage issues
       - RBAC and security configuration problems
    
    3. **Automated Remediation**: Execute approved remediation actions such as:
       - Draining and replacing unhealthy nodes
       - Scaling nodegroups up or down
       - Restarting failed workloads
       - Updating EKS add-ons
       - Applying configuration fixes
    
    4. **Safety and Approval**: Always request approval for potentially disruptive operations. Provide clear impact assessment and rollback procedures.
    
    5. **Cross-Account Operations**: Work across multiple AWS accounts using proper cross-account roles and security controls.
    
    When responding:
    - Always provide step-by-step analysis
    - Include specific commands or API calls used for diagnosis
    - Explain the impact of any proposed changes
    - Suggest monitoring and validation steps
    - Reference Kubernetes and AWS best practices
    
    Use the available Lambda functions to:
    - health_snapshot: Get comprehensive cluster health information
    - network_triage: Analyze network connectivity issues
    - drain_node: Safely drain nodes for maintenance
    - scale_nodegroup: Scale nodegroups up or down
    - restart_workload: Restart deployments, statefulsets, or daemonsets
    - send_approval: Request approval for disruptive operations
    
    Always prioritize cluster stability and workload availability.
  EOT
  
  # Guardrail topics to prevent harmful operations
  denied_topics = [
    "delete-cluster",
    "delete-nodegroup", 
    "delete-persistent-volume",
    "modify-security-groups",
    "delete-load-balancer",
    "modify-iam-roles"
  ]
  
  # Guardrail blocked inputs
  blocked_inputs = [
    "DELETE FROM",
    "DROP TABLE",
    "rm -rf /",
    "kubectl delete cluster",
    "aws eks delete-cluster",
    "aws iam delete-role"
  ]
}

# S3 bucket for Bedrock Agent artifacts
resource "aws_s3_bucket" "bedrock_agent_artifacts" {
  bucket = "${var.project_name}-${var.environment}-bedrock-agent-${random_id.bucket_suffix.hex}"
  
  tags = merge(var.default_tags, {
    "Name"      = "${var.project_name}-${var.environment}-bedrock-agent-artifacts"
    "Component" = "bedrock-agent"
    "Purpose"   = "agent-artifacts"
  })
}

resource "aws_s3_bucket_versioning" "bedrock_agent_artifacts" {
  bucket = aws_s3_bucket.bedrock_agent_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "bedrock_agent_artifacts" {
  bucket = aws_s3_bucket.bedrock_agent_artifacts.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.bedrock_agent.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bedrock_agent_artifacts" {
  bucket = aws_s3_bucket.bedrock_agent_artifacts.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket for Knowledge Base documents
resource "aws_s3_bucket" "knowledge_base" {
  bucket = "${var.project_name}-${var.environment}-knowledge-base-${random_id.bucket_suffix.hex}"
  
  tags = merge(var.default_tags, {
    "Name"      = "${var.project_name}-${var.environment}-knowledge-base"
    "Component" = "bedrock-knowledge-base"
    "Purpose"   = "knowledge-storage"
  })
}

resource "aws_s3_bucket_versioning" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.bedrock_agent.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_public_access_block" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload knowledge base documents
resource "aws_s3_object" "eks_troubleshooting_guide" {
  bucket = aws_s3_bucket.knowledge_base.id
  key    = "eks-troubleshooting-guide.md"
  
  content = file("${path.module}/../../../docs/eks-troubleshooting-guide.md")
  
  content_type = "text/markdown"
  
  tags = {
    "Name"        = "EKS Troubleshooting Guide"
    "Type"        = "documentation"
    "Category"    = "troubleshooting"
  }
}

resource "aws_s3_object" "kubernetes_best_practices" {
  bucket = aws_s3_bucket.knowledge_base.id
  key    = "kubernetes-best-practices.md"
  
  content = file("${path.module}/../../../docs/kubernetes-best-practices.md")
  
  content_type = "text/markdown"
  
  tags = {
    "Name"        = "Kubernetes Best Practices"
    "Type"        = "documentation"
    "Category"    = "best-practices"
  }
}

# KMS key for Bedrock Agent encryption
resource "aws_kms_key" "bedrock_agent" {
  description = "EKS Doctor Bedrock Agent encryption key"
  
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
        Sid    = "Allow Bedrock Service"
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(var.default_tags, {
    "Name" = "${var.project_name}-${var.environment}-bedrock-agent-key"
  })
}

resource "aws_kms_alias" "bedrock_agent" {
  name          = "alias/${var.project_name}-${var.environment}-bedrock-agent"
  target_key_id = aws_kms_key.bedrock_agent.key_id
}

# Bedrock Knowledge Base
resource "aws_bedrockagent_knowledge_base" "eks_doctor" {
  name     = local.knowledge_base_name
  role_arn = aws_iam_role.knowledge_base.arn
  
  description = "EKS Doctor knowledge base containing troubleshooting guides, best practices, and operational procedures"
  
  knowledge_base_configuration {
    vector_knowledge_base_configuration {
      embedding_model_arn = "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/amazon.titan-embed-text-v1"
    }
    type = "VECTOR"
  }
  
  storage_configuration {
    type = "OPENSEARCH_SERVERLESS"
    opensearch_serverless_configuration {
      collection_arn    = aws_opensearchserverless_collection.knowledge_base.arn
      vector_index_name = "eks-doctor-index"
      field_mapping {
        vector_field   = "vector"
        text_field     = "text"
        metadata_field = "metadata"
      }
    }
  }
  
  tags = merge(var.default_tags, {
    "Name"      = local.knowledge_base_name
    "Component" = "bedrock-knowledge-base"
  })
}

# Data source for knowledge base
resource "aws_bedrockagent_data_source" "s3_documents" {
  knowledge_base_id = aws_bedrockagent_knowledge_base.eks_doctor.id
  name             = "eks-doctor-s3-docs"
  
  description = "S3 bucket containing EKS troubleshooting documentation"
  
  data_source_configuration {
    type = "S3"
    s3_configuration {
      bucket_arn = aws_s3_bucket.knowledge_base.arn
      inclusion_prefixes = ["*.md", "*.txt", "*.json"]
    }
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "eks-doctor-s3-docs"
    "Component" = "bedrock-data-source"
  })
}

# OpenSearch Serverless collection for vector storage
resource "aws_opensearchserverless_collection" "knowledge_base" {
  name = "${var.project_name}-${var.environment}-kb"
  type = "VECTORSEARCH"
  
  description = "OpenSearch Serverless collection for EKS Doctor knowledge base"
  
  tags = merge(var.default_tags, {
    "Name"      = "${var.project_name}-${var.environment}-kb"
    "Component" = "opensearch-serverless"
  })
}

# OpenSearch Serverless security policy
resource "aws_opensearchserverless_security_policy" "knowledge_base_encryption" {
  name = "${var.project_name}-${var.environment}-kb-encryption"
  type = "encryption"
  
  policy = jsonencode({
    Rules = [
      {
        ResourceType = "collection"
        Resource = [
          "collection/${var.project_name}-${var.environment}-kb"
        ]
      }
    ]
    AWSOwnedKey = true
  })
}

resource "aws_opensearchserverless_security_policy" "knowledge_base_network" {
  name = "${var.project_name}-${var.environment}-kb-network"
  type = "network"
  
  policy = jsonencode([
    {
      Rules = [
        {
          ResourceType = "collection"
          Resource = [
            "collection/${var.project_name}-${var.environment}-kb"
          ]
        }
      ]
      AllowFromPublic = false
      SourceVPCEs = []
    }
  ])
}

# OpenSearch Serverless access policy
resource "aws_opensearchserverless_access_policy" "knowledge_base" {
  name = "${var.project_name}-${var.environment}-kb-access"
  type = "data"
  
  policy = jsonencode([
    {
      Rules = [
        {
          ResourceType = "collection"
          Resource = [
            "collection/${var.project_name}-${var.environment}-kb"
          ]
          Permission = [
            "aoss:CreateCollectionItems",
            "aoss:DeleteCollectionItems",
            "aoss:UpdateCollectionItems",
            "aoss:DescribeCollectionItems"
          ]
        },
        {
          ResourceType = "index"
          Resource = [
            "index/${var.project_name}-${var.environment}-kb/*"
          ]
          Permission = [
            "aoss:CreateIndex",
            "aoss:DeleteIndex",
            "aoss:UpdateIndex",
            "aoss:DescribeIndex",
            "aoss:ReadDocument",
            "aoss:WriteDocument"
          ]
        }
      ]
      Principal = [
        aws_iam_role.knowledge_base.arn,
        aws_iam_role.bedrock_agent.arn
      ]
    }
  ])
}

# Bedrock Guardrail for safety
resource "aws_bedrock_guardrail" "eks_doctor_safety" {
  name                      = "${var.project_name}-${var.environment}-safety-guardrail"
  blocked_input_messaging   = "This input is not allowed as it may contain harmful operations for EKS clusters."
  blocked_outputs_messaging = "This output was blocked as it may contain harmful operations for EKS clusters."
  description              = "Safety guardrail for EKS Doctor to prevent harmful cluster operations"
  
  # Content policy to block harmful content
  content_policy_config {
    filters_config {
      input_strength  = "HIGH"
      output_strength = "HIGH"
      type           = "VIOLENCE"
    }
    filters_config {
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
      type           = "HATE"
    }
  }
  
  # Topic policy to block specific topics
  topic_policy_config {
    dynamic "topics_config" {
      for_each = local.denied_topics
      content {
        name       = topics_config.value
        examples   = ["Do not ${topics_config.value}"]
        type       = "DENY"
        definition = "Operations related to ${topics_config.value} are not allowed"
      }
    }
  }
  
  # Word policy to block specific inputs
  word_policy_config {
    dynamic "managed_word_lists_config" {
      for_each = ["PROFANITY"]
      content {
        type = managed_word_lists_config.value
      }
    }
    
    dynamic "words_config" {
      for_each = local.blocked_inputs
      content {
        text = words_config.value
      }
    }
  }
  
  tags = merge(var.default_tags, {
    "Name"      = "${var.project_name}-${var.environment}-safety-guardrail"
    "Component" = "bedrock-guardrail"
  })
}

# Bedrock Agent
resource "aws_bedrockagent_agent" "eks_doctor" {
  agent_name                  = local.agent_name
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  customer_encryption_key_arn = aws_kms_key.bedrock_agent.arn
  description                 = "EKS Doctor - Intelligent EKS cluster troubleshooting and remediation agent"
  foundation_model            = var.bedrock_model_id
  idle_session_ttl_in_seconds = 3600
  instruction                 = local.agent_instructions
  
  guardrail_configuration {
    guardrail_identifier = aws_bedrock_guardrail.eks_doctor_safety.guardrail_id
    guardrail_version    = aws_bedrock_guardrail.eks_doctor_safety.version
  }
  
  tags = merge(var.default_tags, {
    "Name"      = local.agent_name
    "Component" = "bedrock-agent"
  })
}

# Associate knowledge base with agent
resource "aws_bedrockagent_agent_knowledge_base_association" "eks_doctor" {
  agent_id             = aws_bedrockagent_agent.eks_doctor.id
  description          = "EKS troubleshooting knowledge base for the EKS Doctor agent"
  knowledge_base_id    = aws_bedrockagent_knowledge_base.eks_doctor.id
  knowledge_base_state = "ENABLED"
}

# Action groups for Lambda functions
resource "aws_bedrockagent_agent_action_group" "health_diagnostics" {
  action_group_name          = "health-diagnostics"
  agent_id                   = aws_bedrockagent_agent.eks_doctor.id
  agent_version             = "DRAFT"
  description               = "EKS cluster health diagnostic functions"
  skip_resource_in_use_check = true
  
  action_group_executor {
    lambda = aws_lambda_function.health_snapshot.arn
  }
  
  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info = {
        title   = "EKS Health Diagnostics API"
        version = "1.0.0"
      }
      paths = {
        "/health-snapshot" = {
          post = {
            description = "Get comprehensive EKS cluster health snapshot"
            parameters = [
              {
                name     = "cluster_name"
                in       = "query"
                required = true
                schema   = { type = "string" }
                description = "Name of the EKS cluster"
              },
              {
                name     = "account_id"
                in       = "query"
                required = true
                schema   = { type = "string" }
                description = "AWS account ID where the cluster resides"
              },
              {
                name     = "region"
                in       = "query"
                required = true
                schema   = { type = "string" }
                description = "AWS region where the cluster resides"
              }
            ]
            responses = {
              "200" = {
                description = "Cluster health snapshot"
                content = {
                  "application/json" = {
                    schema = {
                      type = "object"
                      properties = {
                        cluster_health = { type = "object" }
                        nodes = { type = "array" }
                        pods = { type = "array" }
                        events = { type = "array" }
                        health_score = { type = "number" }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  }
}

resource "aws_bedrockagent_agent_action_group" "network_diagnostics" {
  action_group_name          = "network-diagnostics"
  agent_id                   = aws_bedrockagent_agent.eks_doctor.id
  agent_version             = "DRAFT"
  description               = "EKS network connectivity diagnostic functions"
  skip_resource_in_use_check = true
  
  action_group_executor {
    lambda = aws_lambda_function.network_triage.arn
  }
  
  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info = {
        title   = "EKS Network Diagnostics API"
        version = "1.0.0"
      }
      paths = {
        "/network-triage" = {
          post = {
            description = "Analyze EKS cluster network connectivity issues"
            parameters = [
              {
                name     = "cluster_name"
                in       = "query"
                required = true
                schema   = { type = "string" }
                description = "Name of the EKS cluster"
              },
              {
                name     = "account_id"
                in       = "query"
                required = true
                schema   = { type = "string" }
                description = "AWS account ID"
              },
              {
                name     = "region"
                in       = "query"
                required = true
                schema   = { type = "string" }
                description = "AWS region"
              }
            ]
            responses = {
              "200" = {
                description = "Network analysis results"
                content = {
                  "application/json" = {
                    schema = {
                      type = "object"
                      properties = {
                        vpc_analysis = { type = "object" }
                        subnet_analysis = { type = "array" }
                        security_groups = { type = "array" }
                        connectivity_issues = { type = "array" }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  }
}

resource "aws_bedrockagent_agent_action_group" "remediation_actions" {
  action_group_name          = "remediation-actions"
  agent_id                   = aws_bedrockagent_agent.eks_doctor.id
  agent_version             = "DRAFT"
  description               = "EKS cluster remediation action functions"
  skip_resource_in_use_check = true
  
  action_group_executor {
    lambda = aws_lambda_function.drain_node.arn
  }
  
  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info = {
        title   = "EKS Remediation Actions API"
        version = "1.0.0"
      }
      paths = {
        "/drain-node" = {
          post = {
            description = "Safely drain an EKS node"
            requestBody = {
              required = true
              content = {
                "application/json" = {
                  schema = {
                    type = "object"
                    properties = {
                      cluster_name = { type = "string" }
                      node_name = { type = "string" }
                      account_id = { type = "string" }
                      region = { type = "string" }
                      force = { type = "boolean", default = false }
                    }
                    required = ["cluster_name", "node_name", "account_id", "region"]
                  }
                }
              }
            }
            responses = {
              "200" = {
                description = "Node drain operation result"
              }
            }
          }
        },
        "/scale-nodegroup" = {
          post = {
            description = "Scale an EKS nodegroup"
            requestBody = {
              required = true
              content = {
                "application/json" = {
                  schema = {
                    type = "object"
                    properties = {
                      cluster_name = { type = "string" }
                      nodegroup_name = { type = "string" }
                      desired_size = { type = "integer" }
                      account_id = { type = "string" }
                      region = { type = "string" }
                    }
                    required = ["cluster_name", "nodegroup_name", "desired_size", "account_id", "region"]
                  }
                }
              }
            }
            responses = {
              "200" = {
                description = "Nodegroup scaling operation result"
              }
            }
          }
        },
        "/restart-workload" = {
          post = {
            description = "Restart an EKS workload"
            requestBody = {
              required = true
              content = {
                "application/json" = {
                  schema = {
                    type = "object"
                    properties = {
                      cluster_name = { type = "string" }
                      workload_name = { type = "string" }
                      namespace = { type = "string", default = "default" }
                      workload_type = { type = "string", enum = ["Deployment", "StatefulSet", "DaemonSet"] }
                      account_id = { type = "string" }
                      region = { type = "string" }
                    }
                    required = ["cluster_name", "workload_name", "workload_type", "account_id", "region"]
                  }
                }
              }
            }
            responses = {
              "200" = {
                description = "Workload restart operation result"
              }
            }
          }
        }
      }
    })
  }
}

# Prepare the Bedrock Agent
resource "aws_bedrockagent_agent_alias" "eks_doctor_live" {
  agent_alias_name = "LIVE"
  agent_id         = aws_bedrockagent_agent.eks_doctor.id
  description      = "Live alias for EKS Doctor agent"
  
  tags = merge(var.default_tags, {
    "Name"      = "${local.agent_name}-live"
    "Component" = "bedrock-agent-alias"
  })
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Random ID for unique naming
resource "random_id" "bucket_suffix" {
  byte_length = 4
}
