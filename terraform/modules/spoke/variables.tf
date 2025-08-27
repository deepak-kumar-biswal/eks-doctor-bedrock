# Spoke Module Variables

# Project Configuration
variable "project_name" {
  description = "Name of the EKS Doctor project"
  type        = string
  default     = "eks-doctor"
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.project_name))
    error_message = "Project name must start with a letter and contain only letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "solution_version" {
  description = "Version of the EKS Doctor solution"
  type        = string
  default     = "1.0.0"
}

# Account Configuration
variable "hub_account_id" {
  description = "AWS account ID where the hub resources are deployed"
  type        = string
  
  validation {
    condition     = can(regex("^[0-9]{12}$", var.hub_account_id))
    error_message = "Hub account ID must be a 12-digit number."
  }
}

variable "external_id" {
  description = "External ID for cross-account role assumption (shared secret)"
  type        = string
  sensitive   = true
  
  validation {
    condition     = length(var.external_id) >= 16
    error_message = "External ID must be at least 16 characters long."
  }
}

# Region Configuration
variable "primary_region" {
  description = "Primary AWS region for spoke account resources"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.primary_region))
    error_message = "Primary region must be a valid AWS region name."
  }
}

variable "secondary_region" {
  description = "Secondary AWS region for multi-region deployment"
  type        = string
  default     = "us-west-2"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.secondary_region))
    error_message = "Secondary region must be a valid AWS region name."
  }
}

# EKS Configuration
variable "cluster_name" {
  description = "Name of the primary EKS cluster to manage"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{0,99}$", var.cluster_name))
    error_message = "Cluster name must start with a letter, be 1-100 characters, and contain only letters, numbers, and hyphens."
  }
}

variable "allowed_cluster_arns" {
  description = "List of EKS cluster ARNs that the hub account can manage (null means all clusters)"
  type        = list(string)
  default     = null
  
  validation {
    condition = var.allowed_cluster_arns == null ? true : alltrue([
      for arn in var.allowed_cluster_arns : can(regex("^arn:aws:eks:", arn))
    ])
    error_message = "All cluster ARNs must be valid EKS cluster ARNs."
  }
}

variable "monitored_cluster_names" {
  description = "List of EKS cluster names to monitor for events (null means monitor the primary cluster)"
  type        = list(string)
  default     = null
}

# Security Configuration
variable "trusted_ip_ranges" {
  description = "List of trusted IP ranges for cross-account role assumption"
  type        = list(string)
  default     = null
  
  validation {
    condition = var.trusted_ip_ranges == null ? true : alltrue([
      for ip in var.trusted_ip_ranges : can(cidrhost(ip, 0))
    ])
    error_message = "All trusted IP ranges must be valid CIDR blocks."
  }
}

# Service Role Configuration
variable "create_eks_service_role" {
  description = "Whether to create the EKS service-linked role"
  type        = bool
  default     = false
}

variable "create_nodegroup_service_role" {
  description = "Whether to create the EKS NodeGroup service-linked role"
  type        = bool
  default     = false
}

variable "enable_fargate" {
  description = "Whether Fargate is enabled (creates Fargate service-linked role)"
  type        = bool
  default     = false
}

# Logging Configuration
variable "enable_cluster_logging" {
  description = "Whether to enable EKS cluster logging"
  type        = bool
  default     = true
}

variable "cluster_log_types" {
  description = "List of EKS cluster log types to enable"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  validation {
    condition = alltrue([
      for log_type in var.cluster_log_types : contains([
        "api", "audit", "authenticator", "controllerManager", "scheduler"
      ], log_type)
    ])
    error_message = "Log types must be one of: api, audit, authenticator, controllerManager, scheduler."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch Logs retention period."
  }
}

variable "enable_log_encryption" {
  description = "Whether to encrypt CloudWatch logs with KMS"
  type        = bool
  default     = true
}

# Event Bridge Configuration
variable "create_spoke_event_bus" {
  description = "Whether to create a custom EventBridge bus in the spoke account"
  type        = bool
  default     = false
}

variable "forward_eks_events" {
  description = "Whether to forward EKS events to the hub account"
  type        = bool
  default     = true
}

# Resource Tagging
variable "default_tags" {
  description = "Default tags to apply to all resources"
  type        = map(string)
  default = {
    "Project"     = "EKS-Doctor"
    "ManagedBy"   = "Terraform"
    "Repository"  = "eks-doctor-bedrock"
  }
  
  validation {
    condition = alltrue([
      for k, v in var.default_tags : can(regex("^[a-zA-Z0-9\\s\\-_.:/@+\\=]+$", k))
    ])
    error_message = "Tag keys must contain only valid characters."
  }
  
  validation {
    condition = alltrue([
      for k, v in var.default_tags : can(regex("^[a-zA-Z0-9\\s\\-_.:/@+\\=]*$", v))
    ])
    error_message = "Tag values must contain only valid characters."
  }
}
