# EKS Doctor Deployment Guide

## Overview

This guide provides comprehensive deployment instructions for the EKS Doctor AI-powered diagnostic system across hub and spoke architectures.

## Prerequisites

### Required Tools
- AWS CLI v2.0 or higher
- Terraform >= 1.5.0
- Python >= 3.9
- Docker >= 20.10
- kubectl configured for target clusters

### AWS Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:*",
        "lambda:*",
        "iam:*",
        "eks:*",
        "logs:*",
        "cloudwatch:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Bedrock Model Access
Ensure access to required AI models:
- `anthropic.claude-v2`
- `anthropic.claude-instant-v1`
- `amazon.titan-text-express-v1`

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Hub Account   │    │ Spoke Account 1 │    │ Spoke Account N │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ EKS Doctor  │ │    │ │   Agents    │ │    │ │   Agents    │ │
│ │  Control    │◄┼────┤ │& Collectors │ │    │ │& Collectors │ │
│ │   Plane     │ │    │ │             │ │    │ │             │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │  Bedrock    │ │    │ │EKS Clusters │ │    │ │EKS Clusters │ │
│ │ AI Models   │ │    │ │             │ │    │ │             │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Deployment Steps

### 1. Hub Account Deployment

#### 1.1 Configure Environment
```bash
export AWS_REGION=us-east-1
export HUB_ACCOUNT_ID=123456789012
export PROJECT_NAME=eks-doctor

cd terraform/
```

#### 1.2 Initialize Terraform
```bash
terraform init -backend-config="bucket=terraform-state-${HUB_ACCOUNT_ID}" \
              -backend-config="key=eks-doctor/hub/terraform.tfstate" \
              -backend-config="region=${AWS_REGION}"
```

#### 1.3 Deploy Core Infrastructure
```bash
# Review configuration
terraform plan -var-file="../examples/hub.tfvars"

# Deploy hub components
terraform apply -var-file="../examples/hub.tfvars" -auto-approve
```

#### 1.4 Deploy Lambda Functions
```bash
# Build and deploy Lambda packages
python deploy.py --environment production --region ${AWS_REGION}
```

#### 1.5 Configure Bedrock Models
```bash
# Enable model access
aws bedrock put-model-invocation-logging-configuration \
    --logging-config '{"textDataDeliveryEnabled":true,"imageDataDeliveryEnabled":true,"embeddingDataDeliveryEnabled":true,"s3Config":{"bucketName":"eks-doctor-bedrock-logs","keyPrefix":"bedrock-logs/"}}'

# Test model access
aws bedrock invoke-model \
    --model-id anthropic.claude-v2 \
    --body '{"prompt":"Human: Test connection\n\nAssistant: Connection successful!","max_tokens_to_sample":100}' \
    --accept application/json \
    --content-type application/json \
    output.json
```

### 2. Spoke Account Deployment

#### 2.1 Cross-Account IAM Setup
```bash
# Create cross-account role in each spoke account
aws iam create-role --role-name EKSDoctorSpokeRole \
    --assume-role-policy-document file://policies/spoke-assume-role-policy.json

aws iam attach-role-policy \
    --role-name EKSDoctorSpokeRole \
    --policy-arn arn:aws:iam::${SPOKE_ACCOUNT_ID}:policy/EKSDoctorSpokePolicy
```

#### 2.2 Deploy Spoke Components
```bash
cd terraform/spoke/

terraform init -backend-config="bucket=terraform-state-${SPOKE_ACCOUNT_ID}" \
              -backend-config="key=eks-doctor/spoke/terraform.tfstate"

terraform apply -var="hub_account_id=${HUB_ACCOUNT_ID}" \
               -var="spoke_account_id=${SPOKE_ACCOUNT_ID}" \
               -auto-approve
```

#### 2.3 Install Cluster Agents
```bash
# Deploy diagnostic agents to each EKS cluster
kubectl apply -f k8s-manifests/diagnostic-agent.yaml

# Verify agent deployment
kubectl get pods -n eks-doctor-system
kubectl logs -n eks-doctor-system deployment/eks-doctor-agent
```

### 3. Configuration

#### 3.1 Environment Variables
```bash
# Hub account configuration
export EKS_DOCTOR_HUB_ROLE_ARN=arn:aws:iam::${HUB_ACCOUNT_ID}:role/EKSDoctorHubRole
export BEDROCK_REGION=us-east-1
export LOG_LEVEL=INFO

# Spoke account configuration
export EKS_DOCTOR_SPOKE_ROLE_ARN=arn:aws:iam::${SPOKE_ACCOUNT_ID}:role/EKSDoctorSpokeRole
export CLUSTER_NAME=my-eks-cluster
```

#### 3.2 Configuration Files
```yaml
# config/hub-config.yaml
bedrock:
  models:
    primary: "anthropic.claude-v2"
    fallback: "anthropic.claude-instant-v1"
  timeout: 30
  max_tokens: 2048

diagnostics:
  intervals:
    health_check: "5m"
    performance_analysis: "15m"
    security_scan: "1h"
  
alerts:
  channels:
    - type: "sns"
      topic: "arn:aws:sns:us-east-1:123456789012:eks-doctor-alerts"
    - type: "slack"
      webhook: "${SLACK_WEBHOOK_URL}"
```

### 4. Verification

#### 4.1 Hub Components
```bash
# Verify Lambda functions
aws lambda list-functions --query 'Functions[?contains(FunctionName, `eks-doctor`)]'

# Test API Gateway endpoint
curl -X POST https://api-gateway-id.execute-api.us-east-1.amazonaws.com/prod/diagnostic/health \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"clusterArn":"arn:aws:eks:us-east-1:123456789012:cluster/test"}'

# Check Bedrock model access
aws bedrock list-foundation-models --by-provider anthropic
```

#### 4.2 Spoke Components
```bash
# Verify cross-account role assumption
aws sts assume-role \
    --role-arn arn:aws:iam::${SPOKE_ACCOUNT_ID}:role/EKSDoctorSpokeRole \
    --role-session-name eks-doctor-test

# Test agent connectivity
kubectl exec -n eks-doctor-system deployment/eks-doctor-agent -- \
    curl -f http://localhost:8080/health

# Verify metrics collection
kubectl top nodes
kubectl top pods -n eks-doctor-system
```

#### 4.3 End-to-End Testing
```bash
# Run comprehensive diagnostics
python tests/integration/test_full_workflow.py

# Validate AI responses
python scripts/test-bedrock-integration.py
```

## Post-Deployment Configuration

### 1. Monitoring Setup
```bash
# Create CloudWatch dashboards
aws cloudwatch put-dashboard \
    --dashboard-name EKSDoctor \
    --dashboard-body file://monitoring/cloudwatch-dashboard.json

# Configure alarms
aws cloudwatch put-metric-alarm \
    --alarm-name "EKSDoctor-HighErrorRate" \
    --alarm-description "High error rate in EKS Doctor functions" \
    --actions-enabled \
    --alarm-actions arn:aws:sns:us-east-1:123456789012:eks-doctor-alerts
```

### 2. Security Configuration
```bash
# Enable API Gateway logging
aws apigateway put-method-response \
    --rest-api-id ${API_GATEWAY_ID} \
    --resource-id ${RESOURCE_ID} \
    --http-method POST \
    --status-code 200

# Configure WAF rules
aws wafv2 create-web-acl \
    --name EKSDoctorWAF \
    --scope CLOUDFRONT \
    --default-action Allow={}
```

### 3. Performance Tuning
```bash
# Configure Lambda concurrency
aws lambda put-provisioned-concurrency-config \
    --function-name eks-doctor-diagnostic \
    --qualifier LIVE \
    --provisioned-concurrency-level 10

# Optimize Bedrock model parameters
aws bedrock put-model-customization-job \
    --job-name eks-doctor-model-optimization
```

## Troubleshooting Common Issues

### 1. Bedrock Access Issues
```bash
# Check model availability
aws bedrock list-foundation-models --region us-east-1

# Verify IAM permissions
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::123456789012:role/EKSDoctorRole \
    --action-names bedrock:InvokeModel \
    --resource-arns '*'
```

### 2. Cross-Account Access Problems
```bash
# Test role assumption
aws sts get-caller-identity
aws sts assume-role \
    --role-arn arn:aws:iam::SPOKE-ACCOUNT:role/EKSDoctorSpokeRole \
    --role-session-name test-session
```

### 3. Agent Connectivity Issues
```bash
# Check agent logs
kubectl logs -n eks-doctor-system deployment/eks-doctor-agent --tail=100

# Verify network policies
kubectl get networkpolicies -n eks-doctor-system

# Test service mesh connectivity
kubectl exec -n eks-doctor-system deployment/eks-doctor-agent -- \
    nslookup eks-doctor-hub.amazonaws.com
```

## Maintenance and Updates

### 1. Regular Updates
```bash
# Update Lambda functions
python deploy.py --update-functions --environment production

# Refresh Terraform state
terraform refresh -var-file="../examples/hub.tfvars"
terraform plan -var-file="../examples/hub.tfvars"
```

### 2. Scaling Operations
```bash
# Scale Lambda concurrency
aws lambda put-provisioned-concurrency-config \
    --function-name eks-doctor-diagnostic \
    --provisioned-concurrency-level 20

# Update agent replicas
kubectl scale deployment/eks-doctor-agent \
    --replicas=3 -n eks-doctor-system
```

### 3. Backup and Recovery
```bash
# Backup configuration
aws s3 sync ./config s3://eks-doctor-backup/config/$(date +%Y%m%d)

# Export Terraform state
terraform state pull > terraform-state-backup-$(date +%Y%m%d).json
```
