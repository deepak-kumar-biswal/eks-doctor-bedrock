<div align="center">
  <img src="https://img.shields.io/badge/%F0%9F%8F%A5-EKS%20Doctor%20AI-blue?style=for-the-badge&logoColor=white" alt="EKS Doctor"/>
  <img src="https://img.shields.io/badge/%F0%9F%A4%96-AI%20Powered-purple?style=for-the-badge" alt="AI Powered"/>
  <img src="https://img.shields.io/badge/%E2%9A%A1-Production%20Grade-green?style=for-the-badge" alt="Production Grade"/>
</div>

<div align="center">
  <h1>🏥 EKS Doctor - AI-Powered Kubernetes Diagnostics Platform</h1>
  <p><strong>AI-powered EKS diagnostics and remediation for 1000+ EKS clusters</strong></p>
</div>

<div align="center">

[![Terraform](https://img.shields.io/badge/Terraform-1.5%2B-623CE4?style=for-the-badge&logo=terraform&logoColor=white)](https://www.terraform.io/)
[![AWS Bedrock](https://img.shields.io/badge/AWS-Bedrock-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)](https://aws.amazon.com/bedrock/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28%2B-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![AI Diagnostics](https://img.shields.io/badge/AI-Diagnostics-9F7AEA?style=for-the-badge&logo=brain&logoColor=white)](https://aws.amazon.com/bedrock/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

## 🚀 Production-Grade AI-Powered EKS Diagnostics & Remediation

A **comprehensive, enterprise-grade** EKS cluster diagnostic and remediation system using **AWS Bedrock Agent** with intelligent hub-and-spoke architecture for **1000+ EKS clusters** across multiple AWS accounts.

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [Advanced Features](#advanced-features)
- [Security & Compliance](#security--compliance)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                 HUB ACCOUNT                     │
│            (AI Control Plane)                   │
│  ┌─────────────┐    ┌─────────────────────────┐ │
│  │ Bedrock     │    │ Lambda Tools            │ │
│  │ Agent       │◄──►│ (Diagnostic/Remediation)│ │
│  │ + KB/RAG    │    │                         │ │
│  └─────────────┘    └─────────────────────────┘ │
│         │                       │               │
│         │                       │ STS Assume    │
└─────────┼───────────────────────┼───────────────┘
          │                       │
          │                       ▼
┌─────────┴───────┐    ┌─────────────────────────┐
│   Chat/API      │    │     SPOKE ACCOUNTS      │
│   Interface     │    │   (us-east-1/us-west-2) │
└─────────────────┘    │                         │
                       │ ┌─────────────────────┐ │
                       │ │ EKS Clusters        │ │
                       │ │ - Access Entries    │ │
                       │ │ - RBAC              │ │
                       │ │ - Monitoring        │ │
                       │ └─────────────────────┘ │
                       └─────────────────────────┘
```

## Features

### 🔍 Intelligent Diagnostics
- Real-time cluster health monitoring
- Network connectivity analysis  
- Resource utilization assessment
- Event correlation and root cause analysis

### 🛠️ Automated Remediation
- Safe node draining with approvals
- Intelligent workload restarting
- Auto-scaling recommendations
- Resource optimization

### 🔐 Enterprise Security
- Multi-account IAM with ExternalId
- Least-privilege access patterns
- Audit logging and compliance
- Encrypted data in transit/rest

### 📊 Comprehensive Observability
- CloudWatch integration
- Custom metrics and dashboards
- Alert management
- Performance analytics

### 🤖 AI-Powered Intelligence
- Natural language interaction
- Context-aware recommendations
- Learning from historical patterns
- Proactive issue detection

## Quick Start

### Prerequisites
- AWS CLI configured
- Terraform >= 1.5
- Python 3.12
- kubectl access to EKS clusters

### 1. Configure Variables
```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit with your account IDs and settings
```

### 2. Deploy Infrastructure
```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### 3. Setup Knowledge Base
```bash
cd scripts
./setup-knowledge-base.sh
```

### 4. Configure EKS Access
```bash
./setup-eks-access.sh
```

## Usage

### Chat Interface
```bash
# Start interactive session
python scripts/chat_interface.py

> "Check the health of my prod-eks cluster in us-east-1"
> "Scale the nodegroup in staging cluster to 5 nodes" 
> "What's causing high CPU in my workloads?"
```

### API Integration
```python
import boto3

bedrock = boto3.client('bedrock-agent-runtime')
response = bedrock.invoke_agent(
    agentId='AGENT-ID',
    sessionId='unique-session',
    inputText='Diagnose all EKS clusters in account 123456789012'
)
```

### Automated Workflows
- Scheduled health checks
- Auto-remediation triggers
- Integration with CI/CD pipelines
- Incident response automation

## Configuration

### Multi-Account Setup
The solution supports up to 5 spoke accounts across multiple regions:

```hcl
spoke_accounts = [
  "111111111111",  # Production
  "222222222222",  # Staging  
  "333333333333",  # Development
  "444444444444",  # Testing
  "555555555555"   # Sandbox
]

regions = ["us-east-1", "us-west-2"]
```

### Security Configuration
- External ID for cross-account trust
- Separate read-only and change roles
- Approval workflows for destructive operations
- Comprehensive audit logging

### Monitoring Configuration
- Container Insights enabled
- Custom CloudWatch dashboards
- Alert rules and notifications
- Performance metrics collection

## Advanced Features

### Knowledge Base Integration
- EKS best practices documentation
- Troubleshooting runbooks
- Historical incident data
- Community knowledge synthesis

### Approval Workflows
- Slack/Teams integration
- Email notifications
- Mobile approvals
- Audit trails

### Extensibility
- Custom diagnostic plugins
- Third-party tool integration
- Webhook support
- API extensibility

## Security & Compliance

### IAM Best Practices
- Principle of least privilege
- Regular access reviews  
- Temporary credentials
- Multi-factor authentication

### Data Protection
- Encryption at rest and in transit
- Secure credential handling
- GDPR/SOC2 compliance ready
- Data residency controls

### Audit & Logging
- CloudTrail integration
- Detailed operation logs
- Security event monitoring
- Compliance reporting

## Troubleshooting

### Common Issues
- [Permission denied errors](docs/troubleshooting.md#permissions)
- [Network connectivity issues](docs/troubleshooting.md#networking)
- [Agent response delays](docs/troubleshooting.md#performance)

### Support
- Check the [troubleshooting guide](docs/troubleshooting.md)
- Review CloudWatch logs
- Contact support team

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.
