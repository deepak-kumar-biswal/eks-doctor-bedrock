# EKS Doctor API Reference

## Overview

This document provides comprehensive API documentation for the EKS Doctor AI-powered diagnostic system, including Lambda functions, Bedrock integrations, and diagnostic endpoints.

## Lambda Functions

### eks-doctor-diagnostic

**Function Name:** `eks-doctor-diagnostic`

#### Request Format
```json
{
  "clusterName": "string",
  "diagnosticType": "health|performance|security|networking",
  "symptoms": ["string"],
  "timeRange": {
    "start": "ISO8601",
    "end": "ISO8601"
  },
  "includeAIAnalysis": true
}
```

#### Response Format
```json
{
  "statusCode": 200,
  "body": {
    "diagnosticId": "string",
    "clusterHealth": "healthy|warning|critical",
    "findings": [
      {
        "category": "string",
        "severity": "low|medium|high|critical",
        "issue": "string",
        "recommendation": "string",
        "aiConfidence": 0.95
      }
    ],
    "aiInsights": {
      "rootCause": "string",
      "predictiveAnalysis": "string",
      "recommendations": ["string"]
    }
  }
}
```

### eks-doctor-remediation

**Function Name:** `eks-doctor-remediation`

#### Request Format
```json
{
  "diagnosticId": "string",
  "remediationActions": ["string"],
  "autoApprove": false,
  "rollbackPlan": {
    "enabled": true,
    "timeoutMinutes": 30
  }
}
```

#### Response Format
```json
{
  "statusCode": 200,
  "body": {
    "remediationId": "string",
    "status": "pending|running|completed|failed",
    "appliedActions": ["string"],
    "results": {
      "successful": ["string"],
      "failed": ["string"]
    }
  }
}
```

## Bedrock AI Integration

### Model Configuration
```json
{
  "modelId": "anthropic.claude-v2",
  "modelParams": {
    "max_tokens": 2048,
    "temperature": 0.1,
    "top_p": 0.9
  }
}
```

### Diagnostic Prompts

#### Cluster Health Analysis
```json
{
  "systemPrompt": "You are an expert Kubernetes administrator analyzing EKS cluster health metrics.",
  "userPrompt": "Analyze the following cluster metrics and identify potential issues: {metrics_data}",
  "responseFormat": "structured_json"
}
```

#### Performance Analysis
```json
{
  "systemPrompt": "You are a performance optimization expert for Kubernetes clusters.",
  "userPrompt": "Review these performance metrics and provide optimization recommendations: {performance_data}",
  "responseFormat": "structured_json"
}
```

## REST API Endpoints

### Health Check Endpoint

**Endpoint:** `POST /api/v1/diagnostic/health`

**Headers:**
```
Content-Type: application/json
Authorization: Bearer {token}
```

**Request Body:**
```json
{
  "clusterArn": "arn:aws:eks:region:account:cluster/name",
  "checkTypes": ["nodes", "pods", "services", "ingress"],
  "deepAnalysis": true
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "overallHealth": "healthy",
    "checks": {
      "nodes": {
        "status": "healthy",
        "total": 10,
        "ready": 10,
        "notReady": 0
      },
      "pods": {
        "status": "warning",
        "total": 150,
        "running": 145,
        "pending": 3,
        "failed": 2
      }
    },
    "recommendations": ["string"]
  }
}
```

### Performance Analysis Endpoint

**Endpoint:** `POST /api/v1/diagnostic/performance`

**Request Body:**
```json
{
  "clusterArn": "string",
  "timeWindow": "1h|6h|24h|7d",
  "metrics": ["cpu", "memory", "network", "storage"],
  "includeNodeMetrics": true,
  "includePodMetrics": true
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "performanceScore": 85,
    "bottlenecks": [
      {
        "type": "memory",
        "severity": "medium",
        "affectedResources": ["node-1", "node-2"],
        "recommendation": "Consider increasing memory limits"
      }
    ],
    "trends": {
      "cpuUtilization": "stable",
      "memoryUsage": "increasing",
      "networkTraffic": "stable"
    }
  }
}
```

## WebSocket Events

### Real-time Diagnostics

**Connection:** `wss://api.eks-doctor.com/ws/diagnostics`

#### Subscription Message
```json
{
  "action": "subscribe",
  "clusterArn": "string",
  "eventTypes": ["health", "performance", "alerts"]
}
```

#### Event Format
```json
{
  "eventType": "health_change",
  "timestamp": "ISO8601",
  "clusterArn": "string",
  "data": {
    "component": "node-1",
    "previousState": "healthy",
    "currentState": "warning",
    "details": "High memory utilization detected"
  }
}
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "EKS_DOCTOR_001",
    "message": "Cluster not accessible",
    "details": "Unable to establish connection to EKS cluster",
    "timestamp": "ISO8601",
    "requestId": "string"
  }
}
```

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| EKS_DOCTOR_001 | Cluster not accessible | 404 |
| EKS_DOCTOR_002 | Insufficient permissions | 403 |
| EKS_DOCTOR_003 | AI service unavailable | 503 |
| EKS_DOCTOR_004 | Invalid request format | 400 |
| EKS_DOCTOR_005 | Rate limit exceeded | 429 |

## Authentication

### API Token Format
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Required Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters",
        "eks:DescribeNodegroup",
        "bedrock:InvokeModel",
        "cloudwatch:GetMetricData",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| Health Check | 100 requests | 1 minute |
| Performance Analysis | 20 requests | 1 minute |
| AI Diagnostics | 10 requests | 1 minute |
| WebSocket Connections | 50 connections | Per user |

## SDK Examples

### Python SDK
```python
from eks_doctor import EKSDoctor

client = EKSDoctor(api_key="your-api-key")

# Health check
result = client.check_health(
    cluster_arn="arn:aws:eks:us-east-1:123456789:cluster/my-cluster",
    deep_analysis=True
)

# Performance analysis
perf_result = client.analyze_performance(
    cluster_arn="arn:aws:eks:us-east-1:123456789:cluster/my-cluster",
    time_window="24h"
)
```

### JavaScript SDK
```javascript
import { EKSDoctor } from 'eks-doctor-sdk';

const client = new EKSDoctor({ apiKey: 'your-api-key' });

// Health check
const healthResult = await client.checkHealth({
  clusterArn: 'arn:aws:eks:us-east-1:123456789:cluster/my-cluster',
  deepAnalysis: true
});

// Performance analysis
const perfResult = await client.analyzePerformance({
  clusterArn: 'arn:aws:eks:us-east-1:123456789:cluster/my-cluster',
  timeWindow: '24h'
});
```
