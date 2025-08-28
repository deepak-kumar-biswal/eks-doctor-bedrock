# Troubleshooting Guide

## Common Issues and Solutions

### EKS Cluster Issues

#### Issue: Cannot connect to EKS cluster
**Symptoms:**
- Connection timeout errors
- Authentication failures
- kubectl commands failing

**Solutions:**
1. Verify AWS credentials are properly configured
2. Check VPC security groups allow necessary traffic
3. Ensure IAM roles have proper permissions
4. Update kubeconfig with correct cluster endpoint

```bash
aws eks update-kubeconfig --region <region> --name <cluster-name>
```

#### Issue: Pods stuck in Pending state
**Symptoms:**
- Pods remain in Pending status
- No resources allocated to pods

**Solutions:**
1. Check node capacity and resource requests
2. Verify node groups are healthy
3. Check for resource constraints

```bash
kubectl describe nodes
kubectl top nodes
kubectl describe pod <pod-name>
```

### AWS Bedrock Issues

#### Issue: Bedrock API calls failing
**Symptoms:**
- API timeout errors
- Access denied errors
- Invalid model responses

**Solutions:**
1. Verify Bedrock service is enabled in your region
2. Check IAM permissions for Bedrock access
3. Ensure model access is granted
4. Validate request format and parameters

#### Issue: AI diagnostic results are inaccurate
**Symptoms:**
- Incorrect diagnosis suggestions
- Missing critical issues
- False positive alerts

**Solutions:**
1. Review input data quality
2. Update AI model prompts
3. Fine-tune diagnostic algorithms
4. Validate cluster metrics collection

### Lambda Function Issues

#### Issue: Lambda function timeout
**Symptoms:**
- Function exceeds execution time limit
- Incomplete diagnostics

**Solutions:**
1. Increase function timeout in configuration
2. Optimize code for better performance
3. Implement pagination for large datasets
4. Use asynchronous processing where possible

#### Issue: Memory issues
**Symptoms:**
- Out of memory errors
- Function crashes during execution

**Solutions:**
1. Increase memory allocation
2. Optimize data structures
3. Implement streaming for large responses
4. Clean up unused variables

### Monitoring and Logging

#### Issue: Missing logs or metrics
**Symptoms:**
- CloudWatch logs not appearing
- Metrics not being collected
- Dashboard showing no data

**Solutions:**
1. Verify CloudWatch agent configuration
2. Check IAM permissions for logging
3. Ensure log groups exist
4. Validate metric filters

#### Issue: Performance degradation
**Symptoms:**
- Slow response times
- High resource utilization
- Increased error rates

**Solutions:**
1. Review CloudWatch metrics
2. Analyze application logs
3. Check database performance
4. Optimize resource allocation

## Diagnostic Commands

### EKS Cluster Health Check
```bash
# Check cluster status
aws eks describe-cluster --name <cluster-name>

# Check node status
kubectl get nodes -o wide

# Check system pods
kubectl get pods -n kube-system

# Check resource usage
kubectl top nodes
kubectl top pods --all-namespaces
```

### AWS Bedrock Testing
```bash
# Test Bedrock access
aws bedrock list-foundation-models

# Test model invocation
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-v2 \
  --body '{"prompt":"Hello","max_tokens_to_sample":100}' \
  output.json
```

### Lambda Function Debugging
```bash
# View function logs
aws logs tail /aws/lambda/<function-name> --follow

# Test function locally
sam local invoke <function-name> --event test-event.json

# Check function configuration
aws lambda get-function --function-name <function-name>
```

## Getting Help

1. Check this troubleshooting guide first
2. Review the [deployment guide](deployment-guide.md)
3. Check CloudWatch logs for error details
4. Search existing GitHub issues
5. Create a new issue with:
   - Detailed problem description
   - Steps to reproduce
   - Error messages and logs
   - Environment information

## Support Resources

- [AWS EKS Documentation](https://docs.aws.amazon.com/eks/)
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug-application-cluster/)
- [AWS Lambda Troubleshooting](https://docs.aws.amazon.com/lambda/latest/dg/troubleshooting.html)
