# EKS Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting procedures for Amazon EKS (Elastic Kubernetes Service) clusters. It covers common issues, diagnostic steps, and remediation procedures.

## Table of Contents

1. [Cluster Health Issues](#cluster-health-issues)
2. [Node Problems](#node-problems)
3. [Pod Issues](#pod-issues)
4. [Network Connectivity](#network-connectivity)
5. [Storage Issues](#storage-issues)
6. [Security and RBAC](#security-and-rbac)
7. [Performance Problems](#performance-problems)
8. [Monitoring and Logging](#monitoring-and-logging)

## Cluster Health Issues

### Cluster in Failed State

**Symptoms:**
- Cluster shows as FAILED in AWS Console
- kubectl commands return connection errors
- Cluster endpoint is unreachable

**Diagnosis:**
```bash
# Check cluster status
aws eks describe-cluster --name <cluster-name> --region <region>

# Check cluster endpoint
kubectl cluster-info

# Verify VPC and subnet configuration
aws ec2 describe-subnets --subnet-ids <subnet-ids>
aws ec2 describe-vpcs --vpc-ids <vpc-id>
```

**Common Causes:**
1. **VPC Configuration Issues**
   - Private subnets without NAT Gateway
   - Security groups blocking required ports
   - Route table misconfiguration

2. **Service-Linked Roles Missing**
   - EKS service role not properly configured
   - Missing permissions for cluster operations

**Remediation:**
1. Verify VPC configuration meets EKS requirements
2. Check security group rules (ports 443, 1025-65535)
3. Ensure proper IAM roles and policies
4. Validate subnet tagging for load balancers

### Control Plane Unhealthy

**Symptoms:**
- High API server latency
- Frequent 5xx responses from API server
- etcd performance issues

**Diagnosis:**
```bash
# Check cluster logs
aws logs describe-log-groups --log-group-name-prefix "/aws/eks"
aws logs get-log-events --log-group-name "/aws/eks/<cluster-name>/cluster"

# Monitor API server metrics
kubectl top nodes
kubectl get events --sort-by='.lastTimestamp'
```

**Remediation:**
1. Enable cluster logging for all log types
2. Monitor control plane metrics in CloudWatch
3. Review API server configuration
4. Check for resource quotas and limits

## Node Problems

### Nodes in NotReady State

**Symptoms:**
- `kubectl get nodes` shows NotReady
- Pods cannot be scheduled on affected nodes
- Node status shows various conditions

**Diagnosis Steps:**
```bash
# Check node status
kubectl get nodes -o wide
kubectl describe node <node-name>

# Check node logs
kubectl logs -n kube-system <node-problem-detector-pod>

# Check kubelet logs on the node
journalctl -u kubelet -n 50

# Check system resources
kubectl top node <node-name>
```

**Common Causes & Solutions:**

#### 1. Kubelet Not Running
```bash
# On the node
sudo systemctl status kubelet
sudo systemctl start kubelet
sudo systemctl enable kubelet
```

#### 2. Network Plugin Issues
```bash
# Check CNI plugins
kubectl get pods -n kube-system | grep -E "(cni|network)"
kubectl logs -n kube-system <cni-pod-name>

# For AWS VPC CNI
kubectl get pods -n kube-system | grep aws-node
kubectl describe pod -n kube-system <aws-node-pod>
```

#### 3. Resource Exhaustion
```bash
# Check disk usage
df -h
sudo find /var/log -name "*.log" -size +100M

# Check memory usage
free -h
ps aux --sort=-%mem | head -10

# Clean up resources
sudo journalctl --vacuum-time=7d
sudo docker system prune -f
```

### Node Scaling Issues

**Symptoms:**
- Nodes not scaling up under load
- Cluster Autoscaler not working
- Pending pods due to insufficient resources

**Diagnosis:**
```bash
# Check Cluster Autoscaler logs
kubectl logs -n kube-system deployment/cluster-autoscaler

# Check node groups
aws eks describe-nodegroup --cluster-name <cluster-name> --nodegroup-name <nodegroup>

# Check ASG configuration
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names <asg-name>
```

**Remediation:**
1. Verify Cluster Autoscaler configuration
2. Check ASG min/max/desired capacity settings
3. Validate node group subnets have available capacity
4. Review resource requests and limits on pods

## Pod Issues

### CrashLoopBackOff

**Symptoms:**
- Pod repeatedly crashing and restarting
- High restart count
- Application unavailable

**Diagnosis:**
```bash
# Check pod status
kubectl get pods -o wide
kubectl describe pod <pod-name>

# Check logs
kubectl logs <pod-name> --previous
kubectl logs <pod-name> -f

# Check events
kubectl get events --field-selector involvedObject.name=<pod-name>
```

**Common Causes:**
1. **Application Code Issues**
   - Unhandled exceptions
   - Missing dependencies
   - Configuration errors

2. **Resource Constraints**
   - Insufficient memory/CPU
   - Resource limits too low

3. **Health Check Failures**
   - Misconfigured liveness/readiness probes
   - Application slow to start

**Remediation Steps:**
```bash
# Adjust resource limits
kubectl patch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<container-name>","resources":{"limits":{"memory":"1Gi","cpu":"500m"}}}]}}}}'

# Update probe configuration
kubectl patch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<container-name>","livenessProbe":{"initialDelaySeconds":60}}]}}}}'
```

### ImagePullBackOff

**Symptoms:**
- Pods stuck in ImagePullBackOff state
- Cannot pull container image
- Authentication or network issues

**Diagnosis:**
```bash
# Check pod events
kubectl describe pod <pod-name>

# Check image details
kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].image}'

# Test image pull manually on node
sudo docker pull <image-name>
```

**Common Solutions:**
1. **Authentication Issues**
   ```bash
   # Check image pull secrets
   kubectl get secret <image-pull-secret> -o yaml
   
   # Create new secret
   kubectl create secret docker-registry <secret-name> \
     --docker-server=<registry-server> \
     --docker-username=<username> \
     --docker-password=<password>
   ```

2. **Network Issues**
   - Check NAT Gateway configuration
   - Verify security group rules
   - Validate VPC endpoints for ECR

3. **Image Repository Issues**
   - Verify image exists in repository
   - Check repository permissions
   - Validate image tag

### OOMKilled Pods

**Symptoms:**
- Pods terminated with exit code 137
- Memory usage exceeds limits
- Application performance degradation

**Diagnosis:**
```bash
# Check resource usage
kubectl top pod <pod-name>
kubectl describe pod <pod-name> | grep -A5 "Last State"

# Check memory metrics
kubectl get --raw /metrics | grep container_memory
```

**Remediation:**
```bash
# Increase memory limits
kubectl patch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<container-name>","resources":{"limits":{"memory":"2Gi"},"requests":{"memory":"1Gi"}}}]}}}}'

# Add memory monitoring
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    resources:
      limits:
        memory: "1Gi"
      requests:
        memory: "512Mi"
EOF
```

## Network Connectivity

### Pod-to-Pod Communication Issues

**Symptoms:**
- Pods cannot communicate with each other
- Service discovery not working
- DNS resolution failures

**Diagnosis:**
```bash
# Test pod connectivity
kubectl exec -it <source-pod> -- ping <target-pod-ip>
kubectl exec -it <source-pod> -- nslookup <service-name>

# Check CNI configuration
kubectl get pods -n kube-system -l k8s-app=aws-node
kubectl logs -n kube-system -l k8s-app=aws-node

# Check CoreDNS
kubectl get pods -n kube-system -l k8s-app=kube-dns
kubectl logs -n kube-system -l k8s-app=kube-dns
```

**Common Solutions:**
1. **CNI Issues**
   ```bash
   # Restart CNI pods
   kubectl delete pods -n kube-system -l k8s-app=aws-node
   
   # Check security group rules
   aws ec2 describe-security-groups --group-ids <cluster-sg-id>
   ```

2. **DNS Issues**
   ```bash
   # Restart CoreDNS
   kubectl rollout restart -n kube-system deployment/coredns
   
   # Check DNS configuration
   kubectl get configmap -n kube-system coredns -o yaml
   ```

### LoadBalancer Service Issues

**Symptoms:**
- LoadBalancer service stuck in Pending state
- External traffic cannot reach services
- SSL/TLS certificate issues

**Diagnosis:**
```bash
# Check service status
kubectl get svc -o wide
kubectl describe svc <service-name>

# Check AWS Load Balancer Controller logs
kubectl logs -n kube-system deployment/aws-load-balancer-controller

# Check target groups
aws elbv2 describe-target-groups
aws elbv2 describe-target-health --target-group-arn <arn>
```

**Solutions:**
1. **Controller Issues**
   ```bash
   # Install/update AWS Load Balancer Controller
   kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller//crds?ref=master"
   ```

2. **Security Group Configuration**
   ```bash
   # Allow traffic from LoadBalancer to nodes
   aws ec2 authorize-security-group-ingress \
     --group-id <node-sg-id> \
     --protocol tcp \
     --port 30000-32767 \
     --source-group <lb-sg-id>
   ```

## Storage Issues

### PersistentVolume Problems

**Symptoms:**
- PVCs stuck in Pending state
- Pods cannot mount volumes
- Data loss or corruption

**Diagnosis:**
```bash
# Check PV/PVC status
kubectl get pv,pvc -o wide
kubectl describe pvc <pvc-name>

# Check EBS CSI driver
kubectl get pods -n kube-system -l app=ebs-csi-controller
kubectl logs -n kube-system -l app=ebs-csi-controller

# Check volume attachments
aws ec2 describe-volumes --volume-ids <volume-id>
```

**Common Solutions:**
1. **StorageClass Issues**
   ```bash
   # Check available storage classes
   kubectl get storageclass
   
   # Create EBS storage class
   kubectl apply -f - <<EOF
   apiVersion: storage.k8s.io/v1
   kind: StorageClass
   metadata:
     name: ebs-gp3
   provisioner: ebs.csi.aws.com
   parameters:
     type: gp3
     fsType: ext4
   EOF
   ```

2. **Volume Mounting Issues**
   ```bash
   # Check node permissions
   aws iam list-attached-role-policies --role-name <node-role-name>
   
   # Restart CSI driver
   kubectl rollout restart -n kube-system daemonset/ebs-csi-node
   ```

## Security and RBAC

### RBAC Permission Errors

**Symptoms:**
- "Forbidden" errors when accessing resources
- ServiceAccounts cannot perform operations
- Users cannot access cluster resources

**Diagnosis:**
```bash
# Check current user permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default

# Check RBAC bindings
kubectl get clusterrolebinding,rolebinding -A
kubectl describe clusterrolebinding <binding-name>

# Check aws-auth ConfigMap
kubectl get configmap -n kube-system aws-auth -o yaml
```

**Solutions:**
1. **Update aws-auth ConfigMap**
   ```bash
   kubectl patch configmap/aws-auth -n kube-system --type merge -p '{"data":{"mapUsers":"[{\"userarn\":\"arn:aws:iam::ACCOUNT:user/USERNAME\",\"username\":\"USERNAME\",\"groups\":[\"system:masters\"]}]"}}'
   ```

2. **Create ServiceAccount with Permissions**
   ```bash
   kubectl create serviceaccount <sa-name>
   kubectl create clusterrolebinding <binding-name> \
     --clusterrole=cluster-admin \
     --serviceaccount=default:<sa-name>
   ```

### Pod Security Issues

**Symptoms:**
- Pods failing security admission checks
- PSA/PSP violations
- Container runtime security errors

**Diagnosis:**
```bash
# Check admission controllers
kubectl get events | grep -i "admission"

# Check security contexts
kubectl get pod <pod-name> -o yaml | grep -A10 securityContext

# Check PSA labels
kubectl get namespace <namespace> --show-labels
```

**Solutions:**
```bash
# Add security context to pod
kubectl patch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"securityContext":{"runAsUser":1000,"runAsGroup":1000,"fsGroup":1000}}}}}'

# Set namespace PSA level
kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=baseline
```

## Performance Problems

### High Resource Usage

**Symptoms:**
- Nodes running out of CPU/memory
- Slow pod startup times
- Application response time issues

**Diagnosis:**
```bash
# Check resource usage
kubectl top nodes
kubectl top pods -A

# Check metrics server
kubectl get pods -n kube-system | grep metrics-server
kubectl logs -n kube-system deployment/metrics-server

# Check resource quotas
kubectl get resourcequota -A
kubectl describe resourcequota <quota-name>
```

**Solutions:**
1. **Optimize Resource Allocation**
   ```bash
   # Set appropriate resource requests/limits
   kubectl patch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<container-name>","resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"200m","memory":"256Mi"}}}]}}}}'
   ```

2. **Scale Resources**
   ```bash
   # Scale deployment
   kubectl scale deployment <deployment-name> --replicas=3
   
   # Enable HPA
   kubectl autoscale deployment <deployment-name> --cpu-percent=50 --min=1 --max=10
   ```

## Monitoring and Logging

### CloudWatch Integration

**Setup Container Insights:**
```bash
# Install CloudWatch agent
kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/cloudwatch-namespace.yaml

# Configure Fluent Bit for logs
kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/fluent-bit/fluent-bit.yaml
```

### Prometheus and Grafana

**Install monitoring stack:**
```bash
# Add Prometheus Helm repository
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

# Install Prometheus
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace

# Port forward to access Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80
```

### Common Monitoring Queries

**Important metrics to monitor:**

1. **Node Health:**
   - `kube_node_status_condition{condition="Ready",status="true"}`
   - `node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes`
   - `1 - rate(node_cpu_seconds_total{mode="idle"}[5m])`

2. **Pod Health:**
   - `kube_pod_container_status_restarts_total`
   - `kube_pod_status_phase{phase="Running"}`
   - `container_memory_usage_bytes / container_spec_memory_limit_bytes`

3. **Cluster Health:**
   - `up{job="apiserver"}`
   - `etcd_server_leader_changes_seen_total`
   - `apiserver_request_duration_seconds`

## Emergency Procedures

### Cluster Recovery Steps

1. **Immediate Assessment:**
   ```bash
   # Check cluster status
   aws eks describe-cluster --name <cluster-name>
   kubectl cluster-info
   kubectl get nodes
   kubectl get pods -A | grep -v Running
   ```

2. **Critical System Recovery:**
   ```bash
   # Restart system pods
   kubectl rollout restart -n kube-system daemonset/aws-node
   kubectl rollout restart -n kube-system daemonset/kube-proxy
   kubectl rollout restart -n kube-system deployment/coredns
   ```

3. **Node Recovery:**
   ```bash
   # Drain problematic nodes
   kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
   
   # Terminate instance (if using managed node group)
   aws ec2 terminate-instances --instance-ids <instance-id>
   ```

### Escalation Procedures

1. **Level 1:** Restart affected pods/services
2. **Level 2:** Scale resources or restart nodes
3. **Level 3:** Contact AWS Support for control plane issues
4. **Level 4:** Disaster recovery procedures

### Key Contacts and Resources

- AWS Support: Enterprise/Business Support case
- EKS Documentation: https://docs.aws.amazon.com/eks/
- Kubernetes Documentation: https://kubernetes.io/docs/
- AWS EKS Best Practices Guide: https://aws.github.io/aws-eks-best-practices/

---

*This guide should be regularly updated based on new issues encountered and lessons learned from troubleshooting activities.*
