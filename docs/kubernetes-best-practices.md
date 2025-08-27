# Kubernetes Best Practices for EKS

## Overview

This document outlines production-ready best practices for running Kubernetes workloads on Amazon EKS. Following these practices ensures reliability, security, scalability, and maintainability of your EKS clusters.

## Table of Contents

1. [Cluster Configuration](#cluster-configuration)
2. [Security Best Practices](#security-best-practices)
3. [Resource Management](#resource-management)
4. [Networking](#networking)
5. [Storage](#storage)
6. [Monitoring and Observability](#monitoring-and-observability)
7. [Deployment Strategies](#deployment-strategies)
8. [Backup and Disaster Recovery](#backup-and-disaster-recovery)

## Cluster Configuration

### Control Plane Configuration

**Enable All Log Types:**
```bash
aws eks update-cluster-config \
  --name <cluster-name> \
  --logging '{"enable":["api","audit","authenticator","controllerManager","scheduler"]}'
```

**Private Endpoint Configuration:**
```bash
# Enable private endpoint access for security
aws eks update-cluster-config \
  --name <cluster-name> \
  --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=false
```

**Version Management:**
- Always run supported Kubernetes versions
- Plan regular upgrade cycles
- Test upgrades in non-production first
- Use blue/green cluster strategy for major upgrades

### Node Group Best Practices

**Managed Node Groups (Preferred):**
```yaml
# Example managed node group configuration
nodeGroups:
  - name: primary-nodes
    instanceType: m5.large
    minSize: 1
    maxSize: 10
    desiredSize: 3
    
    # Use latest AMI
    amiFamily: AmazonLinux2
    
    # Enable IMDSv2
    metadataOptions:
      httpTokens: required
      httpPutResponseHopLimit: 2
    
    # Tagging for cost allocation
    tags:
      Environment: production
      Team: platform
      
    # Subnet placement
    availabilityZones: ["us-east-1a", "us-east-1b", "us-east-1c"]
```

**Instance Selection Guidelines:**
- Use compute-optimized instances for CPU-intensive workloads
- Use memory-optimized instances for memory-intensive applications
- Consider spot instances for cost optimization (non-critical workloads)
- Use multiple instance types for better availability

### Add-ons Management

**Essential Add-ons:**
```bash
# AWS VPC CNI
aws eks create-addon --cluster-name <cluster-name> --addon-name vpc-cni

# CoreDNS
aws eks create-addon --cluster-name <cluster-name> --addon-name coredns

# kube-proxy
aws eks create-addon --cluster-name <cluster-name> --addon-name kube-proxy

# EBS CSI Driver
aws eks create-addon --cluster-name <cluster-name> --addon-name aws-ebs-csi-driver
```

## Security Best Practices

### Identity and Access Management

**Use IAM Roles for Service Accounts (IRSA):**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  namespace: default
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/MyRole
```

**Principle of Least Privilege:**
```yaml
# Example minimal RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: my-service-account
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### Pod Security Standards

**Implement Pod Security Standards:**
```yaml
# Namespace with PSA enforcement
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Security Context Best Practices:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
```

### Network Security

**Network Policies:**
```yaml
# Default deny all ingress traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress

---
# Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

### Secrets Management

**Use AWS Secrets Manager or Parameter Store:**
```yaml
# Using External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: default
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        secretRef:
          accessKeyIDSecretRef:
            name: awssm-secret
            key: access-key-id
          secretAccessKeySecretRef:
            name: awssm-secret
            key: secret-access-key
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: default
spec:
  refreshInterval: 15s
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: database-secret
    creationPolicy: Owner
  data:
  - secretKey: username
    remoteRef:
      key: prod/database
      property: username
  - secretKey: password
    remoteRef:
      key: prod/database
      property: password
```

## Resource Management

### Resource Requests and Limits

**Always Set Resource Requests:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: resource-managed-app
spec:
  template:
    spec:
      containers:
      - name: app
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

**Use Vertical Pod Autoscaler for Right-Sizing:**
```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: vpa-recommender
spec:
  targetRef:
    apiVersion: "apps/v1"
    kind: Deployment
    name: my-app
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: app
      maxAllowed:
        cpu: "1"
        memory: "2Gi"
      minAllowed:
        cpu: "100m"
        memory: "128Mi"
```

### Quality of Service

**Understand QoS Classes:**

1. **Guaranteed (Highest Priority):**
   ```yaml
   resources:
     requests:
       memory: "256Mi"
       cpu: "250m"
     limits:
       memory: "256Mi"
       cpu: "250m"
   ```

2. **Burstable (Medium Priority):**
   ```yaml
   resources:
     requests:
       memory: "128Mi"
       cpu: "100m"
     limits:
       memory: "512Mi"
       cpu: "500m"
   ```

3. **BestEffort (Lowest Priority):**
   ```yaml
   # No resource requests or limits specified
   ```

### Resource Quotas and Limits

**Namespace Resource Quotas:**
```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
  namespace: development
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    count/pods: 50
    count/services: 10
    count/persistentvolumeclaims: 20
```

**Limit Ranges:**
```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limit-range
  namespace: development
spec:
  limits:
  - default:
      memory: "256Mi"
      cpu: "200m"
    defaultRequest:
      memory: "128Mi"
      cpu: "100m"
    type: Container
```

## Networking

### Service Mesh (Optional but Recommended)

**Istio Configuration:**
```yaml
# Enable Istio sidecar injection
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    istio-injection: enabled
```

### Ingress Configuration

**AWS Load Balancer Controller:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: application-ingress
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:region:account:certificate/cert-id
    alb.ingress.kubernetes.io/healthcheck-path: /health
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service
            port:
              number: 80
```

### DNS Configuration

**Customize CoreDNS:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  custom.server: |
    # Custom domain resolution
    example.com:53 {
        errors
        cache 30
        forward . 8.8.8.8 8.8.4.4
    }
```

## Storage

### Persistent Volume Best Practices

**Use StorageClasses:**
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-gp3-encrypted
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
  iops: "3000"
  throughput: "125"
  encrypted: "true"
  fsType: ext4
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
```

**Volume Snapshots:**
```yaml
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: ebs-snapshot-class
driver: ebs.csi.aws.com
deletionPolicy: Delete
```

### Data Protection

**Backup Strategies:**
```yaml
# Using Velero for backup
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: daily-backup
  namespace: velero
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  template:
    includedNamespaces:
    - production
    - staging
    storageLocation: default
    volumeSnapshotLocations:
    - default
    ttl: 720h  # 30 days
```

## Monitoring and Observability

### Metrics Collection

**Prometheus Setup:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: application-metrics
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: my-application
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

**Custom Metrics:**
```yaml
# Application-specific metrics
apiVersion: v1
kind: Service
metadata:
  name: app-metrics
  labels:
    app: my-app
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
spec:
  ports:
  - port: 8080
    name: metrics
  selector:
    app: my-app
```

### Logging Best Practices

**Structured Logging:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "service": "user-service",
  "trace_id": "abc123",
  "message": "User login successful",
  "user_id": "12345",
  "ip_address": "192.168.1.1"
}
```

**Log Aggregation with Fluent Bit:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: amazon-cloudwatch
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         5
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf
        HTTP_Server   On
        HTTP_Listen   0.0.0.0
        HTTP_Port     2020

    [INPUT]
        Name              tail
        Tag               application.*
        Path              /var/log/containers/*.log
        Parser            docker
        DB                /var/log/flb_kube.db
        Mem_Buf_Limit     50MB
        Skip_Long_Lines   On
        Refresh_Interval  10

    [OUTPUT]
        Name                cloudwatch_logs
        Match               application.*
        region              us-east-1
        log_group_name      /aws/containerinsights/my-cluster/application
        auto_create_group   true
```

### Alerting Rules

**Critical Alerts:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: critical-alerts
  namespace: monitoring
spec:
  groups:
  - name: kubernetes-critical
    rules:
    - alert: KubernetesNodeNotReady
      expr: kube_node_status_condition{condition="Ready",status="true"} == 0
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Kubernetes node is not ready"
        description: "Node {{ $labels.node }} has been not ready for more than 5 minutes."
        
    - alert: KubernetesPodCrashLooping
      expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Pod is crash looping"
        description: "Pod {{ $labels.namespace }}/{{ $labels.pod }} is crash looping."
```

## Deployment Strategies

### Rolling Updates

**Deployment Configuration:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rolling-update-app
spec:
  replicas: 10
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
  template:
    spec:
      containers:
      - name: app
        image: myapp:v2
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
```

### Blue/Green Deployments

**Using Argo Rollouts:**
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: blue-green-rollout
spec:
  replicas: 5
  strategy:
    blueGreen:
      activeService: active-service
      previewService: preview-service
      autoPromotionEnabled: false
      scaleDownDelaySeconds: 30
      prePromotionAnalysis:
        templates:
        - templateName: success-rate
        args:
        - name: service-name
          value: preview-service
      postPromotionAnalysis:
        templates:
        - templateName: success-rate
        args:
        - name: service-name
          value: active-service
  selector:
    matchLabels:
      app: blue-green-app
  template:
    metadata:
      labels:
        app: blue-green-app
    spec:
      containers:
      - name: app
        image: myapp:latest
```

### Canary Deployments

**Istio Virtual Service for Canary:**
```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: canary-virtual-service
spec:
  hosts:
  - app.example.com
  http:
  - match:
    - headers:
        canary:
          exact: "true"
    route:
    - destination:
        host: app-service
        subset: v2
  - route:
    - destination:
        host: app-service
        subset: v1
      weight: 90
    - destination:
        host: app-service
        subset: v2
      weight: 10
```

## Health Checks and Probes

### Liveness and Readiness Probes

**HTTP Probes:**
```yaml
containers:
- name: app
  livenessProbe:
    httpGet:
      path: /health
      port: 8080
    initialDelaySeconds: 30
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
  readinessProbe:
    httpGet:
      path: /ready
      port: 8080
    initialDelaySeconds: 10
    periodSeconds: 5
    timeoutSeconds: 3
    failureThreshold: 3
    successThreshold: 1
```

**TCP Probes:**
```yaml
containers:
- name: database
  livenessProbe:
    tcpSocket:
      port: 5432
    initialDelaySeconds: 30
    periodSeconds: 10
  readinessProbe:
    exec:
      command:
      - /bin/sh
      - -c
      - "pg_isready -h localhost -p 5432"
    initialDelaySeconds: 10
    periodSeconds: 5
```

### Startup Probes

**For Slow-Starting Applications:**
```yaml
containers:
- name: slow-app
  startupProbe:
    httpGet:
      path: /health
      port: 8080
    initialDelaySeconds: 10
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 30  # Allow up to 5 minutes for startup
  livenessProbe:
    httpGet:
      path: /health
      port: 8080
    periodSeconds: 10
  readinessProbe:
    httpGet:
      path: /ready
      port: 8080
    periodSeconds: 5
```

## Backup and Disaster Recovery

### Cluster Backup Strategy

**Backup Components:**
1. **etcd backups** (handled by AWS for EKS)
2. **Application data backups**
3. **Configuration backups**
4. **Persistent volume backups**

**Velero Backup Configuration:**
```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: aws-s3-backup
  namespace: velero
spec:
  provider: aws
  objectStorage:
    bucket: my-backup-bucket
    prefix: velero-backups
  config:
    region: us-east-1
    kmsKeyId: arn:aws:kms:us-east-1:account:key/key-id
---
apiVersion: velero.io/v1
kind: VolumeSnapshotLocation
metadata:
  name: aws-ebs-snapshots
  namespace: velero
spec:
  provider: aws
  config:
    region: us-east-1
```

### Disaster Recovery Plan

**RTO/RPO Targets:**
- **RTO (Recovery Time Objective):** < 4 hours
- **RPO (Recovery Point Objective):** < 1 hour

**Recovery Procedures:**

1. **Data Recovery:**
   ```bash
   # Restore from Velero backup
   velero restore create --from-backup backup-20240115
   
   # Restore specific namespace
   velero restore create ns-restore --from-backup backup-20240115 \
     --include-namespaces production
   ```

2. **Cross-Region Failover:**
   ```bash
   # Switch to secondary region cluster
   kubectl config use-context secondary-cluster
   
   # Verify cluster health
   kubectl get nodes
   kubectl get pods -A
   ```

### Business Continuity

**Multi-Region Setup:**
```yaml
# Primary region cluster
apiVersion: v1
kind: ConfigMap
metadata:
  name: region-config
  namespace: kube-system
data:
  primary_region: "us-east-1"
  secondary_region: "us-west-2"
  failover_enabled: "true"
  cross_region_replication: "true"
```

**Application-Level Replication:**
```yaml
# Database replication configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: database-replica
spec:
  template:
    spec:
      containers:
      - name: postgres
        env:
        - name: POSTGRES_REPLICATION_MODE
          value: slave
        - name: POSTGRES_MASTER_HOST
          value: primary-db.us-east-1.rds.amazonaws.com
```

## Cost Optimization

### Resource Optimization

**Cluster Autoscaler Configuration:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - image: k8s.gcr.io/autoscaling/cluster-autoscaler:v1.21.0
        name: cluster-autoscaler
        command:
        - ./cluster-autoscaler
        - --v=4
        - --stderrthreshold=info
        - --cloud-provider=aws
        - --skip-nodes-with-local-storage=false
        - --expander=least-waste
        - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/my-cluster
        - --balance-similar-node-groups
        - --scale-down-enabled=true
        - --scale-down-delay-after-add=10m
        - --scale-down-unneeded-time=10m
```

**Spot Instance Integration:**
```yaml
# Node group with spot instances
nodeGroups:
  - name: spot-nodes
    instancesDistribution:
      instanceTypes: ["m5.large", "m5.xlarge", "m4.large"]
      onDemandBaseCapacity: 1
      onDemandPercentageAboveBaseCapacity: 25
      spotInstancePools: 3
    
    tags:
      NodeType: spot
      
    labels:
      node-type: spot
      
    taints:
      spot-instance: true:NoSchedule
```

**Resource Requests Optimization:**
```yaml
# Use resource requests efficiently
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"  # 2x request for burstability
```

## Security Scanning and Compliance

### Container Image Scanning

**Amazon ECR Image Scanning:**
```bash
# Enable image scanning on ECR repository
aws ecr put-image-scanning-configuration \
  --repository-name my-app \
  --image-scanning-configuration scanOnPush=true
```

### Runtime Security

**Falco Configuration:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-config
  namespace: falco
data:
  falco.yaml: |
    rules_file:
      - /etc/falco/falco_rules.yaml
      - /etc/falco/k8s_audit_rules.yaml
    
    json_output: true
    json_include_output_property: true
    
    http_output:
      enabled: true
      url: http://falcosidekick:2801/
```

### Policy as Code

**OPA Gatekeeper Policies:**
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        properties:
          labels:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        
        violation[{"msg": msg}] {
          required := input.parameters.labels
          provided := input.review.object.metadata.labels
          missing := required[_]
          not provided[missing]
          msg := sprintf("Missing required label: %v", [missing])
        }
```

This comprehensive guide provides the foundation for running production-ready EKS workloads with emphasis on security, reliability, and operational excellence. Regular review and updates of these practices ensure continued alignment with evolving best practices and new Kubernetes features.
