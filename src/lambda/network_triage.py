"""
EKS Doctor - Network Triage Lambda Function
Production-grade network connectivity and configuration analysis for EKS clusters.
"""

import os
import json
import boto3
import logging
import time
import traceback
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from botocore.exceptions import ClientError, BotoCoreError
import ipaddress

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
HUB_SESSION = boto3.Session()
EXTERNAL_ID = os.environ.get("EXTERNAL_ID")
SPOKE_ROLE_READONLY = os.environ.get("SPOKE_ROLE_READONLY", "eks-ops-readonly")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME")

# Constants
MAX_ENI_ANALYSIS = 100
MAX_SECURITY_GROUP_RULES = 200
NETWORK_CHECK_TIMEOUT = 30


@dataclass
class SecurityGroupRule:
    """Data class for security group rule analysis"""
    type: str  # 'ingress' or 'egress'
    protocol: str
    from_port: Optional[int]
    to_port: Optional[int]
    source_destination: str
    description: Optional[str]
    is_risky: bool = False
    risk_reason: Optional[str] = None


@dataclass
class SecurityGroupAnalysis:
    """Data class for security group analysis"""
    group_id: str
    group_name: str
    description: str
    vpc_id: str
    ingress_rules: List[SecurityGroupRule]
    egress_rules: List[SecurityGroupRule]
    risk_level: str  # 'low', 'medium', 'high'
    issues: List[str]
    recommendations: List[str]


@dataclass
class SubnetAnalysis:
    """Data class for subnet analysis"""
    subnet_id: str
    cidr_block: str
    availability_zone: str
    vpc_id: str
    is_public: bool
    available_ips: int
    total_ips: int
    utilization_percentage: float
    route_table_id: str
    has_igw_route: bool
    has_nat_route: bool
    issues: List[str]
    recommendations: List[str]


@dataclass
class NetworkInterfaceAnalysis:
    """Data class for ENI analysis"""
    interface_id: str
    interface_type: str
    status: str
    subnet_id: str
    private_ip: Optional[str]
    public_ip: Optional[str]
    security_groups: List[str]
    attachment_status: Optional[str]
    instance_id: Optional[str]
    description: str
    issues: List[str]


@dataclass
class VpcAnalysis:
    """Data class for VPC analysis"""
    vpc_id: str
    cidr_block: str
    state: str
    is_default: bool
    dns_hostnames: bool
    dns_resolution: bool
    tenancy: str
    flow_logs_enabled: bool
    issues: List[str]
    recommendations: List[str]


@dataclass
class NetworkHealth:
    """Data class for overall network health"""
    cluster_name: str
    region: str
    account_id: str
    timestamp: str
    vpc_analysis: VpcAnalysis
    subnet_analyses: List[SubnetAnalysis]
    security_group_analyses: List[SecurityGroupAnalysis]
    network_interface_analyses: List[NetworkInterfaceAnalysis]
    connectivity_issues: List[str]
    configuration_issues: List[str]
    recommendations: List[str]
    risk_score: int  # 0-100, higher means more risk
    overall_status: str  # 'healthy', 'warning', 'critical'


class EKSNetworkAnalyzer:
    """Main class for EKS network analysis"""
    
    def __init__(self, hub_session: boto3.Session):
        self.hub_session = hub_session
        self.logger = logger
        
    def assume_spoke_role(self, spoke_account_id: str, role_name: str) -> boto3.Session:
        """Assume role in spoke account"""
        try:
            sts_client = self.hub_session.client("sts")
            
            self.logger.info(f"Assuming role {role_name} in account {spoke_account_id}")
            
            response = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{spoke_account_id}:role/{role_name}",
                RoleSessionName=f"eks-network-triage-{int(time.time())}",
                ExternalId=EXTERNAL_ID,
                DurationSeconds=3600,
            )
            
            credentials = response["Credentials"]
            
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=self.hub_session.region_name
            )
            
            # Validate the assumed role
            identity = session.client('sts').get_caller_identity()
            self.logger.info(f"Successfully assumed role: {identity['Arn']}")
            
            return session
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            self.logger.error(f"Failed to assume role {role_name} in {spoke_account_id}: {error_code} - {error_message}")
            raise
            
        except Exception as e:
            self.logger.error(f"Unexpected error assuming role: {str(e)}")
            raise
    
    def analyze_vpc(self, ec2_client, vpc_id: str) -> VpcAnalysis:
        """Analyze VPC configuration"""
        try:
            # Get VPC details
            vpcs = ec2_client.describe_vpcs(VpcIds=[vpc_id])['Vpcs']
            if not vpcs:
                raise ValueError(f"VPC {vpc_id} not found")
            
            vpc = vpcs[0]
            
            # Check VPC attributes
            vpc_attributes = {}
            try:
                dns_support = ec2_client.describe_vpc_attribute(
                    VpcId=vpc_id, 
                    Attribute='enableDnsSupport'
                )['EnableDnsSupport']['Value']
                
                dns_hostnames = ec2_client.describe_vpc_attribute(
                    VpcId=vpc_id, 
                    Attribute='enableDnsHostnames'
                )['EnableDnsHostnames']['Value']
                
                vpc_attributes['dns_support'] = dns_support
                vpc_attributes['dns_hostnames'] = dns_hostnames
                
            except Exception as e:
                self.logger.warning(f"Failed to get VPC attributes: {str(e)}")
                vpc_attributes['dns_support'] = False
                vpc_attributes['dns_hostnames'] = False
            
            # Check for VPC Flow Logs
            flow_logs_enabled = False
            try:
                flow_logs = ec2_client.describe_flow_logs(
                    Filters=[
                        {'Name': 'resource-id', 'Values': [vpc_id]},
                        {'Name': 'flow-log-status', 'Values': ['ACTIVE']}
                    ]
                )['FlowLogs']
                flow_logs_enabled = len(flow_logs) > 0
            except Exception as e:
                self.logger.warning(f"Failed to check VPC flow logs: {str(e)}")
            
            # Identify issues
            issues = []
            recommendations = []
            
            if not vpc_attributes['dns_support']:
                issues.append("DNS resolution is disabled in VPC")
                recommendations.append("Enable DNS resolution for proper EKS functionality")
            
            if not vpc_attributes['dns_hostnames']:
                issues.append("DNS hostnames are disabled in VPC")
                recommendations.append("Enable DNS hostnames for EKS nodes")
            
            if not flow_logs_enabled:
                issues.append("VPC Flow Logs are not enabled")
                recommendations.append("Enable VPC Flow Logs for network monitoring and security")
            
            if vpc['State'] != 'available':
                issues.append(f"VPC is in {vpc['State']} state")
            
            return VpcAnalysis(
                vpc_id=vpc_id,
                cidr_block=vpc['CidrBlock'],
                state=vpc['State'],
                is_default=vpc['IsDefault'],
                dns_hostnames=vpc_attributes['dns_hostnames'],
                dns_resolution=vpc_attributes['dns_support'],
                tenancy=vpc.get('InstanceTenancy', 'default'),
                flow_logs_enabled=flow_logs_enabled,
                issues=issues,
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Failed to analyze VPC {vpc_id}: {str(e)}")
            raise
    
    def analyze_subnets(self, ec2_client, subnet_ids: List[str]) -> List[SubnetAnalysis]:
        """Analyze subnet configurations"""
        subnet_analyses = []
        
        try:
            if not subnet_ids:
                return subnet_analyses
            
            # Get subnet details
            subnets = ec2_client.describe_subnets(SubnetIds=subnet_ids)['Subnets']
            
            # Get route tables for all subnets
            route_tables = ec2_client.describe_route_tables()['RouteTables']
            
            for subnet in subnets:
                try:
                    subnet_id = subnet['SubnetId']
                    cidr_block = subnet['CidrBlock']
                    
                    # Calculate IP utilization
                    available_ips = subnet['AvailableIpAddressCount']
                    total_ips = int(ipaddress.IPv4Network(cidr_block, strict=False).num_addresses) - 5  # AWS reserves 5 IPs
                    utilization_percentage = ((total_ips - available_ips) / total_ips) * 100 if total_ips > 0 else 0
                    
                    # Find associated route table
                    route_table_id = None
                    has_igw_route = False
                    has_nat_route = False
                    
                    for rt in route_tables:
                        # Check if this route table is associated with the subnet
                        is_associated = False
                        
                        # Check explicit subnet associations
                        for assoc in rt.get('Associations', []):
                            if assoc.get('SubnetId') == subnet_id:
                                is_associated = True
                                route_table_id = rt['RouteTableId']
                                break
                        
                        # If not explicitly associated, check if it's the main route table for the VPC
                        if not is_associated:
                            for assoc in rt.get('Associations', []):
                                if assoc.get('Main', False) and rt['VpcId'] == subnet['VpcId']:
                                    route_table_id = rt['RouteTableId']
                                    is_associated = True
                                    break
                        
                        if is_associated:
                            # Check for IGW and NAT routes
                            for route in rt.get('Routes', []):
                                if route.get('GatewayId', '').startswith('igw-'):
                                    has_igw_route = True
                                elif route.get('NatGatewayId') or route.get('InstanceId'):
                                    has_nat_route = True
                            break
                    
                    # Determine if subnet is public
                    is_public = has_igw_route
                    
                    # Identify issues and recommendations
                    issues = []
                    recommendations = []
                    
                    if utilization_percentage > 90:
                        issues.append(f"Subnet is {utilization_percentage:.1f}% utilized")
                        recommendations.append("Consider using a larger CIDR block or additional subnets")
                    elif utilization_percentage > 75:
                        recommendations.append("Monitor IP address utilization closely")
                    
                    if is_public and not subnet.get('MapPublicIpOnLaunch', False):
                        recommendations.append("Consider enabling auto-assign public IP for public subnets")
                    
                    if not is_public and not has_nat_route:
                        issues.append("Private subnet has no NAT Gateway route for outbound connectivity")
                        recommendations.append("Add NAT Gateway route for outbound internet access")
                    
                    if available_ips < 10:
                        issues.append(f"Only {available_ips} IP addresses available")
                    
                    subnet_analysis = SubnetAnalysis(
                        subnet_id=subnet_id,
                        cidr_block=cidr_block,
                        availability_zone=subnet['AvailabilityZone'],
                        vpc_id=subnet['VpcId'],
                        is_public=is_public,
                        available_ips=available_ips,
                        total_ips=total_ips,
                        utilization_percentage=utilization_percentage,
                        route_table_id=route_table_id or "unknown",
                        has_igw_route=has_igw_route,
                        has_nat_route=has_nat_route,
                        issues=issues,
                        recommendations=recommendations
                    )
                    
                    subnet_analyses.append(subnet_analysis)
                    
                except Exception as e:
                    self.logger.error(f"Failed to analyze subnet {subnet.get('SubnetId', 'unknown')}: {str(e)}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Failed to analyze subnets: {str(e)}")
            
        return subnet_analyses
    
    def analyze_security_group(self, ec2_client, group_id: str) -> SecurityGroupAnalysis:
        """Analyze security group configuration"""
        try:
            # Get security group details
            groups = ec2_client.describe_security_groups(GroupIds=[group_id])['SecurityGroups']
            if not groups:
                raise ValueError(f"Security group {group_id} not found")
            
            sg = groups[0]
            
            # Analyze ingress rules
            ingress_rules = []
            for rule in sg.get('IpPermissions', []):
                ingress_rules.extend(self._parse_security_group_rules(rule, 'ingress'))
            
            # Analyze egress rules
            egress_rules = []
            for rule in sg.get('IpPermissionsEgress', []):
                egress_rules.extend(self._parse_security_group_rules(rule, 'egress'))
            
            # Assess risk level and identify issues
            risk_level, issues, recommendations = self._assess_security_group_risk(
                ingress_rules, egress_rules, sg
            )
            
            return SecurityGroupAnalysis(
                group_id=group_id,
                group_name=sg.get('GroupName', 'unknown'),
                description=sg.get('Description', ''),
                vpc_id=sg['VpcId'],
                ingress_rules=ingress_rules,
                egress_rules=egress_rules,
                risk_level=risk_level,
                issues=issues,
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Failed to analyze security group {group_id}: {str(e)}")
            raise
    
    def _parse_security_group_rules(self, rule: Dict, rule_type: str) -> List[SecurityGroupRule]:
        """Parse individual security group rules"""
        rules = []
        
        try:
            protocol = rule.get('IpProtocol', 'unknown')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            
            # Handle different source/destination types
            sources_destinations = []
            
            # IP ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', 'unknown')
                description = ip_range.get('Description', '')
                sources_destinations.append((cidr, description))
            
            # IPv6 ranges
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr = ipv6_range.get('CidrIpv6', 'unknown')
                description = ipv6_range.get('Description', '')
                sources_destinations.append((cidr, description))
            
            # Security groups
            for sg_ref in rule.get('UserIdGroupPairs', []):
                group_id = sg_ref.get('GroupId', 'unknown')
                description = sg_ref.get('Description', '')
                sources_destinations.append((f"sg:{group_id}", description))
            
            # Prefix lists
            for prefix_list in rule.get('PrefixListIds', []):
                pl_id = prefix_list.get('PrefixListId', 'unknown')
                description = prefix_list.get('Description', '')
                sources_destinations.append((f"pl:{pl_id}", description))
            
            # Create rules for each source/destination
            for source_dest, desc in sources_destinations:
                is_risky, risk_reason = self._assess_rule_risk(
                    rule_type, protocol, from_port, to_port, source_dest
                )
                
                sg_rule = SecurityGroupRule(
                    type=rule_type,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    source_destination=source_dest,
                    description=desc,
                    is_risky=is_risky,
                    risk_reason=risk_reason
                )
                
                rules.append(sg_rule)
                
        except Exception as e:
            self.logger.warning(f"Failed to parse security group rule: {str(e)}")
            
        return rules
    
    def _assess_rule_risk(
        self, 
        rule_type: str, 
        protocol: str, 
        from_port: Optional[int], 
        to_port: Optional[int], 
        source_dest: str
    ) -> tuple[bool, Optional[str]]:
        """Assess risk level of a security group rule"""
        
        # Check for overly permissive rules
        if source_dest == '0.0.0.0/0':
            if rule_type == 'ingress':
                # High risk ports open to the world
                high_risk_ports = {22, 3389, 1433, 3306, 5432, 6379, 27017}
                
                if protocol == '-1':  # All protocols
                    return True, "All traffic allowed from anywhere (0.0.0.0/0)"
                
                if from_port and to_port:
                    for port in high_risk_ports:
                        if from_port <= port <= to_port:
                            return True, f"High-risk port {port} open to the world"
                
                if from_port == 0 and to_port == 65535:
                    return True, "All ports open to the world"
                    
                return True, "Ingress rule allows traffic from anywhere"
        
        # Check for overly broad CIDR blocks
        try:
            if '/' in source_dest and not source_dest.startswith('sg:'):
                network = ipaddress.ip_network(source_dest, strict=False)
                if network.prefixlen < 16:  # /15 or larger
                    return True, f"Very broad CIDR block ({source_dest}) allowed"
        except:
            pass
        
        # Check for dangerous protocol/port combinations
        dangerous_combinations = [
            {'protocol': 'tcp', 'ports': [22], 'reason': 'SSH access'},
            {'protocol': 'tcp', 'ports': [3389], 'reason': 'RDP access'},
            {'protocol': 'tcp', 'ports': [1433], 'reason': 'SQL Server access'},
            {'protocol': 'tcp', 'ports': [3306], 'reason': 'MySQL access'},
            {'protocol': 'tcp', 'ports': [5432], 'reason': 'PostgreSQL access'},
        ]
        
        if from_port and to_port and not source_dest.startswith('sg:'):
            for combo in dangerous_combinations:
                if protocol == combo['protocol']:
                    for port in combo['ports']:
                        if from_port <= port <= to_port:
                            return True, f"{combo['reason']} from external source"
        
        return False, None
    
    def _assess_security_group_risk(
        self, 
        ingress_rules: List[SecurityGroupRule], 
        egress_rules: List[SecurityGroupRule],
        sg_data: Dict
    ) -> tuple[str, List[str], List[str]]:
        """Assess overall security group risk level"""
        
        issues = []
        recommendations = []
        risk_score = 0
        
        # Count risky rules
        risky_ingress = [rule for rule in ingress_rules if rule.is_risky]
        risky_egress = [rule for rule in egress_rules if rule.is_risky]
        
        # Assess ingress rules
        if risky_ingress:
            issues.extend([f"Risky ingress rule: {rule.risk_reason}" for rule in risky_ingress[:5]])
            risk_score += len(risky_ingress) * 10
        
        # Check for overly permissive egress
        all_egress_rules = [rule for rule in egress_rules if rule.source_destination == '0.0.0.0/0' and rule.protocol == '-1']
        if all_egress_rules:
            issues.append("All outbound traffic allowed to anywhere")
            recommendations.append("Restrict egress rules to specific destinations and ports")
            risk_score += 5
        
        # Check for no ingress rules (might indicate misconfiguration)
        if not ingress_rules:
            issues.append("No ingress rules defined")
            recommendations.append("Verify if this security group should allow any inbound traffic")
        
        # Check for too many rules
        if len(ingress_rules) + len(egress_rules) > 50:
            issues.append("Security group has many rules - may be complex to manage")
            recommendations.append("Consider splitting into multiple security groups for better organization")
        
        # Generate recommendations for risky rules
        if risky_ingress:
            recommendations.append("Review and restrict overly permissive ingress rules")
        
        if len([rule for rule in ingress_rules if '0.0.0.0/0' in rule.source_destination]) > 3:
            recommendations.append("Too many rules allow traffic from anywhere - consider using security group references")
        
        # Determine risk level
        if risk_score >= 30:
            risk_level = 'high'
        elif risk_score >= 15:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return risk_level, issues, recommendations
    
    def analyze_network_interfaces(self, ec2_client, sg_ids: List[str]) -> List[NetworkInterfaceAnalysis]:
        """Analyze network interfaces associated with security groups"""
        interface_analyses = []
        
        try:
            if not sg_ids:
                return interface_analyses
            
            # Get ENIs associated with the security groups
            enis = ec2_client.describe_network_interfaces(
                Filters=[{'Name': 'group-id', 'Values': sg_ids}]
            )['NetworkInterfaces']
            
            # Limit analysis to prevent timeout
            enis = enis[:MAX_ENI_ANALYSIS]
            
            for eni in enis:
                try:
                    interface_id = eni['NetworkInterfaceId']
                    status = eni['Status']
                    subnet_id = eni['SubnetId']
                    
                    # Get IP addresses
                    private_ip = eni.get('PrivateIpAddress')
                    public_ip = None
                    if eni.get('Association'):
                        public_ip = eni['Association'].get('PublicIp')
                    
                    # Get security groups
                    security_groups = [sg['GroupId'] for sg in eni.get('Groups', [])]
                    
                    # Get attachment info
                    attachment = eni.get('Attachment', {})
                    attachment_status = attachment.get('Status')
                    instance_id = attachment.get('InstanceId')
                    
                    # Identify issues
                    issues = []
                    
                    if status != 'in-use':
                        issues.append(f"Network interface is {status}")
                    
                    if not private_ip:
                        issues.append("No private IP address assigned")
                    
                    if attachment_status and attachment_status != 'attached':
                        issues.append(f"Attachment status is {attachment_status}")
                    
                    if not security_groups:
                        issues.append("No security groups attached")
                    
                    # Check for multiple security groups (might indicate complexity)
                    if len(security_groups) > 5:
                        issues.append(f"Many security groups attached ({len(security_groups)})")
                    
                    interface_analysis = NetworkInterfaceAnalysis(
                        interface_id=interface_id,
                        interface_type=eni.get('InterfaceType', 'interface'),
                        status=status,
                        subnet_id=subnet_id,
                        private_ip=private_ip,
                        public_ip=public_ip,
                        security_groups=security_groups,
                        attachment_status=attachment_status,
                        instance_id=instance_id,
                        description=eni.get('Description', ''),
                        issues=issues
                    )
                    
                    interface_analyses.append(interface_analysis)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to analyze network interface {eni.get('NetworkInterfaceId', 'unknown')}: {str(e)}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Failed to analyze network interfaces: {str(e)}")
        
        return interface_analyses
    
    def perform_network_triage(
        self, 
        spoke_account_id: str, 
        region: str, 
        cluster_name: str
    ) -> NetworkHealth:
        """Perform comprehensive network triage"""
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting network triage for cluster {cluster_name} in {spoke_account_id}/{region}")
            
            # Assume spoke role
            spoke_session = self.assume_spoke_role(spoke_account_id, SPOKE_ROLE_READONLY)
            
            # Get EKS cluster network configuration
            eks_client = spoke_session.client("eks", region_name=region)
            ec2_client = spoke_session.client("ec2", region_name=region)
            
            cluster_info = eks_client.describe_cluster(name=cluster_name)["cluster"]
            vpc_config = cluster_info.get("resourcesVpcConfig", {})
            
            vpc_id = vpc_config.get("vpcId")
            subnet_ids = vpc_config.get("subnetIds", [])
            sg_ids = vpc_config.get("securityGroupIds", [])
            
            if not vpc_id:
                raise ValueError(f"No VPC found for cluster {cluster_name}")
            
            self.logger.info(f"Analyzing VPC: {vpc_id}, Subnets: {len(subnet_ids)}, Security Groups: {len(sg_ids)}")
            
            # Perform analyses
            vpc_analysis = self.analyze_vpc(ec2_client, vpc_id)
            subnet_analyses = self.analyze_subnets(ec2_client, subnet_ids)
            
            security_group_analyses = []
            for sg_id in sg_ids:
                try:
                    sg_analysis = self.analyze_security_group(ec2_client, sg_id)
                    security_group_analyses.append(sg_analysis)
                except Exception as e:
                    self.logger.error(f"Failed to analyze security group {sg_id}: {str(e)}")
                    continue
            
            network_interface_analyses = self.analyze_network_interfaces(ec2_client, sg_ids)
            
            # Analyze overall network health
            connectivity_issues = []
            configuration_issues = []
            recommendations = []
            
            # Aggregate issues from components
            connectivity_issues.extend(vpc_analysis.issues)
            for subnet_analysis in subnet_analyses:
                connectivity_issues.extend(subnet_analysis.issues)
            
            for sg_analysis in security_group_analyses:
                configuration_issues.extend(sg_analysis.issues)
            
            for eni_analysis in network_interface_analyses:
                connectivity_issues.extend(eni_analysis.issues)
            
            # Aggregate recommendations
            recommendations.extend(vpc_analysis.recommendations)
            for subnet_analysis in subnet_analyses:
                recommendations.extend(subnet_analysis.recommendations)
            
            for sg_analysis in security_group_analyses:
                recommendations.extend(sg_analysis.recommendations)
            
            # Calculate risk score
            risk_score = self._calculate_network_risk_score(
                vpc_analysis, subnet_analyses, security_group_analyses, network_interface_analyses
            )
            
            # Determine overall status
            if risk_score >= 70 or len(connectivity_issues) >= 5:
                overall_status = 'critical'
            elif risk_score >= 40 or len(connectivity_issues) >= 2:
                overall_status = 'warning'
            else:
                overall_status = 'healthy'
            
            # Create network health object
            network_health = NetworkHealth(
                cluster_name=cluster_name,
                region=region,
                account_id=spoke_account_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                vpc_analysis=vpc_analysis,
                subnet_analyses=subnet_analyses,
                security_group_analyses=security_group_analyses,
                network_interface_analyses=network_interface_analyses,
                connectivity_issues=connectivity_issues[:20],  # Limit issues
                configuration_issues=configuration_issues[:20],
                recommendations=list(set(recommendations))[:15],  # Dedupe and limit
                risk_score=risk_score,
                overall_status=overall_status
            )
            
            execution_time = time.time() - start_time
            self.logger.info(f"Network triage completed in {execution_time:.2f}s - Status: {overall_status}, Risk: {risk_score}")
            
            return network_health
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Network triage failed after {execution_time:.2f}s: {str(e)}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    def _calculate_network_risk_score(
        self,
        vpc_analysis: VpcAnalysis,
        subnet_analyses: List[SubnetAnalysis],
        security_group_analyses: List[SecurityGroupAnalysis],
        network_interface_analyses: List[NetworkInterfaceAnalysis]
    ) -> int:
        """Calculate overall network risk score (0-100)"""
        
        risk_score = 0
        
        # VPC issues (20 points max)
        risk_score += len(vpc_analysis.issues) * 5
        
        # Subnet issues (30 points max)
        for subnet in subnet_analyses:
            risk_score += len(subnet.issues) * 3
            if subnet.utilization_percentage > 90:
                risk_score += 10
            elif subnet.utilization_percentage > 75:
                risk_score += 5
        
        # Security group risk (40 points max)
        for sg in security_group_analyses:
            if sg.risk_level == 'high':
                risk_score += 15
            elif sg.risk_level == 'medium':
                risk_score += 10
            elif sg.risk_level == 'low':
                risk_score += 2
        
        # Network interface issues (10 points max)
        eni_issues = sum(len(eni.issues) for eni in network_interface_analyses)
        risk_score += min(eni_issues * 2, 10)
        
        return min(risk_score, 100)
    
    def publish_metrics(self, network_health: NetworkHealth):
        """Publish network metrics to CloudWatch"""
        try:
            cloudwatch = self.hub_session.client('cloudwatch')
            
            timestamp = datetime.now(timezone.utc)
            namespace = 'EKSDoctor/NetworkHealth'
            
            dimensions = [
                {'Name': 'ClusterName', 'Value': network_health.cluster_name},
                {'Name': 'Region', 'Value': network_health.region},
                {'Name': 'AccountId', 'Value': network_health.account_id}
            ]
            
            metrics = [
                {
                    'MetricName': 'NetworkRiskScore',
                    'Dimensions': dimensions,
                    'Value': network_health.risk_score,
                    'Unit': 'None',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'ConnectivityIssues',
                    'Dimensions': dimensions,
                    'Value': len(network_health.connectivity_issues),
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'ConfigurationIssues',
                    'Dimensions': dimensions,
                    'Value': len(network_health.configuration_issues),
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'HighRiskSecurityGroups',
                    'Dimensions': dimensions,
                    'Value': sum(1 for sg in network_health.security_group_analyses if sg.risk_level == 'high'),
                    'Unit': 'Count',
                    'Timestamp': timestamp
                },
                {
                    'MetricName': 'SubnetUtilizationHigh',
                    'Dimensions': dimensions,
                    'Value': sum(1 for subnet in network_health.subnet_analyses if subnet.utilization_percentage > 75),
                    'Unit': 'Count',
                    'Timestamp': timestamp
                }
            ]
            
            # Add per-subnet utilization metrics
            for subnet in network_health.subnet_analyses:
                subnet_dimensions = dimensions + [
                    {'Name': 'SubnetId', 'Value': subnet.subnet_id}
                ]
                
                metrics.append({
                    'MetricName': 'SubnetUtilizationPercentage',
                    'Dimensions': subnet_dimensions,
                    'Value': subnet.utilization_percentage,
                    'Unit': 'Percent',
                    'Timestamp': timestamp
                })
            
            # Send metrics in batches
            for i in range(0, len(metrics), 20):
                batch = metrics[i:i+20]
                cloudwatch.put_metric_data(
                    Namespace=namespace,
                    MetricData=batch
                )
            
            self.logger.info(f"Published {len(metrics)} network metrics to CloudWatch")
            
        except Exception as e:
            self.logger.error(f"Failed to publish network metrics: {str(e)}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for EKS network triage
    
    Expected event format:
    {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "my-eks-cluster"
    }
    """
    
    request_id = context.aws_request_id if context else "local-test"
    logger.info(f"Starting network triage - Request ID: {request_id}")
    
    try:
        # Validate input
        required_fields = ["spoke_account_id", "region", "cluster"]
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        spoke_account_id = event["spoke_account_id"]
        region = event["region"]
        cluster_name = event["cluster"]
        
        # Validate inputs
        if not spoke_account_id.isdigit() or len(spoke_account_id) != 12:
            raise ValueError("spoke_account_id must be a 12-digit AWS account ID")
        
        logger.info(f"Processing network triage for {cluster_name} in {spoke_account_id}/{region}")
        
        # Create network analyzer and perform triage
        network_analyzer = EKSNetworkAnalyzer(HUB_SESSION)
        network_health = network_analyzer.perform_network_triage(spoke_account_id, region, cluster_name)
        
        # Publish metrics
        network_analyzer.publish_metrics(network_health)
        
        # Prepare response
        response = {
            "ok": True,
            "request_id": request_id,
            "network_health": asdict(network_health),
            "execution_time_ms": int((time.time() - context.get_remaining_time_in_millis() / 1000) * 1000) if context else 0
        }
        
        logger.info(f"Network triage completed successfully - Status: {network_health.overall_status}, Risk: {network_health.risk_score}")
        
        return response
        
    except ValueError as e:
        logger.error(f"Invalid input: {str(e)}")
        return {
            "ok": False,
            "error": "ValidationError",
            "message": str(e),
            "request_id": request_id
        }
        
    except Exception as e:
        logger.error(f"Network triage failed: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return {
            "ok": False,
            "error": "InternalError",
            "message": f"Network triage failed: {str(e)}",
            "request_id": request_id
        }


# For local testing
if __name__ == "__main__":
    test_event = {
        "spoke_account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "test-cluster"
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
        def get_remaining_time_in_millis(self):
            return 30000
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2, default=str))
