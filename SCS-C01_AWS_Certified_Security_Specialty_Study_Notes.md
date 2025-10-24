# AWS Certified Security - Specialty (SCS-C01) Study Notes

**Last Updated:** October 2025  
**Exam Focus:** AWS Security architecture, implementation, and operations

---

## Table of Contents
1. [Introduction & Shared Responsibility Model](#chapter-1-introduction)
2. [Identity and Access Management (IAM)](#chapter-2-iam)
3. [Managing Accounts](#chapter-3-accounts)
4. [Policies and Procedures for Secure Access](#chapter-4-policies)
5. [Securing the Network: VPC](#chapter-5-vpc)
6. [Network Access Protection Beyond VPC](#chapter-6-advanced-network)
7. [Protecting Data in the Cloud](#chapter-7-data-protection)
8. [Logging and Audit Trails](#chapter-8-logging)
9. [Continuous Monitoring](#chapter-9-monitoring)
10. [Incident Response and Remediation](#chapter-10-incident-response)
11. [Securing Real-World Applications](#chapter-11-application-security)
12. [Key AWS Security Services Reference](#security-services-reference)
13. [Common Exam Traps & Scenarios](#exam-traps)
14. [Acronyms & Definitions](#acronyms)

---

## Chapter 1: Introduction & Shared Responsibility Model {#chapter-1-introduction}

### Core Concepts

**Shared Responsibility Model**
- **AWS Responsibility**: "Security OF the cloud"
  - Physical infrastructure, hardware, network infrastructure
  - Hypervisor and managed service infrastructure
  - AWS services security controls
  
- **Customer Responsibility**: "Security IN the cloud"
  - Guest OS, applications, and data
  - IAM configuration
  - Network and firewall configuration
  - Encryption (data at rest and in transit)
  - Security group configuration

### Key Security Pillars

1. **Identity and Access Management**
   - Users, groups, roles, and policies
   - Least privilege access
   - Multi-factor authentication (MFA)

2. **Detective Controls**
   - Logging and monitoring
   - CloudTrail, CloudWatch, Config

3. **Infrastructure Protection**
   - VPC, security groups, NACLs
   - WAF, Shield, Firewall Manager

4. **Data Protection**
   - Encryption at rest and in transit
   - Key management (KMS, CloudHSM)
   - Data classification

5. **Incident Response**
   - Automated remediation
   - Forensics and analysis
   - Recovery procedures

### Bastion Host
- **Purpose**: Secure entry point for SSH/RDP access to private instances
- **Best Practices**:
  - Place in public subnet with security group restrictions
  - Use MFA and key-based authentication
  - Log all sessions via CloudTrail
  - Consider AWS Systems Manager Session Manager as alternative

### Common Exam Scenarios
- ❌ Assuming AWS secures application-level data
- ✅ Customer must encrypt data and manage keys
- ❌ Believing AWS manages OS patches
- ✅ Customer responsible for OS and application patches on EC2

---

## Chapter 2: Identity and Access Management (IAM) {#chapter-2-iam}

### IAM Core Components

#### 1. Users
- Represent people or applications
- Long-term credentials (password, access keys)
- **Best Practice**: Avoid using root account; create individual IAM users

#### 2. Groups
- Collection of users
- Attach policies to groups, not individual users
- Users inherit permissions from all groups they belong to

#### 3. Roles
- Assumed by users, applications, or services
- Temporary credentials via STS (Security Token Service)
- **Use Cases**:
  - EC2 instance profiles
  - Cross-account access
  - Federation with external identity providers

#### 4. Policies
- JSON documents defining permissions
- Two main types: **Identity-based** and **Resource-based**

### Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}
```

**Key Elements**:
- **Version**: Policy language version (always use "2012-10-17")
- **Statement**: Array of permission statements
- **Effect**: "Allow" or "Deny"
- **Action**: API actions (e.g., s3:GetObject, ec2:DescribeInstances)
- **Resource**: ARN of resource(s)
- **Condition**: Optional constraints (IP, time, MFA, tags)

### Policy Evaluation Logic

**Order of Evaluation**:
1. **Explicit Deny** - Always wins
2. **Explicit Allow** - Required for access
3. **Implicit Deny** - Default (no allow = deny)

**Formula**: By default, all requests are denied (implicit deny) → Explicit allows grant access → Explicit denies override allows

### Policy Types

#### Identity-Based Policies
- Attached to users, groups, or roles
- **Managed Policies**:
  - AWS Managed: Pre-built by AWS (e.g., ReadOnlyAccess)
  - Customer Managed: Custom policies you create
- **Inline Policies**: Directly embedded in user/role

#### Resource-Based Policies
- Attached to resources (S3 buckets, KMS keys, Lambda functions)
- Support cross-account access
- Include "Principal" element

**Example S3 Bucket Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:user/Alice"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

### Permission Boundaries
- Set maximum permissions for IAM entities
- Prevent privilege escalation
- Used in delegated administration scenarios

**Example Use Case**: Allow developers to create IAM roles but limit max permissions

### Attribute-Based Access Control (ABAC)
- Use tags to control access
- More scalable than role-based access control (RBAC)

**Example**: Allow users to access EC2 instances tagged with their department
```json
{
  "Effect": "Allow",
  "Action": "ec2:*",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "ec2:ResourceTag/Department": "${aws:PrincipalTag/Department}"
    }
  }
}
```

### Service Control Policies (SCPs)
- Applied at AWS Organizations level
- Set permission guardrails across accounts
- **Do NOT grant permissions**, only restrict

### Assuming Roles

**AWS CLI Command**:
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name MySession \
  --duration-seconds 3600
```

**Process**:
1. Request temporary credentials from STS
2. Receive: AccessKeyId, SecretAccessKey, SessionToken
3. Use credentials for API calls
4. Credentials expire after specified duration

### IAM Best Practices

✅ **Enable MFA for privileged users**
✅ **Use roles instead of access keys for applications**
✅ **Rotate credentials regularly**
✅ **Apply least privilege principle**
✅ **Use policy conditions to restrict access (IP, time, MFA)**
✅ **Monitor IAM activity with CloudTrail**
✅ **Remove unnecessary users and credentials**

### Common IAM Exam Traps

❌ **Trap**: Believing inline policies are more secure
✅ **Truth**: Managed policies are recommended for reusability and management

❌ **Trap**: Thinking roles require passwords
✅ **Truth**: Roles use temporary credentials; no passwords

❌ **Trap**: Assuming permission boundaries grant permissions
✅ **Truth**: Boundaries only limit maximum permissions

❌ **Trap**: Confusing identity-based and resource-based policies
✅ **Truth**: Identity policies attach to users/roles; resource policies attach to resources and include Principal

### IAM Access Analyzer
- Identifies resources shared with external entities
- Generates findings for S3 buckets, IAM roles, KMS keys, etc.
- Validates policies against AWS best practices

---

## Chapter 3: Managing Accounts {#chapter-3-accounts}

### AWS Organizations

**Purpose**: Centrally manage multiple AWS accounts

**Key Features**:
- **Consolidated billing**: Single payment for all accounts
- **Hierarchical structure**: Organize accounts in Organizational Units (OUs)
- **Service Control Policies (SCPs)**: Apply permission guardrails
- **Cross-account role access**: Simplify account switching

**Organization Structure**:
```
Root
├── OU: Production
│   ├── Account: Prod-App1
│   └── Account: Prod-App2
├── OU: Development
│   ├── Account: Dev-App1
│   └── Account: Dev-App2
└── OU: Security
    └── Account: Security-Logging
```

### Service Control Policies (SCPs)

**SCP Example - Deny Region Access**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```

**SCP Evaluation**:
- Account must have both SCP allow AND IAM policy allow
- SCP deny overrides everything
- Root account not affected by SCPs (but best practice: don't use root)

### Cross-Account Access Patterns

#### Pattern 1: IAM Role Assumption
1. Account A creates role with trust policy allowing Account B
2. Account B users assume role to access Account A resources
3. Temporary credentials issued by STS

**Trust Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::222222222222:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345"
        }
      }
    }
  ]
}
```

**External ID**: Prevents "confused deputy" problem when third parties assume roles

#### Pattern 2: Resource-Based Policies
- Direct access without role assumption
- Supported by: S3, SNS, SQS, Lambda, KMS
- Include Principal element specifying external account

#### Pattern 3: VPC Peering
- Network-level access between VPCs
- Does not grant IAM permissions
- Requires route table and security group updates

### AWS Control Tower

**Purpose**: Automated multi-account setup with governance

**Key Concepts**:
- **Landing Zone**: Well-architected multi-account environment
- **Guardrails**: Preventive (SCPs) and detective (Config rules)
- **Account Factory**: Automated account provisioning
- **Dashboard**: Compliance and governance visibility

**Guardrail Types**:
- **Mandatory**: Always enforced (e.g., enable CloudTrail)
- **Strongly Recommended**: Best practices (e.g., enable MFA)
- **Elective**: Optional based on requirements

### AWS Resource Access Manager (RAM)

**Purpose**: Share AWS resources across accounts/OUs

**Supported Resources**:
- VPC subnets
- Transit Gateway
- Route 53 Resolver rules
- License Manager configurations
- Aurora DB clusters

**Benefits**:
- Reduce resource duplication
- Centralized management
- No data transfer charges between shared resources

### Identity Federation

#### SAML 2.0 Federation
- Integrate corporate identity providers (AD, Okta, etc.)
- Users authenticate with IdP, receive SAML assertion
- Exchange assertion for AWS temporary credentials

**Flow**:
1. User authenticates with corporate IdP
2. IdP returns SAML assertion
3. User calls STS AssumeRoleWithSAML
4. STS returns temporary credentials
5. User accesses AWS resources

#### Web Identity Federation (Cognito)
- For mobile/web apps
- Support for social providers (Google, Facebook, Amazon)
- Cognito provides AWS credentials for authenticated users

**Use Case**: Mobile app users accessing S3 photos

### AWS Single Sign-On (SSO)

**Purpose**: Centralized access management for AWS accounts and business applications

**Features**:
- Integration with AWS Organizations
- Support for SAML 2.0 applications
- Built-in identity store or connect to external directory
- Permission sets map to IAM roles

**Permission Set**: Template defining IAM permissions; automatically creates roles in accounts

### Account Security Best Practices

✅ **Use AWS Organizations for multi-account strategy**
✅ **Implement SCPs to enforce security boundaries**
✅ **Enable AWS CloudTrail in all accounts to centralized S3 bucket**
✅ **Use cross-account roles instead of sharing credentials**
✅ **Implement MFA for cross-account access**
✅ **Regularly review and audit cross-account permissions**

### Common Exam Scenarios

- **Scenario**: Centralized logging from multiple accounts
  - **Solution**: Create logging account, enable CloudTrail in all accounts with S3 bucket in logging account, use bucket policy to allow cross-account writes

- **Scenario**: Prevent accounts from leaving specific regions
  - **Solution**: Apply SCP denying actions outside allowed regions

- **Scenario**: Third-party access to S3 bucket
  - **Solution**: Create role with external ID, provide role ARN and external ID to third party

---

## Chapter 4: Policies and Procedures for Secure Access {#chapter-4-policies}

### IAM Best Practices Framework

#### 1. Enforce Multi-Factor Authentication (MFA)

**MFA Options**:
- Virtual MFA (Google Authenticator, Authy)
- Hardware MFA (YubiKey, Gemalto)
- SMS-based MFA (not recommended for high security)

**Enforce MFA with Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

#### 2. Implement Least Privilege Access

**Strategies**:
- Start with no permissions, add as needed
- Use AWS managed policies as starting point
- Regularly review and remove unused permissions
- Use IAM Access Analyzer to identify overly permissive policies

**Access Advisor**: Shows service-level last accessed information for roles/users

#### 3. Use Separate Accounts for Different Environments

**Account Separation Benefits**:
- Blast radius containment
- Clear billing separation
- Independent IAM boundaries
- Simplified compliance auditing

**Typical Structure**:
- **Master/Management Account**: Billing, Organizations, SSO
- **Security Account**: CloudTrail logs, GuardDuty, Security Hub
- **Log Archive Account**: Centralized logging
- **Production Accounts**: Production workloads
- **Development/Test Accounts**: Non-production environments
- **Shared Services Account**: Networking, AD, monitoring

#### 4. Rotate Credentials Regularly

**Rotation Best Practices**:
- Access keys: 90 days maximum
- Passwords: Per compliance requirements (typically 90 days)
- Automate rotation for application credentials (use Secrets Manager)
- Monitor for unrotated credentials

**AWS CLI to Find Old Access Keys**:
```bash
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d
```

#### 5. Remove Unnecessary Credentials

**What to Remove**:
- Inactive users (no activity in 90+ days)
- Unused access keys
- Overly permissive policies
- Service accounts no longer needed

**IAM Credential Report**: CSV report showing all users and credential status

### Permission Boundaries in Practice

**Use Case**: Allow team leads to create IAM users/roles but prevent privilege escalation

**Boundary Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "ec2:*",
        "rds:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Preventing Privilege Escalation

**Common Privilege Escalation Vectors**:
1. **Creating/updating policies**: Attacker creates policy with elevated permissions
2. **Attaching policies**: Attacker attaches powerful policy to their user/role
3. **Creating access keys for other users**: Attacker gains access to another user's permissions
4. **Updating assume role trust policy**: Attacker allows themselves to assume powerful role

**Mitigation Strategies**:
1. Use permission boundaries
2. Require MFA for sensitive IAM operations
3. Use SCPs to prevent certain high-risk actions
4. Implement strong password policies
5. Monitor IAM changes with CloudTrail and EventBridge

**Policy to Prevent Policy Modification**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### Cyber Kill Chain and AWS Security

**Lockheed Martin Cyber Kill Chain Stages**:
1. **Reconnaissance**: Attacker gathers information
   - AWS Defense: Minimize public exposure, use Security Groups
   
2. **Weaponization**: Attacker prepares exploit
   - AWS Defense: Keep systems patched, use Inspector
   
3. **Delivery**: Attacker delivers exploit
   - AWS Defense: WAF, email security, Shield
   
4. **Exploitation**: Exploit executes
   - AWS Defense: GuardDuty, runtime protection
   
5. **Installation**: Malware installed
   - AWS Defense: Host-based IDS, Systems Manager
   
6. **Command & Control (C2)**: Attacker establishes control
   - AWS Defense: VPC Flow Logs, GuardDuty, Network Firewall
   
7. **Actions on Objectives**: Attacker achieves goals
   - AWS Defense: Encryption, backups, incident response

### Password Policies

**AWS IAM Password Policy Options**:
- Minimum password length (8-128 characters)
- Require uppercase letters
- Require lowercase letters
- Require numbers
- Require non-alphanumeric characters
- Password expiration (1-1095 days)
- Prevent password reuse (1-24 previous passwords)
- Allow users to change their own password
- Require administrator reset after expiration

**Setting Password Policy (AWS CLI)**:
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 12
```

### Security Analysis and Monitoring

**Tools for Ongoing Security Posture**:
- **AWS Trusted Advisor**: Basic security recommendations (free tier limited)
- **IAM Access Analyzer**: Identifies external resource access
- **AWS Security Hub**: Centralized security finding aggregation
- **AWS Config**: Track resource configuration and compliance
- **CloudTrail Insights**: Detect unusual API activity

### Key Exam Focus Areas

✅ **Understand permission evaluation logic** (explicit deny > explicit allow > implicit deny)
✅ **Know difference between identity and resource policies**
✅ **Be able to identify privilege escalation risks**
✅ **Understand when to use permission boundaries**
✅ **Know MFA enforcement patterns**
✅ **Recognize least privilege violations**

### Common Exam Traps

❌ **Trap**: Thinking MFA enforcement requires complex setup
✅ **Truth**: Simple condition in policy: `aws:MultiFactorAuthPresent: false` with Deny effect

❌ **Trap**: Assuming SCPs grant permissions
✅ **Truth**: SCPs only restrict; IAM policies still needed to grant access

❌ **Trap**: Believing permission boundaries are for users only
✅ **Truth**: Can be applied to users or roles

---

## Chapter 5: Securing the Network - VPC {#chapter-5-vpc}

### VPC Fundamentals

**Amazon VPC (Virtual Private Cloud)**: Logically isolated network in AWS

**Core Components**:
- **VPC**: Container for network resources
- **Subnets**: Segments of VPC IP address range
- **Route Tables**: Control traffic routing
- **Internet Gateway (IGW)**: VPC access to internet
- **NAT Gateway/Instance**: Outbound internet for private subnets
- **Security Groups**: Stateful firewall at instance level
- **Network ACLs (NACLs)**: Stateless firewall at subnet level

### VPC Design Patterns

#### CIDR Block Selection
- **VPC CIDR**: /16 to /28 (65,536 to 16 IPs)
- **Recommended**: Use RFC 1918 private ranges
  - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
  - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)

**Example VPC Layout**:
```
VPC: 10.0.0.0/16
├── Public Subnet A:  10.0.1.0/24 (us-east-1a)
├── Public Subnet B:  10.0.2.0/24 (us-east-1b)
├── Private Subnet A: 10.0.10.0/24 (us-east-1a)
├── Private Subnet B: 10.0.11.0/24 (us-east-1b)
├── Data Subnet A:    10.0.20.0/24 (us-east-1a)
└── Data Subnet B:    10.0.21.0/24 (us-east-1b)
```

**AWS Reserved IPs per Subnet** (first 4 and last 1):
- .0 - Network address
- .1 - VPC router
- .2 - DNS server
- .3 - Reserved for future use
- .255 - Broadcast (not supported but reserved)

### Creating VPC

**AWS CLI Command**:
```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16

# Create Subnet
aws ec2 create-subnet \
  --vpc-id vpc-abc123 \
  --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a

# Create Internet Gateway
aws ec2 create-internet-gateway

# Attach IGW to VPC
aws ec2 attach-internet-gateway \
  --internet-gateway-id igw-xyz789 \
  --vpc-id vpc-abc123
```

### Subnet Types

#### Public Subnet
- Has route to Internet Gateway (0.0.0.0/0 → IGW)
- Resources get public IP addresses
- Used for: Load balancers, bastion hosts, NAT gateways

#### Private Subnet
- No direct route to Internet Gateway
- Outbound internet via NAT Gateway/Instance
- Used for: Application servers, databases

#### Isolated Subnet
- No route to internet (inbound or outbound)
- VPC endpoints for AWS service access
- Used for: Highly sensitive databases

### Route Tables

**Route Table Basics**:
- Each subnet associated with one route table
- Routes evaluated: most specific match wins
- Local route (VPC CIDR) automatically present and cannot be removed

**Example Public Subnet Route Table**:
| Destination | Target |
|-------------|--------|
| 10.0.0.0/16 | local |
| 0.0.0.0/0 | igw-xyz789 |

**Example Private Subnet Route Table**:
| Destination | Target |
|-------------|--------|
| 10.0.0.0/16 | local |
| 0.0.0.0/0 | nat-abc123 |

### NAT Gateway vs NAT Instance

| Feature | NAT Gateway | NAT Instance |
|---------|-------------|--------------|
| **Availability** | Managed HA | Single EC2 |
| **Bandwidth** | Up to 100 Gbps | Depends on instance type |
| **Maintenance** | AWS managed | Customer managed |
| **Cost** | Per hour + data processing | EC2 instance cost |
| **Security Groups** | N/A | Yes |
| **Use as bastion** | No | Yes |
| **Port forwarding** | No | Yes |

**Best Practice**: Use NAT Gateway for production, NAT instance only for cost-sensitive dev/test

### Security Groups

**Key Characteristics**:
- **Stateful**: Return traffic automatically allowed
- **Instance-level**: Attached to ENIs (Elastic Network Interfaces)
- **Default**: All inbound denied, all outbound allowed
- **Rules**: Allow rules only (no deny rules)
- **Evaluation**: All rules evaluated; most permissive wins

**Security Group Rule Structure**:
- **Type**: Protocol (TCP, UDP, ICMP, or All)
- **Port Range**: Single port or range
- **Source/Destination**: CIDR block, security group ID, prefix list
- **Description**: Optional but recommended

**Example Web Server Security Group**:
```bash
# Inbound Rules
Type        Port    Source          Description
HTTP        80      0.0.0.0/0       Allow HTTP from anywhere
HTTPS       443     0.0.0.0/0       Allow HTTPS from anywhere
SSH         22      10.0.0.0/16     Allow SSH from VPC only

# Outbound Rules
Type        Port    Destination     Description
All         All     0.0.0.0/0       Allow all outbound
```

**Referencing Security Groups in Rules**:
- Source can be another security group ID
- Allows dynamic security rules
- Useful for multi-tier architectures

**Example**:
- Web tier SG: Allow inbound 443 from ALB SG
- App tier SG: Allow inbound 8080 from Web SG
- DB tier SG: Allow inbound 3306 from App SG

### Network ACLs (NACLs)

**Key Characteristics**:
- **Stateless**: Separate inbound and outbound rules; return traffic must be explicitly allowed
- **Subnet-level**: Apply to all resources in subnet
- **Default**: Default NACL allows all inbound and outbound
- **Custom NACL**: Denies all inbound and outbound by default
- **Rule Evaluation**: Numbered rules evaluated in order; first match wins
- **Rules**: Support both allow and deny

**NACL Rule Structure**:
- **Rule Number**: 1-32766 (lower numbers evaluated first)
- **Type**: Protocol
- **Port Range**: Port or range
- **Source/Destination**: CIDR block
- **Allow/Deny**: Action to take

**Example NACL Rules**:
```
Inbound Rules:
Rule #  Type    Port    Source          Action
100     HTTP    80      0.0.0.0/0       ALLOW
110     HTTPS   443     0.0.0.0/0       ALLOW
120     SSH     22      203.0.113.0/24  ALLOW
*       All     All     0.0.0.0/0       DENY

Outbound Rules:
Rule #  Type        Port        Destination     Action
100     All         All         0.0.0.0/0       ALLOW
*       All         All         0.0.0.0/0       DENY
```

**Ephemeral Ports**: For stateless NACLs, allow outbound ephemeral ports (1024-65535) for return traffic

### Security Groups vs NACLs

| Feature | Security Groups | NACLs |
|---------|----------------|--------|
| **Level** | Instance (ENI) | Subnet |
| **State** | Stateful | Stateless |
| **Rules** | Allow only | Allow and Deny |
| **Evaluation** | All rules | First match |
| **Default** | Deny all inbound | Allow all (default NACL) |
| **Use Case** | Primary firewall | Additional layer, deny specific IPs |

**Best Practice**: Use Security Groups as primary control, NACLs for additional defense in depth

### VPC Flow Logs

**Purpose**: Capture IP traffic information for VPC, subnet, or ENI

**Log Levels**:
- VPC level: All ENIs in VPC
- Subnet level: All ENIs in subnet
- ENI level: Specific network interface

**Flow Log Fields**:
```
version account-id interface-id srcaddr dstaddr srcport dstport 
protocol packets bytes start end action log-status
```

**Log Destinations**:
- CloudWatch Logs
- S3
- Kinesis Data Firehose

**Common Use Cases**:
- Troubleshoot connectivity issues
- Security analysis and anomaly detection
- Compliance and audit requirements

**Query Flow Logs in Athena**:
```sql
SELECT srcaddr, dstaddr, srcport, dstport, protocol, action, COUNT(*) as count
FROM vpc_flow_logs
WHERE action = 'REJECT'
GROUP BY srcaddr, dstaddr, srcport, dstport, protocol, action
ORDER BY count DESC
LIMIT 100;
```

### VPC Peering

**Purpose**: Private connectivity between VPCs

**Characteristics**:
- **Non-transitive**: VPC A ↔ VPC B and VPC B ↔ VPC C does NOT mean VPC A ↔ VPC C
- **No overlapping CIDR blocks**: VPCs must have unique IP ranges
- **Cross-account and cross-region**: Supported
- **No single point of failure**: AWS-managed HA

**Setup Steps**:
1. Request peering connection from VPC A to VPC B
2. Accept peering connection in VPC B
3. Update route tables in both VPCs
4. Update security groups to allow traffic

**Peering Limitations**:
- No transitive peering
- No edge-to-edge routing (can't route through VPN/DX via peer)
- No overlapping CIDR blocks
- Limit: 125 peering connections per VPC

### VPN Connections

#### Site-to-Site VPN
- **Purpose**: Connect on-premises network to VPC
- **Components**:
  - **Virtual Private Gateway (VGW)**: AWS side VPN endpoint
  - **Customer Gateway (CGW)**: On-premises VPN device
  - **VPN Connection**: IPsec tunnels between VGW and CGW

**Setup**:
```bash
# Create Customer Gateway
aws ec2 create-customer-gateway \
  --type ipsec.1 \
  --public-ip 203.0.113.1 \
  --bgp-asn 65000

# Create Virtual Private Gateway
aws ec2 create-vpn-gateway --type ipsec.1

# Attach VGW to VPC
aws ec2 attach-vpn-gateway \
  --vpn-gateway-id vgw-abc123 \
  --vpc-id vpc-xyz789

# Create VPN Connection
aws ec2 create-vpn-connection \
  --type ipsec.1 \
  --customer-gateway-id cgw-123456 \
  --vpn-gateway-id vgw-abc123
```

**VPN Characteristics**:
- Two IPsec tunnels for redundancy
- Encrypted traffic over internet
- Up to 1.25 Gbps per tunnel
- Supports static routing and BGP dynamic routing

#### AWS Client VPN
- **Purpose**: Remote user VPN access to VPC and on-premises
- **Authentication**: Active Directory, SAML, certificate-based
- **Fully managed**: AWS handles scaling and availability

### AWS Direct Connect

**Purpose**: Dedicated network connection from on-premises to AWS

**Benefits**:
- **Consistent network performance**: Not over internet
- **Lower bandwidth costs**: Reduced data transfer charges
- **Private connectivity**: Traffic doesn't traverse internet
- **Hybrid cloud**: Extend on-premises to AWS

**Direct Connect Gateway**: Connect to multiple VPCs across regions from single DX connection

**DX + VPN**: Use VPN over Direct Connect for encryption (DX itself is not encrypted)

### Common Network Exam Scenarios

**Scenario 1**: Allow web servers to access internet but prevent inbound internet access
- **Solution**: Place in private subnet with NAT Gateway, security group allows outbound 80/443

**Scenario 2**: Connect two VPCs in different accounts
- **Solution**: VPC peering with route table and security group updates

**Scenario 3**: Block specific IP range from accessing resources
- **Solution**: NACL deny rule (security groups can't deny)

**Scenario 4**: Troubleshoot connection issue between instances
- **Solution**: Check Security Groups, NACLs, route tables, VPC Flow Logs

**Scenario 5**: Secure access to AWS services from private subnet without internet
- **Solution**: VPC endpoints (Gateway or Interface endpoints)

### Common Exam Traps

❌ **Trap**: Forgetting NACLs are stateless
✅ **Truth**: Must allow both inbound and outbound + ephemeral ports for return traffic

❌ **Trap**: Assuming VPC peering is transitive
✅ **Truth**: Must explicitly peer each VPC pair

❌ **Trap**: Thinking security groups can deny traffic
✅ **Truth**: Security groups only have allow rules; use NACLs for explicit denies

❌ **Trap**: Believing NAT Gateway provides inbound access
✅ **Truth**: NAT only for outbound; use load balancer for inbound

---

## Chapter 6: Network Access Protection Beyond VPC {#chapter-6-advanced-network}

### Private Connectivity Without Internet Gateway

#### VPC Endpoints

**Purpose**: Private connectivity to AWS services without internet gateway

**Types**:

##### 1. Gateway Endpoints (Free)
- **Supported Services**: S3, DynamoDB only
- **Route Table Entry**: Prefix list as destination
- **No ENI created**: Routes at subnet level
- **No additional charge**

**Example Route Table with Gateway Endpoint**:
```
Destination         Target
10.0.0.0/16        local
pl-123abc (S3)     vpce-xyz789
```

##### 2. Interface Endpoints (PrivateLink)
- **Supported Services**: Most AWS services (EC2, SNS, SQS, etc.)
- **Creates ENI**: In your subnet with private IP
- **DNS**: Endpoint-specific DNS name or private DNS
- **Cost**: Per hour + data processing charges

**Interface Endpoint Security**:
- Security groups control access to endpoint
- Endpoint policies control which actions allowed

**Example Endpoint Policy (S3)**:
```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

**VPC Endpoint vs NAT Gateway**:
| Feature | VPC Endpoint | NAT Gateway |
|---------|--------------|-------------|
| **AWS services** | Yes, private | Yes, via internet |
| **Non-AWS destinations** | No | Yes |
| **Cost** | Lower for AWS services | Higher for AWS services |
| **HA** | Managed | Need multiple for HA |

### AWS Web Application Firewall (WAF)

**Purpose**: Protect web applications from common web exploits

**Deployment Targets**:
- Application Load Balancer (ALB)
- API Gateway
- CloudFront distributions
- AppSync GraphQL APIs
- Cognito User Pools

**WAF Core Concepts**:
- **Web ACL**: Collection of rules
- **Rules**: Conditions to match requests
- **Rule Actions**: Allow, Block, Count
- **Rule Capacity Units (WCU)**: Complexity measure (max 5000 per Web ACL)

#### WAF Rule Types

1. **IP Set Match**: Match source IP addresses
2. **String Match**: Match patterns in URI, query string, headers, body
3. **SQL Injection**: Detect SQL injection attempts
4. **XSS**: Detect cross-site scripting attempts
5. **Size Constraint**: Match request size
6. **Geo Match**: Match country of origin
7. **Rate-based**: Limit requests from single IP (e.g., 2000 req per 5 min)

**Example WAF Rule (Block Large Requests)**:
```json
{
  "Name": "BlockLargeRequests",
  "Priority": 1,
  "Statement": {
    "SizeConstraintStatement": {
      "FieldToMatch": {
        "Body": {}
      },
      "ComparisonOperator": "GT",
      "Size": 8192,
      "TextTransformations": [
        {
          "Priority": 0,
          "Type": "NONE"
        }
      ]
    }
  },
  "Action": {
    "Block": {}
  }
}
```

#### AWS Managed Rule Groups

**Core Rule Sets**:
- **Core Rule Set (CRS)**: OWASP Top 10 protection
- **Known Bad Inputs**: Prevent patterns known to be malicious
- **SQL Database**: SQL injection protection
- **Linux/Windows Operating System**: OS-specific protections
- **PHP/WordPress**: Application-specific rules

**Use Case Rule Sets**:
- **IP Reputation**: Block known malicious IPs (managed by AWS Threat Intelligence)
- **Anonymous IP**: Block traffic from VPNs, proxies, Tor
- **Bot Control**: Managed bot detection and mitigation

**Example Web ACL with Managed Rules**:
```json
{
  "Name": "MyWebACL",
  "Rules": [
    {
      "Name": "AWS-AWSManagedRulesCommonRuleSet",
      "Priority": 0,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet"
        }
      },
      "OverrideAction": {
        "None": {}
      }
    }
  ]
}
```

#### WAF Rate-Based Rules

**Purpose**: Prevent abuse and DDoS

**Example Rate Limiting Rule**:
```json
{
  "Name": "RateLimitRule",
  "Priority": 10,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 2000,
      "AggregateKeyType": "IP"
    }
  },
  "Action": {
    "Block": {}
  }
}
```

**Rate Limiting Options**:
- Per IP address
- Per IP + header
- Per IP + query string
- Per forwarded IP (when behind proxy)

#### WAF Logging and Monitoring

**Log Destinations**:
- S3 bucket
- CloudWatch Logs
- Kinesis Data Firehose

**What's Logged**:
- Timestamp
- HTTP request details (URI, method, headers)
- Client IP
- Rule that matched
- Action taken (Allow/Block/Count)

**Sample WAF Log Analysis**:
```sql
-- Top blocked IPs
SELECT clientIP, COUNT(*) as request_count
FROM waf_logs
WHERE action = 'BLOCK'
GROUP BY clientIP
ORDER BY request_count DESC
LIMIT 100;
```

### AWS Shield

**Purpose**: DDoS protection for AWS resources

#### AWS Shield Standard (Free)
- **Automatic**: Enabled for all AWS customers
- **Protection**: Layer 3/4 (network/transport) DDoS attacks
- **Services**: CloudFront, Route 53, ELB, AWS Global Accelerator
- **No additional cost**

#### AWS Shield Advanced ($3000/month)
- **Enhanced DDoS Protection**: Layer 3, 4, 7
- **24/7 DDoS Response Team (DRT)**: Access to AWS experts
- **Cost Protection**: Credits for scaling costs during attack
- **Real-time Metrics**: CloudWatch metrics and notifications
- **Integration**: WAF included at no extra cost

**Shield Advanced Features**:
- Application layer (HTTP/S) DDoS protection
- DDoS cost protection: Won't be charged for scaling during attack
- Health-based detection: Uses Route 53 health checks
- Attack diagnostics and forensics

**When to Use Shield Advanced**:
✅ Internet-facing applications with high availability requirements
✅ Applications that have been targeted by DDoS in the past
✅ Compliance requirements for DDoS protection
✅ Need for dedicated DRT support

### AWS Network Firewall

**Purpose**: Managed network firewall for VPC-level traffic inspection

**Capabilities**:
- **Stateful inspection**: Track connections
- **Intrusion Prevention System (IPS)**: Signature-based detection
- **Domain name filtering**: Block/allow based on FQDNs
- **Custom rules**: Protocol, port, direction-based filtering

**Deployment**:
- Deployed in firewall subnet
- Route traffic through firewall via route tables
- Centralized via AWS Transit Gateway for multi-VPC

**Rule Groups**:
1. **Stateless**: Fast path filtering (IP, port, protocol)
2. **Stateful**: Deep packet inspection, protocol detection
3. **Domain List**: Allow/deny based on domain names
4. **Suricata Compatible**: Import IPS rules in Suricata format

**Example Domain Filtering Rule**:
```
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (
  tls.sni; content:".amazonaws.com"; 
  msg:"Allow AWS services";
  sid:1000001;
)
```

**Use Cases**:
- Block known bad domains
- Prevent data exfiltration
- IPS for threat prevention
- Centralized internet egress filtering

### Lambda@Edge and CloudFront Functions

**Purpose**: Run code at AWS edge locations for request/response manipulation

#### Lambda@Edge
- **Full Lambda**: Node.js or Python
- **Use Cases**: Complex logic, external service calls
- **Triggers**: Viewer request/response, Origin request/response
- **Limitations**: 
  - Viewer request: 128MB, 5 sec timeout
  - Viewer response: 128MB, 5 sec timeout
  - Origin request: 128MB, 30 sec timeout

**Example Lambda@Edge (Add Security Headers)**:
```javascript
exports.handler = (event, context, callback) => {
    const response = event.Records[0].cf.response;
    const headers = response.headers;
    
    headers['strict-transport-security'] = [{
        key: 'Strict-Transport-Security',
        value: 'max-age=63072000; includeSubdomains; preload'
    }];
    headers['x-content-type-options'] = [{
        key: 'X-Content-Type-Options',
        value: 'nosniff'
    }];
    headers['x-frame-options'] = [{
        key: 'X-Frame-Options',
        value: 'DENY'
    }];
    
    callback(null, response);
};
```

#### CloudFront Functions
- **Lightweight**: JavaScript only
- **Sub-millisecond execution**
- **Use Cases**: Simple transformations, redirects, URL rewrites
- **Triggers**: Viewer request/response only

**When to Use Which**:
| Requirement | Use |
|------------|-----|
| Simple URL rewrite | CloudFront Functions |
| Add security headers | CloudFront Functions |
| Call external API | Lambda@Edge |
| Read/write to database | Lambda@Edge |
| Complex logic > 1ms | Lambda@Edge |
| Sub-millisecond response needed | CloudFront Functions |

### Transit Gateway

**Purpose**: Central hub for connecting VPCs and on-premises networks

**Features**:
- **Hub-and-spoke topology**: Simplifies network management
- **Transitive routing**: Unlike VPC peering
- **Cross-region peering**: Connect Transit Gateways across regions
- **Route tables**: Control routing between attachments
- **Scalability**: Thousands of VPCs

**Attachments**:
- VPC
- VPN
- Direct Connect Gateway
- Transit Gateway (peering)

**Use Case**: Connect 50 VPCs and on-premises network
- **Without TGW**: Would need 50 VPN connections or 1225 peering connections
- **With TGW**: Single Transit Gateway with 50 VPC attachments + 1 VPN

### Third-Party Firewall Integration

**Options**:
- Palo Alto Networks VM-Series
- Cisco ASA
- Fortinet FortiGate
- Check Point CloudGuard

**Deployment Patterns**:
1. **Inline**: Route traffic through firewall instances
2. **Out-of-band**: Mirror traffic for inspection (VPC Traffic Mirroring)
3. **Gateway Load Balancer**: Distribute traffic across firewall fleet

**Gateway Load Balancer (GWLB)**:
- **Purpose**: Scale and HA for third-party appliances
- **Protocol**: GENEVE encapsulation
- **Use Cases**: Firewalls, IPS/IDS, deep packet inspection

**GWLB Flow**:
1. Traffic sent to GWLB
2. GWLB distributes to appliance targets
3. Appliance inspects and returns traffic to GWLB
4. GWLB forwards to destination or drops if threat detected

### Network Security Best Practices

✅ **Use multiple layers of defense** (Security Groups + NACLs + WAF + Shield)
✅ **Implement least privilege network access**
✅ **Use VPC endpoints for AWS service access** (avoid internet gateway)
✅ **Enable VPC Flow Logs for forensics and monitoring**
✅ **Deploy WAF for internet-facing applications**
✅ **Use Shield Advanced for critical applications**
✅ **Centralize egress filtering** with Transit Gateway + Network Firewall
✅ **Regularly review and audit network configurations**

### Common Exam Scenarios

**Scenario**: Prevent SQL injection on web application
- **Solution**: Enable AWS WAF with SQL injection rule group on ALB

**Scenario**: Block traffic from specific countries
- **Solution**: WAF geo-match rule or CloudFront geo-restriction

**Scenario**: DDoS protection for public-facing website
- **Solution**: CloudFront + Shield Standard (included); Shield Advanced for enhanced protection

**Scenario**: Access S3 from private subnet without internet
- **Solution**: S3 VPC Gateway Endpoint

**Scenario**: Centralized egress filtering for multiple VPCs
- **Solution**: Transit Gateway + Network Firewall in inspection VPC

### Common Exam Traps

❌ **Trap**: Confusing Gateway and Interface endpoints
✅ **Truth**: Gateway (S3, DynamoDB, free), Interface (most others, paid)

❌ **Trap**: Thinking WAF works at network layer
✅ **Truth**: WAF is layer 7 (HTTP/HTTPS) only; use Security Groups/NACLs for layer 3/4

❌ **Trap**: Assuming Shield Standard protects against all DDoS
✅ **Truth**: Standard is layer 3/4 only; Advanced adds layer 7 + DRT support

❌ **Trap**: Believing VPC endpoints work for on-premises
✅ **Truth**: VPC endpoints are for AWS services from VPCs, not on-prem

---

## Chapter 7: Protecting Data in the Cloud {#chapter-7-data-protection}

### Data Protection Principles

**Data Security Lifecycle**:
1. **Data at Rest**: Stored on disk
2. **Data in Transit**: Moving over network
3. **Data in Use**: Being processed

**Data Classification**:
- **Public**: No harm if disclosed
- **Internal**: Limited to organization
- **Confidential**: Business-critical, limited access
- **Restricted**: Highly sensitive (PII, PHI, financial)

### Encryption Fundamentals

#### Encryption at Rest

**Encryption Types**:
- **Client-Side Encryption**: Encrypt before sending to AWS
- **Server-Side Encryption**: AWS encrypts after receiving

#### AWS Key Management Service (KMS)

**KMS Key Types**:

1. **AWS Managed Keys**
   - Prefix: `aws/service-name` (e.g., aws/s3)
   - Automatic rotation every 1 year
   - Cannot delete or manage rotation
   - No additional charge

2. **Customer Managed Keys (CMK)**
   - Full control over key policies, rotation, deletion
   - Automatic rotation: Optional, every 1 year
   - Manual rotation: On-demand
   - Cost: $1/month + usage charges

3. **AWS Owned Keys**
   - Used by AWS services internally
   - Not visible in your account
   - Free

**KMS Key Policy Structure**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM policies",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow use of key for encryption",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:role/MyAppRole"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**KMS Operations**:
- **Encrypt**: Encrypt data (max 4KB)
- **Decrypt**: Decrypt data
- **GenerateDataKey**: Get data encryption key (plaintext + encrypted)
- **ReEncrypt**: Re-encrypt with different key (no client-side decryption)

**Envelope Encryption**:
1. KMS generates data key (plaintext + encrypted version)
2. Use plaintext key to encrypt data
3. Store encrypted data + encrypted key together
4. Discard plaintext key from memory
5. To decrypt: Use KMS to decrypt data key, then decrypt data

**KMS Key Rotation**:
- **Automatic**: Enabled per key, rotates yearly, old versions kept
- **Manual**: Create new key version, update key alias

**Cross-Account KMS Access**:
1. Key policy in source account grants target account access
2. IAM policy in target account allows key usage
3. Both policies required

#### AWS CloudHSM

**Purpose**: Hardware Security Module for generating and managing encryption keys

**CloudHSM vs KMS**:
| Feature | KMS | CloudHSM |
|---------|-----|----------|
| **Control** | Shared tenancy | Dedicated hardware |
| **Compliance** | FIPS 140-2 Level 2 | FIPS 140-2 Level 3 |
| **Integration** | Native with AWS services | Manual integration |
| **Management** | AWS managed | Customer managed |
| **Cost** | Pay per key | Per HSM hourly |
| **Use Case** | General encryption | Compliance requirements |

**When to Use CloudHSM**:
✅ Regulatory requirement for FIPS 140-2 Level 3
✅ Need single-tenant HSM
✅ Custom cryptographic operations
✅ Offload SSL/TLS processing

### S3 Data Protection

#### S3 Encryption Options

**Server-Side Encryption (SSE)**:

1. **SSE-S3** (AES-256)
   - S3-managed keys
   - Header: `x-amz-server-side-encryption: AES256`
   - Free (except storage/requests)

2. **SSE-KMS**
   - KMS Customer Managed Keys
   - Audit trail via CloudTrail
   - Header: `x-amz-server-side-encryption: aws:kms`
   - Additional KMS costs

3. **SSE-C** (Customer-Provided Keys)
   - Customer manages keys
   - AWS performs encryption/decryption
   - Key provided with each request
   - No key management overhead in AWS

**Enforcing Encryption**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    }
  ]
}
```

**Client-Side Encryption**:
- AWS Encryption SDK
- S3 Encryption Client
- Data encrypted before upload
- Customer manages keys

#### S3 Access Control

**S3 Access Control Mechanisms**:
1. **IAM Policies**: Who can access from AWS accounts
2. **Bucket Policies**: Cross-account access, public access
3. **Access Control Lists (ACLs)**: Legacy, not recommended
4. **S3 Block Public Access**: Overrides all public permissions

**S3 Canned ACLs**:
| ACL | Description |
|-----|-------------|
| private | Owner gets FULL_CONTROL |
| public-read | All can read object |
| public-read-write | All can read/write object |
| authenticated-read | Authenticated AWS users can read |
| bucket-owner-read | Bucket owner can read |
| bucket-owner-full-control | Bucket owner FULL_CONTROL |

**Best Practice**: Use IAM and bucket policies; disable ACLs

**S3 Block Public Access**:
- **BlockPublicAcls**: Reject PUT requests with public ACL
- **IgnorePublicAcls**: Ignore public ACLs on existing objects
- **BlockPublicPolicy**: Reject bucket policies granting public access
- **RestrictPublicBuckets**: Restrict access to bucket with public policy

**Recommendation**: Enable all four settings by default

#### S3 Access Points

**Purpose**: Simplify managing access to shared S3 buckets

**Benefits**:
- **Unique hostname**: Each access point has its own DNS name
- **Separate policies**: Different permissions per access point
- **VPC access**: Restrict to specific VPC

**Example**:
- Bucket: `shared-data-bucket`
- Access Point 1: `marketing-data` (marketing team access)
- Access Point 2: `finance-data` (finance team access)
- Access Point 3: `readonly-data` (read-only access)

**Creating Access Point**:
```bash
aws s3control create-access-point \
  --name finance-data \
  --account-id 111111111111 \
  --bucket shared-data-bucket \
  --policy file://policy.json
```

#### S3 Object Lock

**Purpose**: Write-once-read-many (WORM) storage

**Modes**:
1. **Governance Mode**: Some users can override retention
2. **Compliance Mode**: No one can override, not even root

**Retention Periods**:
- **Retain Until Date**: Object cannot be deleted/overwritten until date
- **Legal Hold**: Indefinite hold, removed manually

**Use Cases**:
- Regulatory compliance (SEC Rule 17a-4)
- Prevent accidental deletion
- Ransomware protection

**Enabling Object Lock**:
```bash
# Must enable at bucket creation
aws s3api create-bucket \
  --bucket my-worm-bucket \
  --object-lock-enabled-for-bucket
```

#### S3 Versioning

**Purpose**: Keep multiple versions of objects

**Benefits**:
- Recover from accidental deletes
- Recover from application failures
- Audit history of changes

**Versioning States**:
- **Unversioned** (default)
- **Enabled**: Cannot be disabled, only suspended
- **Suspended**: New objects get null version ID

**Deleting with Versioning**:
- Delete without version ID: Adds delete marker
- Delete with version ID: Permanently deletes that version

**MFA Delete**:
- Require MFA to permanently delete versions
- Require MFA to suspend versioning
- Only bucket owner (root) can enable

### RDS Data Protection

#### RDS Encryption

**At Rest**:
- Enable at instance creation (cannot add later without snapshot/restore)
- Uses KMS
- Encrypts DB, logs, backups, snapshots, read replicas

**In Transit**:
- SSL/TLS connections
- Force SSL with parameter group
- Download SSL certificate from AWS

**Enforcing SSL**:
```sql
-- PostgreSQL
ALTER USER myuser SET sslmode='require';

-- MySQL
GRANT USAGE ON *.* TO 'myuser'@'%' REQUIRE SSL;
```

#### RDS Backup and Snapshots

**Automated Backups**:
- Retention: 0-35 days (0 = disabled)
- Point-in-time recovery (PITR) to any second within retention
- Taken during backup window
- Impact: Brief I/O suspension (Single-AZ); no impact (Multi-AZ)

**Manual Snapshots**:
- Persist until explicitly deleted
- Can copy across regions
- Can share with other accounts (unencrypted or KMS encrypted)

**Snapshot Sharing**:
- Unencrypted snapshots: Can share directly
- Encrypted snapshots: Share KMS key with target account, then share snapshot

### DynamoDB Data Protection

**Encryption**:
- **At Rest**: Always enabled, no option to disable
- **Key Types**:
  - AWS owned key (default, free)
  - AWS managed key (aws/dynamodb)
  - Customer managed key

**In Transit**: All connections use TLS

**Point-in-Time Recovery (PITR)**:
- Continuous backups for 35 days
- Restore to any second in window
- No performance impact
- Additional cost per GB-month

**On-Demand Backup**:
- Full backup at any time
- Does not affect performance
- Restore to same or different table
- Retain indefinitely

**Global Tables**: Multi-region, multi-active replication

### EBS Encryption

**Encryption at Rest**:
- Uses KMS
- Enabled per volume
- Snapshots of encrypted volumes are encrypted
- Cannot change encryption status of existing volume

**Encrypting Existing Volume**:
1. Create snapshot of unencrypted volume
2. Copy snapshot with encryption enabled
3. Create new volume from encrypted snapshot

**Default Encryption**:
- Enable at account/region level
- All new EBS volumes and snapshots encrypted by default
- Specify CMK for default encryption

### AWS Secrets Manager

**Purpose**: Rotate, manage, and retrieve secrets

**Features**:
- **Automatic Rotation**: Configurable intervals (e.g., every 30 days)
- **Fine-Grained Access**: IAM and resource policies
- **Audit**: CloudTrail logs all access
- **Encryption**: KMS encrypted at rest

**Secret Types**:
- Database credentials
- API keys
- OAuth tokens
- Custom secrets

**Rotation Lambda**:
- AWS provides templates for RDS, Redshift, DocumentDB
- Custom Lambda for other secret types

**Retrieving Secret**:
```python
import boto3
import json

client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId='MyDatabaseSecret')
secret = json.loads(response['SecretString'])
username = secret['username']
password = secret['password']
```

**Secrets Manager vs Parameter Store**:
| Feature | Secrets Manager | Parameter Store |
|---------|----------------|-----------------|
| **Rotation** | Built-in | Manual with Lambda |
| **Pricing** | $0.40/secret/month | Free (standard), paid (advanced) |
| **Secret Size** | 65KB | 4KB (standard), 8KB (advanced) |
| **Use Case** | Database credentials | Configuration data |

### Data Protection Best Practices

✅ **Enable encryption at rest for all storage**
✅ **Use TLS/SSL for data in transit**
✅ **Classify data and apply appropriate controls**
✅ **Rotate secrets automatically**
✅ **Enable versioning for critical data (S3, backups)**
✅ **Use S3 Block Public Access by default**
✅ **Enable MFA Delete for S3 buckets with sensitive data**
✅ **Regularly test backup restore procedures**
✅ **Use KMS CMKs for sensitive data (audit trail)**

### Common Exam Scenarios

**Scenario**: Encrypt existing S3 bucket
- **Solution**: Update bucket policy to deny non-encrypted uploads; use S3 batch operations or lifecycle policy to re-upload with encryption

**Scenario**: Share encrypted RDS snapshot with another account
- **Solution**: Share KMS key with target account, then share snapshot

**Scenario**: Rotate database credentials without downtime
- **Solution**: Use Secrets Manager with automatic rotation

**Scenario**: Prevent accidental deletion of critical data
- **Solution**: Enable S3 versioning + MFA Delete, or use S3 Object Lock

**Scenario**: Audit all access to encryption keys
- **Solution**: Use KMS CMKs (audit in CloudTrail); CloudTrail logs all KMS API calls

### Common Exam Traps

❌ **Trap**: Thinking encryption can be added to existing RDS instance
✅ **Truth**: Must create encrypted snapshot and restore to new instance

❌ **Trap**: Assuming S3 versioning prevents all deletions
✅ **Truth**: Versioning prevents accidental deletion, but permanent delete of versions still possible; use MFA Delete or Object Lock

❌ **Trap**: Believing all S3 encryption types have audit trails
✅ **Truth**: Only SSE-KMS logs usage in CloudTrail

❌ **Trap**: Confusing AWS managed keys with customer managed keys
✅ **Truth**: AWS managed (prefix aws/*, auto-rotation, free); Customer managed (full control, optional rotation, $1/month)

---

## Chapter 8: Logging and Audit Trails {#chapter-8-logging}

### AWS CloudTrail

**Purpose**: Log all API calls and account activity

**Key Concepts**:
- **Event**: Record of activity (API call, console sign-in)
- **Trail**: Configuration for logging events
- **Event History**: 90-day history available in console (no trail needed)

#### CloudTrail Event Types

1. **Management Events** (Control Plane)
   - API calls to manage AWS resources
   - Examples: RunInstances, CreateBucket, DeleteDBInstance
   - **Read vs Write**: Read (describe, list, get), Write (create, delete, modify)

2. **Data Events** (Data Plane)
   - Resource operations on data
   - Examples: S3 GetObject/PutObject, Lambda Invoke, DynamoDB GetItem
   - **Higher volume**: Can significantly increase costs
   - **Selective logging**: Log only specific buckets/functions

3. **Insights Events**
   - Detect unusual API activity
   - Uses ML to establish baseline
   - Examples: Sudden spike in IAM errors, unusual resource deletion

**CloudTrail Log Structure**:
```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI234567890EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/Alice",
    "accountId": "123456789012",
    "userName": "Alice"
  },
  "eventTime": "2025-10-24T10:00:00Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "RunInstances",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.1",
  "userAgent": "aws-cli/2.0.0",
  "requestParameters": {
    "instanceType": "t3.micro",
    "imageId": "ami-12345678"
  },
  "responseElements": {
    "instancesSet": [...]
  }
}
```

#### CloudTrail Best Practices

✅ **Enable in all regions**
✅ **Enable log file integrity validation** (detect tampering)
✅ **Encrypt logs with KMS**
✅ **Store in dedicated S3 bucket with restricted access**
✅ **Enable MFA Delete on CloudTrail S3 bucket**
✅ **Forward to CloudWatch Logs for real-time monitoring**
✅ **Enable CloudTrail Insights for anomaly detection**

#### CloudTrail Multi-Region vs Single-Region

| Feature | Multi-Region Trail | Single-Region Trail |
|---------|-------------------|---------------------|
| **Scope** | All regions | One region |
| **Global Services** | Logged once | Optionally logged |
| **Management** | One trail for all | Trail per region |
| **Recommendation** | Preferred | Legacy use only |

#### Centralized CloudTrail Logging

**Architecture**:
- **Organization Trail**: Created in management account
- **Centralized S3 Bucket**: Logs from all accounts
- **Cross-Account Access**: Bucket policy allows member account writes

**S3 Bucket Policy for Multi-Account**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::my-org-cloudtrail-logs"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-org-cloudtrail-logs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
```

#### Querying CloudTrail with Athena

**Setup**:
1. Create Athena table pointing to CloudTrail S3 bucket
2. Use partitioning for better performance (by account/region/date)

**Example Queries**:

```sql
-- Find all failed access attempts
SELECT useridentity.username, eventname, errorcode, errormessage
FROM cloudtrail_logs
WHERE errorcode IS NOT NULL
AND eventtime > '2025-10-01'
ORDER BY eventtime DESC;

-- Find who created/deleted IAM users
SELECT eventtime, useridentity.username, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('CreateUser', 'DeleteUser')
AND eventtime > '2025-10-01'
ORDER BY eventtime DESC;

-- Find all console sign-ins
SELECT eventtime, useridentity.username, sourceipaddress, 
       JSON_EXTRACT_SCALAR(responseelements, '$.ConsoleLogin') as success
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
AND eventtime > '2025-10-01'
ORDER BY eventtime DESC;

-- Identify API calls from specific IP
SELECT eventtime, eventname, eventSource, useridentity.username
FROM cloudtrail_logs
WHERE sourceipaddress = '203.0.113.1'
AND eventtime > '2025-10-01'
ORDER BY eventtime DESC;
```

### AWS Config

**Purpose**: Track resource configuration changes and compliance

**Key Concepts**:
- **Configuration Items (CI)**: Snapshot of resource configuration at point in time
- **Configuration Recorder**: Records changes (must be enabled)
- **Delivery Channel**: Where to store data (S3 bucket)
- **Config Rules**: Compliance evaluation rules

#### Config Components

1. **Configuration Recorder**: Records supported resources in region

2. **Delivery Channel**: S3 bucket and optional SNS topic for notifications

3. **Config Rules**:
   - **AWS Managed**: Pre-built rules (e.g., encrypted-volumes, root-account-mfa-enabled)
   - **Custom**: Lambda function for custom logic

**Config Rule Types**:
- **Configuration Changes**: Triggered when resource changes
- **Periodic**: Evaluated at regular intervals (1, 3, 6, 12, or 24 hours)

#### Config Rule Examples

**AWS Managed Rules**:
- `s3-bucket-public-read-prohibited`: S3 buckets should not allow public read
- `rds-storage-encrypted`: RDS instances should be encrypted
- `root-account-mfa-enabled`: Root account should have MFA
- `iam-password-policy`: Password policy should meet requirements
- `ec2-instance-managed-by-ssm`: EC2 instances should be managed by Systems Manager

**Custom Config Rule (Lambda)**:
```python
import json

def evaluate_compliance(config_item):
    # Check if EC2 instance has required tag
    if config_item['resourceType'] != 'AWS::EC2::Instance':
        return 'NOT_APPLICABLE'
    
    tags = config_item.get('tags', {})
    
    if 'Environment' in tags:
        return 'COMPLIANT'
    else:
        return 'NON_COMPLIANT'

def lambda_handler(event, context):
    config_item = json.loads(event['configurationItem'])
    compliance_status = evaluate_compliance(config_item)
    
    return {
        'compliance_type': compliance_status,
        'annotation': 'Environment tag validation'
    }
```

#### Config Aggregators

**Purpose**: Multi-account and multi-region aggregated view

**Types**:
- **Individual Account**: Aggregate across regions in single account
- **Organization**: Aggregate across all accounts in AWS Organizations

**Use Cases**:
- Centralized compliance dashboard
- Cross-account security posture
- Organization-wide resource inventory

#### Config vs CloudTrail

| Feature | CloudTrail | Config |
|---------|-----------|--------|
| **Purpose** | WHO did WHAT and WHEN | WHAT resource configuration changed |
| **Focus** | API calls and user activity | Resource configuration |
| **Compliance** | Audit trail | Compliance rules |
| **Changes** | API-level changes | Configuration state |
| **Use Case** | Security forensics | Configuration auditing |

**Complementary**: Both should be used together
- CloudTrail: *Who* changed security group *when*
- Config: *What* security group configuration was before/after change

### VPC Flow Logs

**Purpose**: Capture IP traffic information for network interfaces

**Log Levels**:
- VPC: All ENIs in VPC
- Subnet: All ENIs in subnet
- ENI: Specific network interface

**Flow Log Fields (Default)**:
```
version account-id interface-id srcaddr dstaddr srcport dstport 
protocol packets bytes start end action log-status
```

**Custom Format** (additional fields):
- vpc-id, subnet-id
- instance-id
- tcp-flags
- pkt-srcaddr, pkt-dstaddr (for packets behind NAT)

**Flow Log Destinations**:
- CloudWatch Logs
- S3
- Kinesis Data Firehose

**Example Flow Log Entry**:
```
2 123456789012 eni-abc123 203.0.113.1 10.0.1.5 443 32768 6 10 5000 1635072000 1635072060 ACCEPT OK
```

**Interpretation**:
- Source: 203.0.113.1:443
- Destination: 10.0.1.5:32768
- Protocol: 6 (TCP)
- Action: ACCEPT
- 10 packets, 5000 bytes

**Flow Logs Use Cases**:
- Troubleshoot connectivity
- Detect anomalous traffic patterns
- Identify top talkers
- Security forensics
- Compliance evidence

**Flow Logs Limitations**:
- Not real-time (up to 10 min delay)
- Does not log:
  - Traffic to/from instance metadata (169.254.169.254)
  - DHCP traffic
  - Traffic to reserved IPs (.1, .2, .3)
  - Windows license activation traffic

### CloudWatch Logs

**Purpose**: Centralized logging for applications and AWS services

**Hierarchy**:
- **Log Groups**: Container for log streams (e.g., /aws/lambda/my-function)
- **Log Streams**: Sequence of log events from same source
- **Log Events**: Individual log entry with timestamp and message

**Log Sources**:
- Lambda functions (automatic)
- EC2 instances (CloudWatch Agent)
- RDS/Aurora (database logs)
- VPC Flow Logs
- CloudTrail
- API Gateway
- ECS/EKS containers

#### CloudWatch Logs Insights

**Purpose**: Query and analyze log data

**Example Queries**:

```sql
# Find errors in Lambda logs
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 100

# Count errors by type
fields @message
| filter @message like /ERROR/
| stats count() by @message

# API Gateway latency analysis
fields @timestamp, status, latency
| filter status >= 400
| sort latency desc
| limit 20

# VPC Flow Logs - Top source IPs
fields srcAddr, dstAddr, srcPort, dstPort, action
| filter action = 'REJECT'
| stats count() by srcAddr
| sort count desc
```

#### CloudWatch Logs Subscriptions

**Purpose**: Real-time log streaming to other services

**Destinations**:
- Lambda (for processing)
- Kinesis Data Streams
- Kinesis Data Firehose (S3, Elasticsearch, Splunk)

**Use Cases**:
- Real-time alerting
- Log aggregation to SIEM
- Real-time security analysis
- Streaming to data lake

**Subscription Filter Pattern**:
```json
{ $.eventName = "ConsoleLogin" && $.errorCode = "Failed authentication" }
```

### Amazon EventBridge (CloudWatch Events)

**Purpose**: Event-driven automation

**Event Sources**:
- AWS services (CloudTrail, Config, etc.)
- Custom applications
- SaaS partners

**Event Pattern Example**:
```json
{
  "source": ["aws.ec2"],
  "detail-type": ["EC2 Instance State-change Notification"],
  "detail": {
    "state": ["running"]
  }
}
```

**Use Cases**:
- Auto-remediation (e.g., isolate compromised instance)
- Security notifications
- Compliance automation
- Incident response orchestration

### Logging Best Practices

✅ **Enable CloudTrail in all accounts and regions**
✅ **Enable Config Rules for compliance**
✅ **Use CloudWatch Logs for application logging**
✅ **Enable VPC Flow Logs for network visibility**
✅ **Centralize logs in dedicated account**
✅ **Encrypt logs at rest (S3 SSE-KMS)**
✅ **Set appropriate log retention**
✅ **Use CloudWatch Logs Insights for analysis**
✅ **Forward critical logs to SIEM**
✅ **Enable log file integrity validation (CloudTrail)**

### Common Exam Scenarios

**Scenario**: Investigate who deleted S3 bucket
- **Solution**: Query CloudTrail logs for DeleteBucket API call

**Scenario**: Alert on IAM policy changes
- **Solution**: CloudTrail to CloudWatch Logs, create metric filter, CloudWatch Alarm, SNS notification

**Scenario**: Track configuration changes for compliance
- **Solution**: Enable Config with appropriate rules and aggregators

**Scenario**: Identify source of network attack
- **Solution**: Analyze VPC Flow Logs for REJECT actions and suspicious IPs

**Scenario**: Real-time security analysis of API calls
- **Solution**: CloudTrail to CloudWatch Logs, subscription filter to Lambda for analysis

### Common Exam Traps

❌ **Trap**: Thinking CloudTrail logs data events by default
✅ **Truth**: Only management events by default; data events require explicit configuration

❌ **Trap**: Assuming Config prevents non-compliant changes
✅ **Truth**: Config only evaluates compliance; use SCPs or preventive controls to block

❌ **Trap**: Believing VPC Flow Logs show packet contents
✅ **Truth**: Flow Logs only show metadata (IPs, ports, protocol); no payload

❌ **Trap**: Expecting real-time CloudTrail events
✅ **Truth**: CloudTrail typically delivers events within 15 minutes; use CloudWatch Events for real-time

---

## Chapter 9: Continuous Monitoring {#chapter-9-monitoring}

### Security Monitoring Strategy

**Goals**:
1. **Detect threats early**: Before significant damage
2. **Respond quickly**: Automated remediation
3. **Maintain compliance**: Continuous validation
4. **Reduce attack surface**: Identify misconfigurations

### Amazon GuardDuty

**Purpose**: Intelligent threat detection using ML

**Data Sources**:
- VPC Flow Logs (network activity)
- CloudTrail management events (API calls)
- CloudTrail S3 data events (S3 access)
- DNS logs (domain queries)

**Threat Categories**:
1. **Reconnaissance**: Port scanning, unusual API activity
2. **Instance Compromise**: Malware, crypto-mining, backdoors
3. **Account Compromise**: Unusual console logins, API usage from unusual locations
4. **Bucket Compromise**: Suspicious S3 access patterns

**GuardDuty Finding Severity**:
- **Low** (0.1-3.9): Informational, minimal risk
- **Medium** (4.0-6.9): Investigate, possible security issue
- **High** (7.0-8.9): Immediate investigation, likely security incident

**Example Findings**:
- **UnauthorizedAccess:EC2/SSHBruteForce**: SSH brute force attempts
- **CryptoCurrency:EC2/BitcoinTool**: Bitcoin-related activity detected
- **Trojan:EC2/DNSDataExfiltration**: DNS queries indicating data theft
- **Recon:IAMUser/MaliciousIPCaller**: API calls from known malicious IP
- **Policy:IAMUser/RootCredentialUsage**: Root account used

#### GuardDuty Setup

**Enable**:
```bash
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES
```

**Multi-Account Setup**:
1. Designate GuardDuty administrator account
2. Member accounts accept invitation or auto-enable via Organizations
3. Administrator sees findings from all accounts

**GuardDuty Integration**:
- **EventBridge**: Real-time finding events for automation
- **Security Hub**: Centralized findings
- **Detective**: Investigation

**Automated Response Example**:
```python
# Lambda triggered by GuardDuty finding via EventBridge
import boto3

def lambda_handler(event, context):
    finding = event['detail']
    severity = finding['severity']
    finding_type = finding['type']
    
    if severity >= 7.0 and 'SSHBruteForce' in finding_type:
        # Isolate instance
        instance_id = finding['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')
        
        # Attach quarantine security group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=['sg-quarantine']
        )
        
        # Send notification
        sns = boto3.client('sns')
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
            Subject=f'High Severity GuardDuty Finding: {finding_type}',
            Message=f'Instance {instance_id} has been quarantined'
        )
```

### Amazon Macie

**Purpose**: Discover and protect sensitive data in S3

**Detection**:
- **Managed Data Identifiers**: Pre-built patterns (credit cards, SSNs, API keys)
- **Custom Data Identifiers**: Regex patterns for proprietary data
- **ML**: Unusual access patterns and data exposure

**Data Identifiers (Examples)**:
- Credit card numbers (PCI DSS)
- Social Security Numbers
- Passport numbers
- Driver's license numbers
- API keys and secrets
- Personal health information

**Macie Jobs**:
- **One-time**: Scan buckets once
- **Scheduled**: Regular scans (daily, weekly, monthly)

**Macie Findings**:
- **Policy Findings**: Bucket configuration issues (public access, encryption)
- **Sensitive Data Findings**: Sensitive data discovered in objects

**Example Use Case**:
1. Enable Macie for S3 buckets
2. Create job to scan for PII
3. Macie finds bucket with unencrypted credit card numbers
4. Generate finding
5. EventBridge triggers Lambda to encrypt bucket and notify security team

### Amazon Inspector

**Purpose**: Automated vulnerability assessment for EC2 and container images

**Assessment Types**:
1. **Network Assessments**: 
   - Network reachability
   - Open ports
   - Unintended network access

2. **Host Assessments** (requires agent):
   - CVEs (Common Vulnerabilities and Exposures)
   - CIS benchmarks
   - Security best practices

**Inspector Rules Packages**:
- **Common Vulnerabilities and Exposures (CVE)**: Known security vulnerabilities
- **CIS Operating System Security Configuration Benchmarks**: Hardening standards
- **Security Best Practices**: AWS recommendations
- **Runtime Behavior Analysis**: Insecure runtime behaviors

**Assessment Runs**:
- **On-demand**: Run when needed
- **Scheduled**: Regular scans (weekly, monthly)
- **Duration**: 15 minutes to 24 hours

**Inspector Findings**:
```
Finding: CVE-2021-12345 - Apache Log4j Remote Code Execution
Severity: High (CVSS Score: 9.8)
Instance: i-abc123
Recommendation: Update to Log4j 2.17.0 or later
```

**Best Practice**: Run Inspector regularly (weekly) and after deployments

### AWS Security Hub

**Purpose**: Centralized security and compliance dashboard

**Key Features**:
- **Aggregated Findings**: From GuardDuty, Inspector, Macie, IAM Access Analyzer, Firewall Manager, etc.
- **Compliance Checks**: CIS Benchmarks, PCI DSS, AWS Foundational Security Best Practices
- **Multi-Account**: Aggregate from organization
- **ASFF**: AWS Security Finding Format for standardized findings
- **Integrations**: Third-party tools (Splunk, PagerDuty, ServiceNow)

**Security Standards**:
1. **AWS Foundational Security Best Practices**: AWS's recommendations
2. **CIS AWS Foundations Benchmark**: Industry standard
3. **PCI DSS**: Payment Card Industry
4. **NIST**: National Institute of Standards and Technology

**Insight Types**:
- **Managed Insights**: Pre-configured (e.g., "Resources with high severity findings")
- **Custom Insights**: User-defined filters

**Workflow Status**:
- **NEW**: Finding just created
- **NOTIFIED**: Alert sent to owner
- **RESOLVED**: Issue remediated
- **SUPPRESSED**: False positive or accepted risk

**Integration Example (Auto-Remediation)**:
```
Security Hub Finding (NOTIFIED) 
→ EventBridge Rule 
→ Lambda (remediation) 
→ Update Finding to RESOLVED
```

**Security Hub vs GuardDuty**:
| Feature | Security Hub | GuardDuty |
|---------|--------------|-----------|
| **Purpose** | Aggregation + compliance | Threat detection |
| **Findings Source** | Multiple services | VPC/CloudTrail/DNS |
| **Compliance** | Yes | No |
| **Detection** | No | Yes (ML-based) |

### AWS Config Rules for Security

**Common Security Config Rules**:

1. **access-keys-rotated**: IAM access keys rotated within specified days
2. **iam-password-policy**: Password policy meets requirements
3. **root-account-mfa-enabled**: Root account has MFA
4. **s3-bucket-public-read-prohibited**: S3 buckets not publicly readable
5. **s3-bucket-public-write-prohibited**: S3 buckets not publicly writable
6. **encrypted-volumes**: EBS volumes are encrypted
7. **rds-storage-encrypted**: RDS instances encrypted
8. **vpc-sg-open-only-to-authorized-ports**: Security groups follow port restrictions
9. **cloudtrail-enabled**: CloudTrail enabled
10. **multi-region-cloudtrail-enabled**: CloudTrail logging all regions

**Remediation**:
- **Manual**: Review findings and fix
- **Automated**: Config Remediation Actions (SSM Automation documents)

**Example Automated Remediation**:
```yaml
# Config Rule: S3 bucket should have encryption
Rule: s3-bucket-server-side-encryption-enabled

# Remediation Action (SSM Automation)
Document: AWS-EnableS3BucketEncryption
Parameters:
  BucketName: <bucket-from-finding>
  SSEAlgorithm: AES256
```

### Third-Party Security Tools

**SIEM Integration**:
- Splunk
- Sumo Logic
- Datadog
- Elasticsearch

**Vulnerability Scanners**:
- Qualys
- Tenable
- Rapid7
- Trend Micro

**Configuration Monitoring**:
- Prowler (open-source AWS security tool)
- Scout Suite
- CloudSploit

**Prowler Example**:
```bash
# Install Prowler
git clone https://github.com/prowler-cloud/prowler

# Run all checks
./prowler -M csv html

# Run specific check
./prowler -c check110  # Check for S3 bucket public access

# Run for specific region
./prowler -r us-east-1

# Output formats
./prowler -M json csv html pdf
```

### Monitoring Best Practices

✅ **Enable GuardDuty in all accounts and regions**
✅ **Use Security Hub as central security dashboard**
✅ **Enable Macie for S3 buckets with sensitive data**
✅ **Run Inspector regularly for vulnerability assessments**
✅ **Automate remediation for common findings**
✅ **Integrate with SIEM for advanced analysis**
✅ **Define and test incident response runbooks**
✅ **Monitor Config compliance continuously**
✅ **Set up alerts for high-severity findings**
✅ **Review security findings regularly**

### Monitoring Metrics and Alarms

**CloudWatch Metrics for Security**:
- Failed authentication attempts
- IAM policy changes
- Security group modifications
- CloudTrail disabled events
- Root account usage
- High-severity GuardDuty findings

**Example Metric Filter (Failed Console Logins)**:
```
Filter Pattern: { $.eventName = ConsoleLogin && $.errorMessage = "Failed authentication" }

Metric: FailedConsoleLogins
Alarm: > 5 in 5 minutes → SNS notification
```

**Example Metric Filter (Security Group Changes)**:
```
Filter Pattern: { $.eventName = AuthorizeSecurityGroupIngress || $.eventName = RevokeSecurityGroupIngress }

Metric: SecurityGroupChanges
Alarm: Any change → SNS notification
```

### Common Exam Scenarios

**Scenario**: Detect and respond to compromised EC2 instance
- **Solution**: GuardDuty detects compromise → EventBridge → Lambda isolates instance + SNS notification

**Scenario**: Ensure compliance with CIS Benchmark
- **Solution**: Enable Security Hub with CIS standard, review findings, use Config remediation

**Scenario**: Discover S3 buckets containing credit card numbers
- **Solution**: Enable Macie, create job to scan S3, review sensitive data findings

**Scenario**: Identify EC2 instances with known vulnerabilities
- **Solution**: Install Inspector agent, run host assessment, review CVE findings

**Scenario**: Alert on changes to critical resources
- **Solution**: Config rule monitors resources, EventBridge on compliance change, SNS notification

### Common Exam Traps

❌ **Trap**: Thinking GuardDuty prevents attacks
✅ **Truth**: GuardDuty detects threats; use WAF, Security Groups, SCPs to prevent

❌ **Trap**: Assuming Macie scans all data automatically
✅ **Truth**: Must create jobs to scan buckets; not automatic

❌ **Trap**: Believing Inspector works without agent for host assessments
✅ **Truth**: Agent required for CVE and CIS checks; network assessments agentless

❌ **Trap**: Expecting Security Hub to generate findings
✅ **Truth**: Security Hub aggregates findings from other services, doesn't generate its own

---

## Chapter 10: Incident Response and Remediation {#chapter-10-incident-response}

### Incident Response Framework

**NIST Incident Response Lifecycle**:
1. **Preparation**: Plans, tools, training
2. **Detection & Analysis**: Identify and validate incidents
3. **Containment**: Limit damage
4. **Eradication**: Remove threat
5. **Recovery**: Restore systems
6. **Post-Incident**: Lessons learned

### Preparation Phase

#### Incident Response Plan Components

1. **Roles and Responsibilities**
   - Incident Commander
   - Security team
   - On-call engineers
   - Communications lead
   - Legal/compliance

2. **Communication Plan**
   - Internal escalation path
   - External stakeholders (customers, partners)
   - Regulatory bodies (if required)

3. **Tools and Access**
   - Break-glass accounts
   - Forensics tools
   - Logging and monitoring
   - Automation scripts

4. **Runbooks/Playbooks**
   - Step-by-step procedures
   - Automated response workflows
   - Decision trees

#### AWS Incident Response Tools

**AWS Tools**:
- **Security Hub**: Central findings dashboard
- **CloudWatch**: Metrics and alarms
- **EventBridge**: Event-driven automation
- **Lambda**: Automated response functions
- **Systems Manager**: Remote command execution
- **Step Functions**: Orchestrate complex workflows

**Third-Party Tools**:
- **PagerDuty**: Incident alerting
- **Jira/ServiceNow**: Incident tracking
- **Slack/Teams**: Collaboration
- **Splunk/Sumo Logic**: Log analysis

### Detection and Analysis

#### Common Security Events

1. **Compromised Credentials**
   - **Indicators**: 
     - Unusual API calls
     - Access from unexpected locations
     - Failed authentication followed by success
   - **GuardDuty Findings**: 
     - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
     - PenTest:IAMUser/KaliLinux

2. **Compromised EC2 Instance**
   - **Indicators**:
     - Outbound connections to known bad IPs
     - Crypto-mining activity
     - Unauthorized processes
   - **GuardDuty Findings**:
     - CryptoCurrency:EC2/BitcoinTool
     - Backdoor:EC2/C&CActivity
     - Trojan:EC2/DNSDataExfiltration

3. **S3 Data Exfiltration**
   - **Indicators**:
     - Unusual download volume
     - Access from unexpected IPs
     - Bucket policy changes
   - **GuardDuty/Macie Findings**:
     - Exfiltration:S3/AnomalousBehavior
     - Policy:S3/AccountBlockPublicAccessDisabled

4. **IAM Privilege Escalation**
   - **Indicators**:
     - Policy modifications
     - New access key creation
     - Assume role requests
   - **CloudTrail Events**:
     - CreateAccessKey
     - PutUserPolicy
     - AttachUserPolicy

#### Investigation Process

**Step 1: Validate the Finding**
- Not all findings are true positives
- Review finding details
- Check for false positive indicators

**Step 2: Determine Scope**
- What resources are affected?
- How long has the incident been ongoing?
- What data may be compromised?

**Step 3: Assess Impact**
- Confidentiality impact
- Integrity impact
- Availability impact
- Business impact

**Step 4: Gather Evidence**
- Preserve CloudTrail logs
- Collect VPC Flow Logs
- Take EC2 snapshots
- Export relevant logs

**Investigation Queries (CloudTrail)**:
```sql
-- Find all actions by suspected compromised user
SELECT eventtime, eventname, eventsource, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE useridentity.username = 'suspected-user'
AND eventtime > '2025-10-20'
ORDER BY eventtime;

-- Find resource modifications in time window
SELECT eventtime, eventname, requestparameters, responseelements
FROM cloudtrail_logs
WHERE eventname LIKE '%Create%' OR eventname LIKE '%Delete%' OR eventname LIKE '%Modify%'
AND eventtime BETWEEN '2025-10-20' AND '2025-10-21'
ORDER BY eventtime;

-- Find access from unusual location
SELECT eventtime, useridentity.username, sourceipaddress, eventname
FROM cloudtrail_logs
WHERE sourceipaddress NOT IN ('203.0.113.0/24', '198.51.100.0/24')
AND eventtime > '2025-10-20'
ORDER BY eventtime;
```

### Containment

**Immediate Actions**:

#### 1. Compromised IAM Credentials
```bash
# Disable user access keys
aws iam update-access-key \
  --user-name suspected-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive

# Attach deny-all policy
aws iam attach-user-policy \
  --user-name suspected-user \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

# Force password reset
aws iam update-login-profile \
  --user-name suspected-user \
  --password-reset-required
```

#### 2. Compromised EC2 Instance
```bash
# Isolate instance (attach quarantine SG)
aws ec2 modify-instance-attribute \
  --instance-id i-abc123 \
  --groups sg-quarantine  # Deny all inbound/outbound

# Or stop instance
aws ec2 stop-instances --instance-ids i-abc123

# Create forensic snapshot before termination
aws ec2 create-snapshot \
  --volume-id vol-xyz789 \
  --description "Forensic snapshot before remediation"
```

**Quarantine Security Group**:
```
Inbound Rules: NONE (deny all)
Outbound Rules: NONE (deny all)
```

#### 3. Exposed S3 Bucket
```bash
# Block public access
aws s3api put-public-access-block \
  --bucket my-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Review bucket policy and ACLs
aws s3api get-bucket-policy --bucket my-bucket
aws s3api get-bucket-acl --bucket my-bucket

# Enable MFA Delete if not already enabled
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::123456789012:mfa/root-account-mfa-device 123456"
```

### Eradication

**Remove Threat**:

1. **Malware/Backdoors**: 
   - Terminate compromised instance
   - Launch new instance from clean AMI
   - Update security groups and IAM roles

2. **Unauthorized Access**:
   - Remove malicious IAM policies/users
   - Delete unauthorized access keys
   - Reset passwords

3. **Persistence Mechanisms**:
   - Check for unauthorized Lambda functions
   - Review CloudFormation stacks
   - Audit Systems Manager documents
   - Review EventBridge rules

**Checklist**:
- [ ] All compromised credentials revoked
- [ ] Unauthorized resources deleted
- [ ] Policies and configurations restored
- [ ] Persistence mechanisms removed
- [ ] Vulnerabilities patched

### Recovery

**Restore Normal Operations**:

1. **Deploy Clean Resources**
   - Use known-good AMIs
   - Deploy from version control
   - Use Infrastructure as Code (CloudFormation/Terraform)

2. **Restore Data**
   - From backups (ensure backups not compromised)
   - Validate integrity

3. **Enhance Security**
   - Apply lessons learned
   - Implement additional controls
   - Update security groups/policies

4. **Monitor Closely**
   - Increased monitoring for recurrence
   - Watch for indicators of compromise

### Automated Remediation

#### EventBridge + Lambda Pattern

**Example 1: Auto-Isolate Compromised Instance**
```python
import boto3

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    # Triggered by GuardDuty finding via EventBridge
    finding_type = event['detail']['type']
    
    if 'Backdoor' in finding_type or 'Trojan' in finding_type:
        instance_id = event['detail']['resource']['instanceDetails']['instanceId']
        
        # Attach quarantine security group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=['sg-quarantine']
        )
        
        # Tag instance
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'Status', 'Value': 'Quarantined'}]
        )
        
        # Create snapshot for forensics
        volumes = ec2.describe_volumes(
            Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
        )
        
        for volume in volumes['Volumes']:
            ec2.create_snapshot(
                VolumeId=volume['VolumeId'],
                Description=f"Forensic snapshot - {finding_type}"
            )
        
        return {'status': 'Instance quarantined'}
```

**Example 2: Auto-Revoke Exposed Access Keys**
```python
import boto3

iam = boto3.client('iam')

def lambda_handler(event, context):
    # Triggered by GuardDuty finding for exposed credentials
    access_key_id = event['detail']['resource']['accessKeyDetails']['accessKeyId']
    username = event['detail']['resource']['accessKeyDetails']['userName']
    
    # Disable access key
    iam.update_access_key(
        UserName=username,
        AccessKeyId=access_key_id,
        Status='Inactive'
    )
    
    # Send notification
    sns = boto3.client('sns')
    sns.publish(
        TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
        Subject='Exposed Access Key Disabled',
        Message=f'Access key {access_key_id} for user {username} has been disabled due to exposure'
    )
    
    return {'status': 'Access key disabled'}
```

**Example 3: Auto-Remediate Non-Compliant S3 Bucket**
```python
import boto3

s3 = boto3.client('s3')

def lambda_handler(event, context):
    # Triggered by Config rule non-compliance
    bucket_name = event['detail']['configurationItem']['resourceName']
    
    # Enable encryption
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                }
            }]
        }
    )
    
    # Block public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    
    # Enable versioning
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    
    return {'status': 'Bucket remediated'}
```

### Forensics

**Evidence Collection**:

1. **CloudTrail Logs**
   - Copy to separate S3 bucket for preservation
   - Enable log file integrity validation

2. **VPC Flow Logs**
   - Identify communication patterns
   - Track data exfiltration

3. **EC2 Forensics**
   - Create EBS snapshot before changes
   - Memory dump (if possible before stop)
   - Analyze disk image offline

4. **S3 Access Logs**
   - Identify unauthorized access
   - Track data downloads

**Forensic Instance Setup**:
```bash
# Create forensic instance from snapshot
aws ec2 run-instances \
  --image-id ami-forensics-ami \
  --instance-type m5.large \
  --subnet-id subnet-isolated \
  --security-group-ids sg-forensics

# Attach compromised volume as secondary
aws ec2 attach-volume \
  --volume-id vol-compromised \
  --instance-id i-forensics \
  --device /dev/sdf
```

### Post-Incident Activity

**After Incident Resolution**:

1. **Document Incident**
   - Timeline of events
   - Actions taken
   - Resources affected
   - Root cause
   - Impact assessment

2. **Lessons Learned Meeting**
   - What worked well?
   - What could be improved?
   - Were detection/response times acceptable?

3. **Update Defenses**
   - Implement new controls
   - Update playbooks
   - Enhance monitoring
   - Security awareness training

4. **Compliance Reporting**
   - Notify affected parties (if required)
   - Regulatory notifications (if applicable)
   - Internal reporting

### Incident Response Best Practices

✅ **Develop and test incident response plans regularly**
✅ **Automate common response actions**
✅ **Preserve evidence (snapshots, logs) before remediation**
✅ **Use separate AWS account for security tools**
✅ **Maintain break-glass access procedures**
✅ **Practice incident response (tabletop exercises)**
✅ **Document all actions during incident**
✅ **Continuously improve based on lessons learned**

### Common Exam Scenarios

**Scenario**: GuardDuty detects compromised EC2 instance
- **Solution**: EventBridge rule → Lambda isolates instance (quarantine SG), creates snapshot, notifies security team

**Scenario**: Exposed IAM credentials detected
- **Solution**: Immediately disable access keys, review CloudTrail for unauthorized actions, rotate all affected credentials

**Scenario**: S3 bucket made public accidentally
- **Solution**: Enable S3 Block Public Access, review bucket policy, enable MFA Delete, audit access logs

**Scenario**: Need to investigate security incident
- **Solution**: Preserve CloudTrail/VPC Flow Logs, create EBS snapshots, analyze logs in forensic environment

**Scenario**: Automate response to Config rule violations
- **Solution**: Config rule → EventBridge → Lambda remediation → Update Security Hub finding status

### Common Exam Traps

❌ **Trap**: Immediately terminating compromised instance
✅ **Truth**: First create snapshot for forensics, then isolate, then terminate

❌ **Trap**: Only disabling compromised user without checking for backdoors
✅ **Truth**: Check for IAM users/roles/policies created by attacker, unauthorized resources, persistence mechanisms

❌ **Trap**: Thinking automated remediation handles all incidents
✅ **Truth**: Automation for common issues; complex incidents require human analysis

❌ **Trap**: Not preserving logs before remediation
✅ **Truth**: Logs may be critical evidence; preserve before making changes

---

## Chapter 11: Securing Real-World Applications {#chapter-11-application-security}

### Sample Application Architecture

**Social Media Application Components**:
- **Frontend**: CloudFront + S3 (static website)
- **API**: API Gateway + Lambda
- **Authentication**: Amazon Cognito
- **Data**: DynamoDB (users, posts, relationships)
- **Media Storage**: S3 (user photos)
- **Search**: Elasticsearch Service

### OWASP Top 10 for AWS

#### 1. Injection Attacks

**SQL Injection** (not applicable to DynamoDB, but relevant for RDS):
- Use parameterized queries
- Input validation
- Least privilege database credentials

**NoSQL Injection** (DynamoDB):
```python
# Vulnerable
user_id = event['queryStringParameters']['user_id']
response = table.query(
    KeyConditionExpression=f"user_id = {user_id}"  # DANGEROUS
)

# Secure
from boto3.dynamodb.conditions import Key

response = table.query(
    KeyConditionExpression=Key('user_id').eq(user_id)  # SAFE - uses parameterized query
)
```

**Command Injection**:
- Never pass user input directly to shell commands
- Use language-specific libraries instead of shell commands
- If shell required, validate and sanitize input

**Mitigation**:
- Input validation
- Parameterized queries
- ORM/SDK usage (not raw queries)
- Principle of least privilege

#### 2. Broken Authentication

**Common Issues**:
- Weak password policies
- No MFA
- Session tokens not rotated
- Credentials in code

**AWS Solution: Amazon Cognito**

**Cognito User Pool Features**:
- Password policies (length, complexity)
- MFA (SMS, TOTP, email)
- Account lockout policies
- Password breach protection (compromise detection)
- Adaptive authentication (risk-based)

**Password Policy Example**:
```json
{
  "MinimumLength": 12,
  "RequireUppercase": true,
  "RequireLowercase": true,
  "RequireNumbers": true,
  "RequireSymbols": true,
  "PasswordHistorySize": 12
}
```

**Cognito Architecture**:
```
User → Cognito User Pool → Authentication
                          ↓
                    JWT Tokens (ID, Access, Refresh)
                          ↓
                    API Gateway (with Cognito Authorizer)
                          ↓
                    Lambda
```

**Cognito MFA**:
- SMS-based (not recommended for high security)
- TOTP (Time-based One-Time Password) - Google Authenticator
- Hardware tokens

**Compromised Credentials Detection**:
- Cognito checks against known breached credentials databases
- Configurable actions: Block, notify, require password reset

#### 3. Sensitive Data Exposure

**Data Classification**:
- Public: Marketing content
- Internal: Business data
- Confidential: User PII
- Restricted: Payment data, health records

**Protection Strategies**:

1. **Encryption at Rest**: KMS for S3, DynamoDB, RDS
2. **Encryption in Transit**: TLS/SSL for all communications
3. **Access Control**: IAM policies, bucket policies, VPC endpoints
4. **Tokenization**: Replace sensitive data with tokens
5. **Data Masking**: Hide sensitive portions (e.g., ****1234 for credit cards)

**S3 Security for User Photos**:
```python
# Generate pre-signed URL for secure upload
s3 = boto3.client('s3')

presigned_url = s3.generate_presigned_url(
    'put_object',
    Params={
        'Bucket': 'user-photos',
        'Key': f'users/{user_id}/photo.jpg',
        'ContentType': 'image/jpeg',
        'ServerSideEncryption': 'aws:kms',
        'SSEKMSKeyId': 'arn:aws:kms:us-east-1:123456789012:key/12345678'
    },
    ExpiresIn=3600,  # 1 hour
    HttpMethod='PUT'
)

# User uploads directly to S3 with pre-signed URL (no app backend involved)
```

**Benefits of Pre-Signed URLs**:
- Temporary access
- No credentials exposed
- Fine-grained permissions
- Offload traffic from application

#### 4. XML External Entities (XXE)

**Not common in AWS serverless architecture** (JSON-based APIs)

**If parsing XML**:
- Disable external entity processing
- Use safe XML parsers
- Validate and sanitize XML input

#### 5. Broken Access Control

**Common Issues**:
- Insecure direct object references
- Missing function-level access control
- Forced browsing

**Example Vulnerability**:
```python
# INSECURE - No authorization check
def get_user_profile(event, context):
    user_id = event['pathParameters']['userId']
    # Anyone can access any user's profile
    return dynamodb.get_item(Key={'user_id': user_id})
```

**Secure Implementation**:
```python
# SECURE - Authorization check
def get_user_profile(event, context):
    requested_user_id = event['pathParameters']['userId']
    authenticated_user_id = event['requestContext']['authorizer']['claims']['sub']
    
    # Check if authenticated user is authorized to view this profile
    if requested_user_id != authenticated_user_id:
        # Check if they're friends or if profile is public
        if not is_authorized(authenticated_user_id, requested_user_id):
            return {'statusCode': 403, 'body': 'Forbidden'}
    
    return dynamodb.get_item(Key={'user_id': requested_user_id})
```

**Access Control Patterns**:
1. **Authentication**: Cognito verifies identity
2. **Authorization**: Lambda checks permissions
3. **Attribute-based**: Use tags/attributes for fine-grained control

**API Gateway Authorizers**:
- **Cognito User Pool**: JWT validation
- **Lambda Authorizer**: Custom logic
- **IAM**: For service-to-service

#### 6. Security Misconfiguration

**Common AWS Misconfigurations**:
- Public S3 buckets
- Overly permissive security groups
- Default credentials/keys
- Missing encryption
- No logging/monitoring
- Unused ports open

**Prevention**:
- Use AWS Config rules
- Enable Security Hub standards
- Use CloudFormation/Terraform (Infrastructure as Code)
- Regular security assessments
- Automated compliance checks

**Security Group Best Practices**:
```
# BAD
Inbound: 0.0.0.0/0:22 (SSH from anywhere)

# GOOD
Inbound: 203.0.113.0/24:22 (SSH from corporate network only)
Inbound: sg-alb:8080 (App traffic from ALB security group only)
```

#### 7. Cross-Site Scripting (XSS)

**Types**:
- **Reflected XSS**: User input reflected in response
- **Stored XSS**: Malicious script stored in database
- **DOM-based XSS**: Client-side code vulnerability

**Protection**:
1. **Input Validation**: Reject invalid data
2. **Output Encoding**: Encode before rendering
3. **Content Security Policy (CSP)**: HTTP header restricting resource loading
4. **HTTPOnly Cookies**: Prevent JavaScript access to cookies

**CSP Header Example**:
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'
```

**Lambda@Edge Security Headers**:
```javascript
exports.handler = (event, context, callback) => {
    const response = event.Records[0].cf.response;
    const headers = response.headers;
    
    headers['content-security-policy'] = [{
        key: 'Content-Security-Policy',
        value: "default-src 'self'; script-src 'self'"
    }];
    headers['x-content-type-options'] = [{
        key: 'X-Content-Type-Options',
        value: 'nosniff'
    }];
    headers['x-frame-options'] = [{
        key: 'X-Frame-Options',
        value: 'DENY'
    }];
    headers['x-xss-protection'] = [{
        key: 'X-XSS-Protection',
        value: '1; mode=block'
    }];
    
    callback(null, response);
};
```

#### 8. Insecure Deserialization

**Risk**: Arbitrary code execution from untrusted serialized data

**Mitigation**:
- Avoid deserializing untrusted data
- Use JSON (simpler, less risky than pickle/serialization)
- Implement integrity checks (HMAC)
- Run deserialization in isolated environment (Lambda)

#### 9. Using Components with Known Vulnerabilities

**Strategies**:
- Regularly update dependencies
- Use dependency scanning tools
- Monitor security advisories
- Automated patch management

**AWS Tools**:
- **Amazon Inspector**: Scan EC2 and containers for CVEs
- **ECR Image Scanning**: Scan container images for vulnerabilities
- **Systems Manager Patch Manager**: Automate OS patching

**Dependency Scanning**:
```bash
# Python
pip install safety
safety check

# Node.js
npm audit
npm audit fix

# Container scanning
docker scan my-image:latest
```

#### 10. Insufficient Logging & Monitoring

**What to Log**:
- Authentication events (success/failure)
- Authorization failures
- Input validation failures
- Application errors
- High-value transactions
- Admin actions

**AWS Logging Services**:
- **CloudTrail**: API activity
- **VPC Flow Logs**: Network traffic
- **Application Logs**: CloudWatch Logs
- **Access Logs**: ALB, S3, CloudFront
- **Database Logs**: RDS/Aurora query logs

**Logging Best Practices**:
✅ Log to CloudWatch Logs from Lambda
✅ Include request ID in all logs
✅ Don't log sensitive data (passwords, tokens)
✅ Use structured logging (JSON)
✅ Set appropriate retention periods
✅ Forward to SIEM for analysis

**Example Application Logging**:
```python
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    request_id = context.request_id
    user_id = event['requestContext']['authorizer']['claims']['sub']
    
    logger.info(json.dumps({
        'request_id': request_id,
        'user_id': user_id,
        'action': 'get_profile',
        'timestamp': context.timestamp
    }))
    
    try:
        # Process request
        pass
    except Exception as e:
        logger.error(json.dumps({
            'request_id': request_id,
            'user_id': user_id,
            'error': str(e)
        }))
        raise
```

### API Gateway Security

**Authentication & Authorization**:
1. **Cognito User Pool Authorizer**: JWT validation
2. **Lambda Authorizer (Custom)**: Custom auth logic
3. **IAM Authorization**: For AWS service calls
4. **API Keys**: Rate limiting and basic access control (not for auth)

**Throttling**:
- Account-level limits
- Per-API limits
- Per-method limits
- Per-client (API key) limits

**Example Throttling**:
```
Burst: 5000 requests
Steady-state: 10000 requests per second
```

**WAF Integration**:
- SQL injection protection
- XSS protection
- Rate-based rules
- Geo-blocking

**API Gateway Resource Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-east-1:123456789012:api-id/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": ["203.0.113.0/24"]
        }
      }
    }
  ]
}
```

### Lambda Security

**Function Security**:
- **Execution Role**: IAM role for Lambda to access AWS services
- **Resource Policies**: Control who can invoke function
- **VPC**: Isolate function in VPC
- **Environment Variables**: Encrypt with KMS
- **Layers**: Share code securely

**Execution Role Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Users"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/12345"
    }
  ]
}
```

**Environment Variable Encryption**:
```bash
aws lambda create-function \
  --function-name my-function \
  --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/12345 \
  --environment "Variables={DB_PASSWORD=encrypted-value}"
```

### DynamoDB Security

**Access Control**:
- IAM policies for API access
- Fine-grained access control with IAM conditions
- VPC endpoints for private access

**Fine-Grained Access Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Users",
      "Condition": {
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"]
        }
      }
    }
  ]
}
```
*Users can only access their own data (partition key matches their user ID)*

**Encryption**:
- At-rest encryption (always enabled)
- In-transit encryption (TLS)

**Backups**:
- Point-in-time recovery
- On-demand backups
- Cross-region replication (Global Tables)

### Application Security Best Practices

✅ **Use Cognito for user authentication**
✅ **Implement authorization checks in Lambda**
✅ **Encrypt sensitive data with KMS**
✅ **Use pre-signed URLs for temporary S3 access**
✅ **Enable WAF on API Gateway/CloudFront**
✅ **Implement rate limiting and throttling**
✅ **Use VPC endpoints for private AWS service access**
✅ **Log all authentication and authorization events**
✅ **Regularly scan for vulnerabilities (Inspector, dependency scanning)**
✅ **Use Infrastructure as Code (CloudFormation/Terraform)**
✅ **Implement security headers (CSP, X-Frame-Options, etc.)**
✅ **Never hardcode credentials (use Secrets Manager/Parameter Store)**

### Common Exam Scenarios

**Scenario**: Secure user authentication for mobile app
- **Solution**: Cognito User Pool with MFA, password policy, adaptive authentication

**Scenario**: Prevent unauthorized access to user data in DynamoDB
- **Solution**: Fine-grained IAM policies with LeadingKeys condition matching user ID

**Scenario**: Secure S3 uploads from web application
- **Solution**: Pre-signed URLs from Lambda with short expiration, enforce encryption

**Scenario**: Protect API from common web attacks
- **Solution**: WAF on API Gateway with managed rule groups (Core Rule Set, SQL injection, XSS)

**Scenario**: Rotate database credentials without downtime
- **Solution**: Secrets Manager with automatic rotation Lambda

### Common Exam Traps

❌ **Trap**: Using API keys for authentication
✅ **Truth**: API keys are for usage tracking, not authentication; use Cognito or IAM

❌ **Trap**: Thinking Lambda is isolated by default
✅ **Truth**: Lambda has internet access by default unless in VPC without NAT

❌ **Trap**: Assuming Cognito handles authorization
✅ **Truth**: Cognito handles authentication; authorization logic must be in application (Lambda)

❌ **Trap**: Hardcoding KMS key IDs in application code
✅ **Truth**: Use environment variables or Parameter Store for configuration

---

## Key AWS Security Services Reference {#security-services-reference}

### Identity & Access Management
| Service | Purpose | Key Features |
|---------|---------|-------------|
| **IAM** | Authentication and authorization | Users, groups, roles, policies, MFA |
| **AWS Organizations** | Multi-account management | SCPs, consolidated billing, OUs |
| **AWS SSO** | Single sign-on | Centralized access, SAML integration |
| **Cognito** | User authentication for apps | User pools, identity pools, MFA |
| **Directory Service** | Managed Active Directory | AD integration, LDAP |

### Network Security
| Service | Purpose | Key Features |
|---------|---------|-------------|
| **VPC** | Virtual private network | Subnets, route tables, NAT, VPN |
| **Security Groups** | Instance-level firewall | Stateful, allow rules only |
| **Network ACLs** | Subnet-level firewall | Stateless, allow and deny rules |
| **AWS WAF** | Web application firewall | SQL injection, XSS, rate limiting |
| **AWS Shield** | DDoS protection | Standard (free), Advanced ($3k/month) |
| **Network Firewall** | Managed network firewall | IPS, domain filtering, stateful |
| **Transit Gateway** | Network hub | VPC connectivity, transitive routing |

### Data Protection
| Service | Purpose | Key Features |
|---------|---------|-------------|
| **KMS** | Encryption key management | CMKs, automatic rotation, audit trail |
| **CloudHSM** | Hardware security module | FIPS 140-2 Level 3, customer-managed |
| **Secrets Manager** | Secrets storage and rotation | Auto-rotation, audit trail |
| **Certificate Manager** | SSL/TLS certificates | Free certificates, auto-renewal |
| **Macie** | S3 data discovery | PII detection, ML-based |

### Logging & Monitoring
| Service | Purpose | Key Features |
|---------|---------|-------------|
| **CloudTrail** | API activity logging | Management/data events, insights |
| **CloudWatch** | Metrics and logs | Alarms, dashboards, Logs Insights |
| **Config** | Resource configuration tracking | Compliance rules, remediation |
| **VPC Flow Logs** | Network traffic logs | IP-level logging, troubleshooting |
| **EventBridge** | Event-driven automation | Rules, patterns, targets |

### Threat Detection & Response
| Service | Purpose | Key Features |
|---------|---------|-------------|
| **GuardDuty** | Threat detection | ML-based, VPC/CloudTrail/DNS analysis |
| **Security Hub** | Security findings aggregation | Multi-service, compliance standards |
| **Inspector** | Vulnerability assessment | CVE scanning, CIS benchmarks |
| **Detective** | Security investigation | Graph-based analysis, root cause |

### Compliance & Governance
| Service | Purpose | Key Features |
|---------|---------|-------------|
| **Artifact** | Compliance reports | SOC, PCI, ISO reports |
| **Audit Manager** | Compliance automation | Evidence collection, frameworks |
| **Control Tower** | Multi-account governance | Landing zone, guardrails |

---

## Common Exam Traps & Scenarios {#exam-traps}

### Question Pattern Recognition

#### Scenario: "Prevent" vs "Detect"
- **Prevent**: Security Groups, NACLs, SCPs, WAF, IAM policies
- **Detect**: GuardDuty, Config Rules, CloudTrail, VPC Flow Logs

**Example**: "How to PREVENT unauthorized API calls?"
✅ IAM policy with explicit deny or SCP
❌ CloudTrail (detects, doesn't prevent)

#### Scenario: "Audit" or "Compliance"
- Look for: CloudTrail, Config, Security Hub, Audit Manager
- Not: GuardDuty (threat detection, not compliance)

**Example**: "Meet compliance requirements for tracking resource configuration changes"
✅ AWS Config with compliance rules
❌ CloudWatch (for operational metrics, not config compliance)

#### Scenario: "Real-time" or "Automated Response"
- Look for: EventBridge + Lambda, Security Hub automated actions
- Not: Manual SNS notifications without automation

**Example**: "Automatically remediate non-compliant resources"
✅ Config Rule → EventBridge → Lambda remediation
❌ Config Rule → SNS → Manual remediation

#### Scenario: "Cost-Effective" or "Free"
- Free: Security Groups, NACLs, IAM, CloudTrail (first trail), Shield Standard, S3 Block Public Access
- Paid: WAF, Shield Advanced, GuardDuty, Config, KMS CMKs

**Example**: "Most cost-effective DDoS protection"
✅ Shield Standard (free, automatic)
❌ Shield Advanced ($3000/month)

#### Scenario: "Multi-Account" or "Organization-Wide"
- Look for: AWS Organizations, SCPs, Control Tower, Config Aggregators, GuardDuty delegated administrator

**Example**: "Enforce security policy across all accounts in organization"
✅ Service Control Policy (SCP)
❌ IAM policy (account-specific)

#### Scenario: "Encryption" Context Matters
| Scenario | Solution |
|----------|----------|
| Encrypt existing RDS | Snapshot → Copy with encryption → Restore |
| Encrypt S3 objects | Bucket policy deny without encryption header |
| Manage own keys | KMS CMK or CloudHSM |
| Compliance (FIPS 140-2 Level 3) | CloudHSM |
| Audit key usage | KMS CMK (CloudTrail logs all usage) |
| Rotate encryption keys | KMS automatic rotation (yearly) |

#### Scenario: "Cross-Account Access"
- **IAM Role**: Preferred for AWS services
- **Resource Policy**: For S3, SNS, SQS, KMS, Lambda
- **VPC Peering**: Network-level, not IAM

**Example**: "Allow users in Account A to read S3 bucket in Account B"
✅ Bucket policy (Principal: Account A) + IAM policy in Account A
❌ VPC peering (doesn't grant IAM permissions)

### Service Confusion Clarification

#### IAM Access Analyzer vs GuardDuty
| Feature | IAM Access Analyzer | GuardDuty |
|---------|---------------------|-----------|
| **Purpose** | Find overly permissive access | Detect threats |
| **Method** | Logic-based analysis | ML-based detection |
| **Findings** | External resource access | Malicious activity |
| **When to Use** | Audit permissions | Detect attacks |

#### CloudTrail vs Config vs VPC Flow Logs
| Aspect | CloudTrail | Config | VPC Flow Logs |
|--------|-----------|--------|---------------|
| **What** | WHO did WHAT, WHEN | WHAT config WAS and IS | Network traffic metadata |
| **Focus** | API calls | Resource configuration | IP traffic |
| **Use Case** | Security audit | Compliance | Network troubleshooting |

#### KMS vs CloudHSM
| Feature | KMS | CloudHSM |
|---------|-----|----------|
| **Control** | Shared tenancy | Dedicated hardware |
| **Compliance** | FIPS 140-2 Level 2 | FIPS 140-2 Level 3 |
| **Management** | AWS manages | Customer manages |
| **Integration** | Native AWS service integration | Manual integration |
| **Cost** | $1/key/month + usage | $1.45/hour per HSM |
| **Use When** | General use | Regulatory requirement |

#### WAF vs Shield vs Network Firewall
| Service | Layer | Purpose | Use Case |
|---------|-------|---------|----------|
| **WAF** | Layer 7 (HTTP/HTTPS) | Application attacks | Web app protection |
| **Shield** | Layer 3/4 (Network) | DDoS protection | Infrastructure protection |
| **Network Firewall** | Layer 3-7 | IPS/IDS | Network inspection |

#### Security Group vs NACL
| Feature | Security Group | NACL |
|---------|----------------|------|
| **Level** | Instance (ENI) | Subnet |
| **State** | Stateful | Stateless |
| **Rules** | Allow only | Allow + Deny |
| **Evaluation** | All rules | First match |
| **Default** | Deny inbound | Allow all |
| **Use For** | Primary firewall | Additional defense, explicit denies |

### Common Wrong Answer Patterns

#### 1. Overcomplicating Solutions
**Question Pattern**: "Simplest way to..."
❌ Wrong: Multi-step solution with multiple services
✅ Right: Single service or built-in feature

**Example**: "Simplest way to block IP from accessing resources"
❌ WAF + CloudFront + Lambda
✅ Security Group or NACL deny rule

#### 2. Using Expensive Solutions for Simple Problems
**Question Pattern**: Mentions "cost-effective"
❌ Wrong: Premium services (Shield Advanced, CloudHSM)
✅ Right: Free/cheaper alternatives (Shield Standard, KMS)

#### 3. Confusing Prevention with Detection
**Question Pattern**: "Prevent" vs "Detect" vs "Respond"
- **Prevent**: IAM deny, SCP, Security Group, NACL, WAF
- **Detect**: GuardDuty, Config, CloudTrail, Macie
- **Respond**: EventBridge, Lambda, Systems Manager

#### 4. Forgetting About Free Services
**Free Security Services**:
- IAM (users, groups, roles, policies)
- Security Groups, NACLs
- CloudTrail (first trail per region)
- Shield Standard
- S3 Block Public Access
- VPC endpoints (Gateway endpoints for S3/DynamoDB)

#### 5. Assuming Services Work Without Configuration
❌ Wrong assumptions:
- GuardDuty detects everything automatically (no, needs to be enabled)
- Config prevents non-compliance (no, only detects)
- CloudTrail logs data events by default (no, only management events)
- Macie scans all S3 automatically (no, requires job creation)

### Exam Day Strategy

**Time Management**:
- 170 minutes for 65 questions = ~2.6 minutes per question
- Flag difficult questions, come back later
- Don't spend >4 minutes on any question

**Elimination Strategy**:
1. Eliminate obviously wrong answers first
2. Identify keywords (prevent/detect, cost-effective, real-time)
3. Choose simplest solution that meets all requirements
4. When stuck between two answers, consider: Which is simpler? Which is more cost-effective? Which AWS recommends?

**Common Keywords & What They Mean**:
- **Least operational overhead**: Managed services, automation
- **Cost-effective**: Free or cheaper services, avoid advanced tiers
- **Highly available**: Multi-AZ, managed services
- **Real-time**: EventBridge, Lambda, not batch processing
- **Audit/Compliance**: CloudTrail, Config, Security Hub
- **Prevent**: IAM policies, SCPs, Security Groups
- **Detect**: GuardDuty, Config Rules, CloudTrail

---

## Acronyms & Definitions {#acronyms}

### Core AWS Acronyms

**IAM** - Identity and Access Management  
**SCPs** - Service Control Policies  
**CMK** - Customer Managed Key  
**KMS** - Key Management Service  
**HSM** - Hardware Security Module  
**VPC** - Virtual Private Cloud  
**ENI** - Elastic Network Interface  
**IGW** - Internet Gateway  
**NAT** - Network Address Translation  
**NACL** - Network Access Control List  
**WAF** - Web Application Firewall  
**DDoS** - Distributed Denial of Service  
**TLS/SSL** - Transport Layer Security / Secure Sockets Layer  
**ACL** - Access Control List  
**CIDR** - Classless Inter-Domain Routing  
**MFA** - Multi-Factor Authentication  
**SSO** - Single Sign-On  
**SAML** - Security Assertion Markup Language  
**JWT** - JSON Web Token  
**API** - Application Programming Interface  
**ARN** - Amazon Resource Name  
**SDK** - Software Development Kit  
**CLI** - Command Line Interface

### Security Service Acronyms

**GuardDuty** - Intelligent threat detection service  
**Macie** - Data discovery and protection service  
**Inspector** - Vulnerability assessment service  
**Detective** - Security investigation service  
**Security Hub** - Centralized security management  
**CloudTrail** - API activity logging service  
**CloudWatch** - Monitoring and logging service  
**Config** - Resource configuration tracking  
**EventBridge** - Event-driven service bus  
**Systems Manager** (SSM) - Operations management  
**Secrets Manager** - Secrets storage and rotation  
**Parameter Store** - Configuration and secrets storage  
**Certificate Manager** (ACM) - SSL/TLS certificate management  
**Resource Access Manager** (RAM) - Resource sharing  
**PrivateLink** - Private connectivity to services  
**Transit Gateway** (TGW) - Network transit hub  
**Direct Connect** (DX) - Dedicated network connection

### Compliance & Standards

**PCI DSS** - Payment Card Industry Data Security Standard  
**HIPAA** - Health Insurance Portability and Accountability Act  
**SOC** - Service Organization Control (SOC 1, SOC 2, SOC 3)  
**ISO** - International Organization for Standardization  
**GDPR** - General Data Protection Regulation  
**NIST** - National Institute of Standards and Technology  
**CIS** - Center for Internet Security  
**FedRAMP** - Federal Risk and Authorization Management Program  
**FIPS** - Federal Information Processing Standard  
**CVE** - Common Vulnerabilities and Exposures  
**CVSS** - Common Vulnerability Scoring System  
**OWASP** - Open Web Application Security Project

### Security Concepts

**AAA** - Authentication, Authorization, Accounting  
**CIA Triad** - Confidentiality, Integrity, Availability  
**RBAC** - Role-Based Access Control  
**ABAC** - Attribute-Based Access Control  
**WORM** - Write Once Read Many  
**PKI** - Public Key Infrastructure  
**MTU** - Maximum Transmission Unit  
**RPO** - Recovery Point Objective (max acceptable data loss)  
**RTO** - Recovery Time Objective (max acceptable downtime)  
**AES** - Advanced Encryption Standard  
**RSA** - Rivest–Shamir–Adleman (encryption algorithm)  
**HMAC** - Hash-based Message Authentication Code  
**IDS/IPS** - Intrusion Detection System / Intrusion Prevention System  
**SIEM** - Security Information and Event Management  
**SOAR** - Security Orchestration, Automation and Response  
**C&C/C2** - Command and Control (attack infrastructure)

### Network Terms

**DHCP** - Dynamic Host Configuration Protocol  
**DNS** - Domain Name System  
**BGP** - Border Gateway Protocol  
**IPsec** - Internet Protocol Security  
**VPN** - Virtual Private Network  
**GENEVE** - Generic Network Virtualization Encapsulation  
**MTU** - Maximum Transmission Unit  
**TTL** - Time To Live  
**RPM** - Requests Per Minute  
**RPS** - Requests Per Second

### Attack Types

**XSS** - Cross-Site Scripting  
**CSRF** - Cross-Site Request Forgery  
**XXE** - XML External Entity  
**SSRF** - Server-Side Request Forgery  
**IDOR** - Insecure Direct Object Reference  
**LFI/RFI** - Local/Remote File Inclusion  
**MITM** - Man-in-the-Middle  
**APT** - Advanced Persistent Threat

### Data Terms

**PII** - Personally Identifiable Information  
**PHI** - Protected Health Information  
**SSN** - Social Security Number  
**PITR** - Point-in-Time Recovery  
**IOPS** - Input/Output Operations Per Second  
**EBS** - Elastic Block Store  
**S3** - Simple Storage Service  
**CORS** - Cross-Origin Resource Sharing

---

## Final Exam Tips

### Study Strategy

**Week Before Exam**:
- Review this study guide daily
- Practice questions (AWS practice exams, Whizlabs, Tutorials Dojo)
- Focus on weak areas
- Review AWS Security Specialty exam guide

**Day Before Exam**:
- Light review only
- Review acronyms and service comparison tables
- Get good sleep

**Exam Day**:
- Arrive 15 minutes early (if in-person)
- Use scratch paper for elimination
- Flag uncertain questions
- Review flagged questions if time permits

### What to Memorize

**Must Know Cold**:
- IAM policy evaluation logic (explicit deny > explicit allow > implicit deny)
- Security Group vs NACL differences
- KMS vs CloudHSM differences
- Service comparison tables in this guide
- Common port numbers (22 SSH, 443 HTTPS, 3389 RDP, 3306 MySQL)
- Which services are free vs paid

**Understand Conceptually**:
- When to use each security service
- How services integrate (e.g., GuardDuty → EventBridge → Lambda)
- Cross-account access patterns
- Encryption patterns (at rest, in transit, envelope encryption)
- Incident response workflow
- OWASP Top 10 and AWS mitigations

### Resources for Further Study

**Official AWS Resources**:
- AWS Security Specialty Exam Guide
- AWS Security Documentation
- AWS Security Blog
- AWS Whitepapers (Security, Well-Architected Framework)

**Practice Exams**:
- AWS Official Practice Exam
- Tutorials Dojo Practice Tests
- Whizlabs Practice Tests

**Hands-On Practice**:
- AWS Free Tier account
- A Cloud Guru / Linux Academy labs
- QwikLabs AWS Security Quest

---

## Quick Reference Tables

### Port Numbers
| Port | Service |
|------|---------|
| 20/21 | FTP |
| 22 | SSH |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 465 | SMTPS |
| 993 | IMAPS |
| 995 | POP3S |
| 1433 | MS SQL |
| 1521 | Oracle DB |
| 3306 | MySQL/Aurora |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 5439 | Redshift |
| 6379 | Redis |
| 8080 | HTTP Alternative |
| 27017 | MongoDB |

### AWS Service Ports
| Service | Port |
|---------|------|
| RDS MySQL | 3306 |
| RDS PostgreSQL | 5432 |
| RDS MS SQL | 1433 |
| RDS Oracle | 1521 |
| Aurora MySQL | 3306 |
| Aurora PostgreSQL | 5432 |
| Redshift | 5439 |
| ElastiCache Redis | 6379 |
| ElastiCache Memcached | 11211 |

### CIDR Notation Quick Reference
| CIDR | Addresses | Typical Use |
|------|-----------|-------------|
| /32 | 1 | Single host |
| /28 | 16 | Small subnet |
| /24 | 256 | Standard subnet |
| /20 | 4,096 | Large subnet |
| /16 | 65,536 | VPC |
| /8 | 16,777,216 | Class A network |

### CloudTrail Event Delay
| Event Type | Typical Delivery |
|------------|------------------|
| Management Events | ~15 minutes |
| Data Events | ~15 minutes |
| Insights Events | ~30 minutes |

### Service Limits (Common)
| Service | Default Limit |
|---------|---------------|
| VPCs per region | 5 |
| Security groups per VPC | 2,500 |
| Rules per security group | 60 |
| NACLs per VPC | 200 |
| Rules per NACL | 20 |
| IAM users per account | 5,000 |
| IAM groups per account | 300 |
| IAM roles per account | 1,000 |
| KMS CMKs per region | 10,000 |
| VPC peering per VPC | 125 |

### Encryption Algorithms
| Algorithm | Key Size | Use Case |
|-----------|----------|----------|
| AES-256 | 256-bit | General encryption |
| RSA-2048 | 2048-bit | Key exchange, signatures |
| RSA-4096 | 4096-bit | High security key exchange |

---

**Good luck with your AWS Certified Security - Specialty exam! 🎯**

