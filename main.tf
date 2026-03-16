# =============================================================================
# NAS Financial — Terraform root
# =============================================================================
# Resources are split into domain-specific files:
#   data.tf           — Data sources (AMI, caller identity, region)
#   iam.tf            — IAM policies, groups, roles, EC2 SSM, N2G, Backup
#   vpc.tf            — VPC, subnets, IGW, NAT, route tables
#   security_groups.tf — Security groups, VPC endpoints (SSM)
#   public-website.tf — Public ALB, listeners, CloudFront, Route 53
#   monitoring.tf     — SNS, CloudWatch alarms
#   asg.tf            — Public web tier (launch template + ASG)
#   intranet.tf       — Internal ALB + ASG
#   rds.tf            — RDS MySQL
#   efs.tf            — EFS file system
#   s3.tf             — Customer PII bucket
#   backup.tf         — AWS Backup (primary + DR vault, plan, selection)
# =============================================================================
