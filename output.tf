# RDS endpoint for configuring web applications to connect to the database
output "rds_endpoint" {
  description = "Connection endpoint for the RDS instance (use this in your app config)"
  value       = aws_db_instance.default.endpoint
}

output "rds_address" {
  description = "Hostname of the RDS instance (host only, no port)"
  value       = aws_db_instance.default.address
}

# EFS outputs for mounting from web servers
output "efs_id" {
  description = "EFS file system ID (use when mounting)"
  value       = aws_efs_file_system.main.id
}

output "efs_dns_name" {
  description = "EFS DNS name for mounting (e.g. fs-xxxx.efs.region.amazonaws.com)"
  value       = aws_efs_file_system.main.dns_name
}

# Disaster recovery
output "backup_plan_id" {
  description = "AWS Backup plan ID for DR (RDS + EFS to us-west-2)"
  value       = aws_backup_plan.dr.id
}

output "dr_vault_arn" {
  description = "DR backup vault ARN (us-west-2)"
  value       = aws_backup_vault.dr.arn
}

# Monitoring
output "website_alerts_sns_topic_arn" {
  description = "SNS topic for website-down alerts; subscribe email in tfvars (alert_email)"
  value       = aws_sns_topic.website_alerts.arn
}

# Intranet (access from within VPC only, e.g. via VPN)
output "intranet_alb_dns_name" {
  description = "Internal ALB DNS for intranet app (HTTP, VPC-only)"
  value       = aws_lb.intranet_alb.dns_name
}

# N2G Auditing (set n2g_auditing_account_id to create role)
output "n2g_trusted_advisor_role_arn" {
  description = "Role ARN for N2G to assume (Trusted Advisor only); use when n2g_auditing_account_id is set"
  value       = length(aws_iam_role.n2g_trusted_advisor) > 0 ? aws_iam_role.n2g_trusted_advisor[0].arn : null
}

# PII storage
output "customer_pii_bucket" {
  description = "S3 bucket for customer PII (encrypted, 30d then Glacier, 5y retention)"
  value       = aws_s3_bucket.customer_pii.id
}
