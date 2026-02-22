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
