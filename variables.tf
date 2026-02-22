variable "instance_type" {
  description = "EC2 instance type for web servers"
  type        = string
  default     = "t2.micro"
}

variable "certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS listener"
  type        = string
}

variable "zone_id" {
  description = "Route53 hosted zone ID for the domain"
  type        = string
}

variable "cloudfront_aliases" {
  description = "Custom domain aliases for the main CloudFront distribution. Set to [] temporarily if CNAMEAlreadyExists; then set to [\"www.fcjnwudo.com\"] and apply again."
  type        = list(string)
  default     = ["www.fcjnwudo.com"]
}

variable "db_username" {
  description = "Master username for the RDS database"
  type        = string
}

variable "db_password" {
  description = "Master password for the RDS database"
  type        = string
  sensitive   = true
}

variable "alert_email" {
  description = "Email address for website-down alerts (SNS subscription). Set in tfvars; confirm via email after apply."
  type        = string
  default     = ""
}

variable "n2g_auditing_account_id" {
  description = "AWS account ID of N2G Auditing (for cross-account Trusted Advisor role)"
  type        = string
  default     = ""
}
