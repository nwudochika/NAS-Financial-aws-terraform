# =============================================================================
# DATA SOURCES (used throughout)
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_ami" "amazon_linux_latest" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

# =============================================================================
# IAM — Access control, EC2 SSM, Backup role, N2G Auditing
# =============================================================================

resource "aws_iam_policy" "full_admin_no_billing" {
  name        = "FullAdminNoBilling"
  description = "Full administrator access excluding billing and cost management"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAllExceptBilling"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Sid      = "DenyBilling"
        Effect   = "Deny"
        Action   = ["aws-portal:*", "budgets:*", "ce:*", "cur:*", "freetier:*", "purchase-orders:*", "tax:*", "payments:*", "consolidatedbilling:*"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "FullAdminDeployRegion" {
  name        = "FullAdminDeployRegion"
  description = "Full administrator access for deployment region (us-east-1 only)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
      Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } }
    }]
  })
}

resource "aws_iam_group" "cloudspace_engineers" { name = "CloudSpace-Engineers" }
resource "aws_iam_group" "nas_security_team"   { name = "Nas_Financial_security" }
resource "aws_iam_group" "Operations"          { name = "Nas_Financial_Operations" }

resource "aws_iam_group_policy_attachment" "cloudspace_engineers_admin" {
  group = aws_iam_group.cloudspace_engineers.name
  policy_arn = aws_iam_policy.full_admin_no_billing.arn
}
resource "aws_iam_group_policy_attachment" "nas_security_team_admin" {
  group = aws_iam_group.nas_security_team.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_group_policy_attachment" "Operations_admin" {
  group = aws_iam_group.Operations.name
  policy_arn = aws_iam_policy.FullAdminDeployRegion.arn
}

# EC2 SSM role (Session Manager — no SSH)
resource "aws_iam_role" "ec2_ssm" {
  name = "nas-financial-ec2-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "nas-financial-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm.name
}

resource "aws_iam_policy" "cloudspace_web_server_ssm" {
  name        = "CloudSpaceWebServerSSM"
  description = "Allow Session Manager only on web servers (ManagedBy=CloudSpace)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSSMOnWebServers"
        Effect = "Allow"
        Action = ["ssm:StartSession", "ssm:ResumeSession", "ssm:DescribeSessions", "ssm:GetConnectionStatus", "ssm:TerminateSession"]
        Resource = "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = { StringEquals = { "ec2:ResourceTag/ManagedBy" = "CloudSpace" } }
      },
      {
        Sid      = "AllowSSMSessionDocuments"
        Effect   = "Allow"
        Action   = "ssm:StartSession"
        Resource = "arn:aws:ssm:*:*:session/document/AWS-StartInteractiveCommand"
      }
    ]
  })
}
resource "aws_iam_group_policy_attachment" "cloudspace_web_server_ssm" {
  group = aws_iam_group.cloudspace_engineers.name
  policy_arn = aws_iam_policy.cloudspace_web_server_ssm.arn
}

resource "aws_iam_policy" "deny_web_server_ssm" {
  name        = "DenyWebServerSSM"
  description = "Deny SSM on web servers (CloudSpace only)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenySSMOnWebServers"
      Effect = "Deny"
      Action = ["ssm:StartSession", "ssm:SendCommand", "ssm:ResumeSession", "ssm:TerminateSession"]
      Resource = "*"
      Condition = { StringEquals = { "ec2:ResourceTag/ManagedBy" = "CloudSpace" } }
    }]
  })
}
resource "aws_iam_group_policy_attachment" "nas_security_deny_web_ssm" {
  group = aws_iam_group.nas_security_team.name
  policy_arn = aws_iam_policy.deny_web_server_ssm.arn
}
resource "aws_iam_group_policy_attachment" "operations_deny_web_ssm" {
  group = aws_iam_group.Operations.name
  policy_arn = aws_iam_policy.deny_web_server_ssm.arn
}

# N2G Auditing — Trusted Advisor only (cross-account)
resource "aws_iam_role" "n2g_trusted_advisor" {
  count  = length(var.n2g_auditing_account_id) > 0 ? 1 : 0
  name   = "N2G-Auditing-TrustedAdvisor-Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.n2g_auditing_account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}
resource "aws_iam_role_policy" "n2g_trusted_advisor_only" {
  count  = length(var.n2g_auditing_account_id) > 0 ? 1 : 0
  name   = "TrustedAdvisorOnly"
  role   = aws_iam_role.n2g_trusted_advisor[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "TrustedAdvisorFullAccess"
      Effect = "Allow"
      Action = ["support:DescribeTrustedAdvisorChecks", "support:DescribeTrustedAdvisorCheckResult", "support:DescribeTrustedAdvisorCheckSummaries", "support:RefreshTrustedAdvisorCheck", "support:DescribeCases", "support:DescribeSeverityLevels"]
      Resource = "*"
    }]
  })
}

# AWS Backup role
resource "aws_iam_role" "backup" {
  name = "nas-financial-backup-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "backup.amazonaws.com" }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "backup" {
  role = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}
resource "aws_iam_role_policy_attachment" "backup_restore" {
  role = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

# =============================================================================
# VPC & NETWORKING
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  instance_tenancy     = "default"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "main" }
}

resource "aws_subnet" "public1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = { Name = "public1" }
}
resource "aws_subnet" "public2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  tags = { Name = "public2" }
}
resource "aws_subnet" "private1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1c"
  tags = { Name = "private1" }
}
resource "aws_subnet" "private2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1d"
  tags = { Name = "private2" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "main" }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}
resource "aws_route_table_association" "a1" {
  subnet_id      = aws_subnet.public1.id
  route_table_id = aws_route_table.public_rt.id
}
resource "aws_route_table_association" "a2" {
  subnet_id      = aws_subnet.public2.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "nat-eip" }
}
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public1.id
  tags = { Name = "main-nat" }
  depends_on = [aws_internet_gateway.igw]
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = { Name = "private-rt" }
}
resource "aws_route_table_association" "private1" {
  subnet_id      = aws_subnet.private1.id
  route_table_id = aws_route_table.private_rt.id
}
resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.private2.id
  route_table_id = aws_route_table.private_rt.id
}

# =============================================================================
# SECURITY GROUPS
# =============================================================================

resource "aws_security_group" "vpc_endpoints" {
  vpc_id      = aws_vpc.main.id
  name        = "vpc-endpoints-sg"
  description = "HTTPS from VPC for SSM endpoints"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "vpc-endpoints-sg" }
}

resource "aws_security_group" "alb_sg" {
  vpc_id      = aws_vpc.main.id
  name        = "alb-sg"
  description = "Public ALB — HTTPS only"
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ec2_sg" {
  vpc_id      = aws_vpc.main.id
  name        = "ec2-sg"
  description = "Web servers — HTTP from ALB only"
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "intranet_alb_sg" {
  vpc_id      = aws_vpc.main.id
  name        = "intranet-alb-sg"
  description = "Internal ALB — HTTP from VPC"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "intranet-alb-sg" }
}

resource "aws_security_group" "intranet_ec2_sg" {
  vpc_id      = aws_vpc.main.id
  name        = "intranet-ec2-sg"
  description = "Intranet app — HTTP from internal ALB only"
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.intranet_alb_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "intranet-ec2-sg" }
}

resource "aws_security_group" "database_sg" {
  vpc_id      = aws_vpc.main.id
  name        = "database-access-sg"
  description = "RDS — 3306 from web servers only"
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "DatabaseAccessSG" }
}

resource "aws_security_group" "efs_sg" {
  vpc_id      = aws_vpc.main.id
  name        = "efs-access-sg"
  description = "EFS — NFS from web servers only"
  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "EFSAccessSG" }
}

# =============================================================================
# VPC ENDPOINTS (SSM — Session Manager traffic stays in AWS)
# =============================================================================

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.id}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private1.id, aws_subnet.private2.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.id}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private1.id, aws_subnet.private2.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.id}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private1.id, aws_subnet.private2.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

# =============================================================================
# PUBLIC WEBSITE — ALB, Listeners, CloudFront, Route 53
# =============================================================================

resource "aws_lb_target_group" "tg" {
  name        = "tf-lb-tg"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
}

resource "aws_lb" "alb" {
  name                       = "lb-tf"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb_sg.id]
  subnets                    = [aws_subnet.public1.id, aws_subnet.public2.id]
  enable_deletion_protection  = false
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_lb_listener_rule" "sorry_page" {
  listener_arn = aws_lb_listener.https_listener.arn
  priority     = 100
  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/html"
      message_body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Access restricted</title></head><body><h1>Sorry you are not in a country authorized to access this web page</h1></body></html>"
      status_code  = "200"
    }
  }
  condition {
    path_pattern {
      values = ["/sorry.html"]
    }
  }
}

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = ""
  comment             = "NAS Financial - dynamic site (US)"
  price_class         = "PriceClass_100"
  origin {
    domain_name = aws_lb.alb.dns_name
    origin_id   = "alb"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    target_origin_id       = "alb"
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
    forwarded_values {
      query_string = true
      headers      = ["Host"]
      cookies { forward = "all" }
    }
  }
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US"]
    }
  }
  custom_error_response {
    error_code            = 403
    response_code        = 200
    response_page_path   = "/sorry.html"
    error_caching_min_ttl = 60
  }
  viewer_certificate {
    acm_certificate_arn            = length(var.cloudfront_aliases) > 0 ? var.certificate_arn : null
    ssl_support_method             = length(var.cloudfront_aliases) > 0 ? "sni-only" : null
    minimum_protocol_version       = length(var.cloudfront_aliases) > 0 ? "TLSv1.2_2021" : null
    cloudfront_default_certificate = length(var.cloudfront_aliases) == 0 ? true : null
  }
  aliases = var.cloudfront_aliases
  tags = { Name = "nas-financial-cf-main" }
}

resource "aws_route53_record" "www" {
  zone_id = var.zone_id
  name    = "www.fcjnwudo.com"
  type    = "A"
  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}

# =============================================================================
# MONITORING — Website-down alerts (2 systems)
# =============================================================================

resource "aws_sns_topic" "website_alerts" {
  name = "nas-financial-website-alerts"
}

resource "aws_sns_topic_subscription" "website_alerts_email" {
  count     = length(var.alert_email) > 0 ? 1 : 0
  topic_arn = aws_sns_topic.website_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "nas-financial-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Website ALB returning 5xx errors"
  alarm_actions       = [aws_sns_topic.website_alerts.arn]
  dimensions = { LoadBalancer = aws_lb.alb.arn_suffix }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "nas-financial-unhealthy-hosts"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Website has unhealthy target(s)"
  alarm_actions       = [aws_sns_topic.website_alerts.arn]
  dimensions = {
    LoadBalancer = aws_lb.alb.arn_suffix
    TargetGroup  = aws_lb_target_group.tg.arn_suffix
  }
}

# =============================================================================
# COMPUTE — Public web tier (ASG + Launch Template)
# =============================================================================

resource "aws_launch_template" "ec2_launchtemplate" {
  name_prefix   = "ec2-launchtemplate"
  image_id      = data.aws_ami.amazon_linux_latest.id
  instance_type = var.instance_type
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile { name = aws_iam_instance_profile.ec2_ssm.name }
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name      = "ASG-Web-Server"
      ManagedBy = "CloudSpace"
    }
  }
}

resource "aws_autoscaling_group" "asg" {
  name                = "asg-terraform"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  target_group_arns   = [aws_lb_target_group.tg.arn]
  vpc_zone_identifier = [aws_subnet.private1.id, aws_subnet.private2.id]
  launch_template {
    id      = aws_launch_template.ec2_launchtemplate.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "ASG-Instances"
    propagate_at_launch = true
  }
}

# =============================================================================
# INTRANET — Internal ALB + ASG (VPC-only, HTTP)
# =============================================================================

resource "aws_lb_target_group" "intranet_tg" {
  name        = "nas-intranet-tg"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
}

resource "aws_lb" "intranet_alb" {
  name               = "nas-intranet-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.intranet_alb_sg.id]
  subnets            = [aws_subnet.private1.id, aws_subnet.private2.id]
}

resource "aws_lb_listener" "intranet_http" {
  load_balancer_arn = aws_lb.intranet_alb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.intranet_tg.arn
  }
}

resource "aws_launch_template" "intranet" {
  name_prefix   = "nas-intranet-lt-"
  image_id      = data.aws_ami.amazon_linux_latest.id
  instance_type = var.instance_type
  vpc_security_group_ids = [aws_security_group.intranet_ec2_sg.id]
  tag_specifications {
    resource_type = "instance"
    tags = { Name = "NAS-Intranet-App" }
  }
}

resource "aws_autoscaling_group" "intranet" {
  name                = "nas-intranet-asg"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1
  target_group_arns   = [aws_lb_target_group.intranet_tg.arn]
  vpc_zone_identifier = [aws_subnet.private1.id, aws_subnet.private2.id]
  launch_template {
    id      = aws_launch_template.intranet.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "Intranet-App"
    propagate_at_launch = true
  }
}

# =============================================================================
# DATABASE — RDS MySQL (Multi-AZ, private)
# =============================================================================

resource "aws_db_subnet_group" "default" {
  name       = "nas-db-subnet-group"
  subnet_ids = [aws_subnet.private1.id, aws_subnet.private2.id]
  tags = { Name = "nas-db-subnet-group" }
}

resource "aws_db_instance" "default" {
  identifier              = "nas-financial-db"
  allocated_storage       = 10
  db_name                 = "mydb"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  username                = var.db_username
  password                = var.db_password
  db_subnet_group_name    = aws_db_subnet_group.default.name
  vpc_security_group_ids  = [aws_security_group.database_sg.id]
  publicly_accessible     = false
  multi_az                = true
  skip_final_snapshot     = true
  tags = { Backup = "nas-financial-dr" }
}

# =============================================================================
# SHARED STORAGE — EFS (web app)
# =============================================================================

resource "aws_efs_file_system" "main" {
  creation_token = "nas-financial-efs"
  encrypted      = true
  tags = {
    Name   = "nas-financial-efs"
    Backup = "nas-financial-dr"
  }
}

resource "aws_efs_mount_target" "private1" {
  file_system_id  = aws_efs_file_system.main.id
  subnet_id       = aws_subnet.private1.id
  security_groups = [aws_security_group.efs_sg.id]
}
resource "aws_efs_mount_target" "private2" {
  file_system_id  = aws_efs_file_system.main.id
  subnet_id       = aws_subnet.private2.id
  security_groups = [aws_security_group.efs_sg.id]
}

# =============================================================================
# STORAGE — Customer PII (S3, encrypted, lifecycle 30d → Glacier, 5y retention)
# =============================================================================

resource "aws_s3_bucket" "customer_pii" {
  bucket = "nas-financial-customer-pii-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "nas-financial-customer-pii" }
}

resource "aws_s3_bucket_versioning" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  rule {
    id     = "pii-30d-glacier-5y-retention"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
    expiration { days = 1825 }
  }
}

# =============================================================================
# DISASTER RECOVERY — AWS Backup (RDS + EFS → us-west-2)
# =============================================================================

resource "aws_backup_vault" "primary" {
  name = "nas-financial-primary-vault"
}

resource "aws_backup_vault" "dr" {
  provider = aws.dr
  name     = "nas-financial-dr-vault"
}

resource "aws_backup_plan" "dr" {
  name = "nas-financial-dr-plan"
  rule {
    rule_name         = "daily_backup_to_dr"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 5 * * ? *)"
    lifecycle { delete_after = 35 }
    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle { delete_after = 35 }
    }
  }
}

resource "aws_backup_selection" "dr" {
  name         = "nas-financial-rds-efs"
  plan_id      = aws_backup_plan.dr.id
  iam_role_arn = aws_iam_role.backup.arn
  resources = [
    "arn:aws:rds:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:db:${aws_db_instance.default.id}",
    aws_efs_file_system.main.arn
  ]
}
