# Custom policy: Full Admin except Billing
resource "aws_iam_policy" "full_admin_no_billing" {
  name        = "FullAdminNoBilling"
  description = "Full administrator access excluding billing and cost management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAllExceptBilling"
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      },
      {
        Sid    = "DenyBilling"
        Effect = "Deny"
        Action = [
          "aws-portal:*",
          "budgets:*",
          "ce:*",
          "cur:*",
          "freetier:*",
          "purchase-orders:*",
          "tax:*",
          "payments:*",
          "consolidatedbilling:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# Custom policy: Full Admin to deployment region only (us-east-1)
resource "aws_iam_policy" "FullAdminDeployRegion" {
  name        = "FullAdminDeployRegion"
  description = "Full administrator access for deployment region"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAllInRegion"
        Effect = "Allow"
        Action = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "us-east-1" 
          }
        }
      }
    ]
  })
}

# IAM group
resource "aws_iam_group" "cloudspace_engineers" {
  name = "CloudSpace-Engineers"
}

resource "aws_iam_group" "nas_security_team" {
  name = "Nas_Financial_security"
}

resource "aws_iam_group" "Operations" {
  name = "Nas_Financial_Operations"
}

# Attach to IAM group
resource "aws_iam_group_policy_attachment" "cloudspace_engineers_admin" {
  group      = aws_iam_group.cloudspace_engineers.name
  policy_arn = aws_iam_policy.full_admin_no_billing.arn
}

resource "aws_iam_group_policy_attachment" "nas_security_team_admin" {
  group      = aws_iam_group.nas_security_team.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" 
}

resource "aws_iam_group_policy_attachment" "Operations_admin" {
  group      = aws_iam_group.Operations.name
  policy_arn = aws_iam_policy.FullAdminDeployRegion.arn
}


# VPC, subnets, route table, internet gateway

resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main"
  }
}

resource "aws_subnet" "public1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone = "us-east-1a"

  tags = {
    Name = "public1"
  }
}

resource "aws_subnet" "public2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone = "us-east-1b"

  tags = {
    Name = "public2"
  }
}

resource "aws_subnet" "private1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.3.0/24"
  availability_zone = "us-east-1c"

  tags = {
    Name = "private1"
  }
}

resource "aws_subnet" "private2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.4.0/24"
  availability_zone = "us-east-1d"

  tags = {
    Name = "private2"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main"
  }
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

# NAT Gateway (so private instances can reach internet for updates)
resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name = "nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public1.id
  tags = {
    Name = "main-nat"
  }
  depends_on = [aws_internet_gateway.igw]
}

# Private route table: send outbound traffic via NAT
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = {
    Name = "private-rt"
  }
}

resource "aws_route_table_association" "private1" {
  subnet_id      = aws_subnet.private1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.private2.id
  route_table_id = aws_route_table.private_rt.id
}

# ALB Security Group
resource "aws_security_group" "alb_sg" {
  vpc_id = aws_vpc.main.id
  name        = "alb-sg"
  description = "Security group for public ALB"

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Public allowed
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 security group
resource "aws_security_group" "ec2_sg" {
  vpc_id = aws_vpc.main.id
  name        = "ec2-sg"
  description = "Security group for webserver"

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

# ALB Target group
resource "aws_lb_target_group" "tg" {
  name        = "tf-lb-tg"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
}

# Load Balancer
resource "aws_lb" "alb" {
  name               = "lb-tf"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public1.id, aws_subnet.public2.id]
  enable_deletion_protection = false
}

# HTTPS Listener
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

# Serve sorry page for non-US (CloudFront fetches this when returning custom 403 response)
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

# Route 53: single A record for www → one CloudFront (geo + custom error handled inside CloudFront)
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


# S3 bucket: static "sorry" page for non-US visitors (GDPR)
resource "aws_s3_bucket" "sorry_page" {
  bucket = "nas-financial-sorry-page-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "nas-financial-sorry-page"
  }
}

resource "aws_s3_bucket_public_access_block" "sorry_page" {
  bucket = aws_s3_bucket.sorry_page.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Static HTML object: "Sorry you are not in a country authorized to access this web page"
resource "aws_s3_object" "sorry_index" {
  bucket       = aws_s3_bucket.sorry_page.id
  key          = "index.html"
  content_type = "text/html; charset=utf-8"
  content      = <<-EOT
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access restricted</title>
</head>
<body>
  <h1>Sorry you are not in a country authorized to access this web page</h1>
</body>
</html>
EOT
}

data "aws_caller_identity" "current" {}

# CloudFront Origin Access Control (OAC) for S3
resource "aws_cloudfront_origin_access_control" "s3_oac" {
  name                              = "nas-financial-s3-oac"
  description                       = "OAC for S3 sorry page bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront distribution (main): ALB only — for US (Route 53 geolocation)
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
      cookies {
        forward = "all"
      }
    }
  }

  # US only; non-US get 403 → custom error shows sorry page from origin /sorry.html
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
    acm_certificate_arn      = length(var.cloudfront_aliases) > 0 ? var.certificate_arn : null
    ssl_support_method       = length(var.cloudfront_aliases) > 0 ? "sni-only" : null
    minimum_protocol_version = length(var.cloudfront_aliases) > 0 ? "TLSv1.2_2021" : null
    cloudfront_default_certificate = length(var.cloudfront_aliases) == 0 ? true : null
  }

  aliases = var.cloudfront_aliases

  tags = {
    Name = "nas-financial-cf-main"
  }
}

# Data Source AMI
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

# Launch Template
resource "aws_launch_template" "ec2_launchtemplate" {
  name_prefix   = "ec2-launchtemplate"
  image_id      = data.aws_ami.amazon_linux_latest.id
  instance_type = var.instance_type
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ASG-Web-Server"
    }
  }
}

# Autoscaling Group
resource "aws_autoscaling_group" "asg" {
  name               = "asg-terraform"
  max_size           = 2
  min_size           = 1
  desired_capacity   = 1
  target_group_arns = [aws_lb_target_group.tg.arn]


  vpc_zone_identifier = [
    aws_subnet.private1.id,
    aws_subnet.private2.id
  ]

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

# Database subnet group
resource "aws_db_subnet_group" "default" {
  name       = "nas-db-subnet-group"
  subnet_ids = [aws_subnet.private1.id, aws_subnet.private2.id]

  tags = {
    Name = "nas-db-subnet-group"
  }
}

# Data Base security_groups
resource "aws_security_group" "database_sg" {
  name        = "database-access-sg"
  description = "Allow database access only from instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "DatabaseAccessSG"
  }
}

# EFS security group: allow web servers to mount via NFS (port 2049)
resource "aws_security_group" "efs_sg" {
  name        = "efs-access-sg"
  description = "Allow NFS access from web servers"
  vpc_id      = aws_vpc.main.id

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

  tags = {
    Name = "EFSAccessSG"
  }
}

# EFS file system for shared storage (e.g. web app uploads)
resource "aws_efs_file_system" "main" {
  creation_token = "nas-financial-efs"
  encrypted      = true

  tags = {
    Name = "nas-financial-efs"
  }
}

# EFS mount target in private subnet 1 (us-east-1c)
resource "aws_efs_mount_target" "private1" {
  file_system_id  = aws_efs_file_system.main.id
  subnet_id       = aws_subnet.private1.id
  security_groups = [aws_security_group.efs_sg.id]
}

# EFS mount target in private subnet 2 (us-east-1d)
resource "aws_efs_mount_target" "private2" {
  file_system_id  = aws_efs_file_system.main.id
  subnet_id       = aws_subnet.private2.id
  security_groups = [aws_security_group.efs_sg.id]
}


resource "aws_db_instance" "default" {
  identifier            = "nas-financial-db"
  allocated_storage     = 10
  db_name              = "mydb"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  username             = var.db_username
  # manage_master_user_password = true
  password             = var.db_password
  db_subnet_group_name = aws_db_subnet_group.default.name
  vpc_security_group_ids = [aws_security_group.database_sg.id]
  publicly_accessible   = false
  multi_az             = true
  skip_final_snapshot  = true
  # enable_deletion_protection = true
}