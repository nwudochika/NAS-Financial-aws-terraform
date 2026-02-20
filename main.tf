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