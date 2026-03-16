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
