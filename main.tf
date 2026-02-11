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

