# =============================================================================
# DATA SOURCES (used throughout)
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# AMI for EC2: set var.ec2_ami_id (default AL2023 in us-east — no ec2:DescribeImages at plan time)
