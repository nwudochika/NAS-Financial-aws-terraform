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
