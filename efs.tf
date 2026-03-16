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
