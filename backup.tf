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
    # Use computed ARN — last segment must be DB *identifier* (e.g. nas-financial-db), not aws_db_instance.id (db-… resource id).
    aws_db_instance.default.arn,
    aws_efs_file_system.main.arn
  ]
}
