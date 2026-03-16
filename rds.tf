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
