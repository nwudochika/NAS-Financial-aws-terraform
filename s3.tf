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
