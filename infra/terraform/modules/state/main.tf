# State: DynamoDB tables + the encrypted S3 bucket. PAY_PER_REQUEST keeps DynamoDB free-tier
# friendly. The audit table is append-only by convention (the control-plane role gets PutItem
# but not Update/Delete on it — enforced in the controlplane module's policy).

variable "name_prefix" {
  type    = string
  default = "mark1"
}

variable "kms_key_arn" {
  type        = string
  description = "Customer KMS key for bucket SSE. Empty => free SSE-S3 (AES256)."
  default     = ""
}

resource "aws_dynamodb_table" "runs" {
  name         = "${var.name_prefix}_runs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "run_id"
  attribute {
    name = "run_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "audit" {
  name         = "${var.name_prefix}_audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "run_id"
  attribute {
    name = "run_id"
    type = "S"
  }
}

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.name_prefix}-artifacts-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Default to free SSE-S3 (AES256); use the customer KMS key only when one is supplied.
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == "" ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn == "" ? null : var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "expire-runs"
    status = "Enabled"
    filter { prefix = "runs/" }
    expiration { days = 14 }
  }
}

output "runs_table" { value = aws_dynamodb_table.runs.name }
output "audit_table" { value = aws_dynamodb_table.audit.name }
output "bucket" { value = aws_s3_bucket.artifacts.bucket }
