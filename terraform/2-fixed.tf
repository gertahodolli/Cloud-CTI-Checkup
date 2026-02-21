# =============================================================================
# CTI-Checkup Demo: FIXED AWS Resources
# =============================================================================
# Apply this AFTER 1-misconfigured.tf to remediate the security findings.
#
# Workflow:
#   1. Apply 1-misconfigured.tf (rename this file out first)
#   2. Run: cti-checkup cloud aws scan  → see findings
#   3. Rename 1-misconfigured.tf → 1-misconfigured.tf.bak
#   4. Ensure this file (2-fixed.tf) is the only config
#   5. terraform apply  → updates resources to secure config
#   6. Run: cti-checkup cloud aws scan  → findings resolved
#
# Fixes applied:
#   - CRITICAL: Removes all-ports-open security group
#   - HIGH: S3 block public access; EC2 SSH restricted; IAM admin/priv-esc users removed
#   - MEDIUM: S3 encryption; IAM NotAction user removed
#   - IAM: Adds least-privilege user (explicit actions/resources)
#   - LOW: S3 versioning, logging; unused security group removed
# =============================================================================

variable "project_prefix" {
  description = "Prefix for resource names (must match 1-misconfigured.tf)"
  type        = string
  default     = "cti-checkup-demo"
}

variable "region" {
  description = "AWS region for EC2 security group"
  type        = string
  default     = "us-east-1"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed for SSH (restrict instead of 0.0.0.0/0)"
  type        = string
  default     = "10.0.0.0/8"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  bucket_name = "${var.project_prefix}-${local.account_id}-misconfigured"
}

# -----------------------------------------------------------------------------
# S3 Bucket - FIXED configuration
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "demo" {
  bucket = local.bucket_name
}

# Block Public Access ENABLED - prevents public access
resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Default encryption - FIXES: default_encryption_not_configured
resource "aws_s3_bucket_server_side_encryption_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Versioning - FIXES: versioning_disabled
resource "aws_s3_bucket_versioning" "demo" {
  bucket = aws_s3_bucket.demo.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Logging bucket (target for access logs)
resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_prefix}-${local.account_id}-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Grant log delivery write permission (required for S3 access logging)
# Uses bucket policy (works with Bucket owner enforced; ACLs may be disabled)
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogDelivery"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/access-logs/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:s3:::${aws_s3_bucket.demo.id}"
          }
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

# Server access logging - FIXES: server_access_logging_disabled
resource "aws_s3_bucket_logging" "demo" {
  bucket = aws_s3_bucket.demo.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access-logs/"
}

# -----------------------------------------------------------------------------
# IAM - REMEDIATED: Least-privilege user (explicit Action + Resource, no wildcards)
# Replaces misconfigured users; passes all IAM checks
# -----------------------------------------------------------------------------

resource "aws_iam_user" "remediated" {
  name = "${var.project_prefix}-remediated-user"
}

resource "aws_iam_user_policy" "remediated" {
  name   = "least-privilege-s3-read"
  user   = aws_iam_user.remediated.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Sid      = "AllowS3ListAndRead"
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:GetObject"]
      Resource = [
        aws_s3_bucket.demo.arn,
        "${aws_s3_bucket.demo.arn}/*"
      ]
    }]
  })
}

# -----------------------------------------------------------------------------
# EC2 Security Group - FIXED (SSH restricted, not 0.0.0.0/0)
# -----------------------------------------------------------------------------

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "demo" {
  name        = "${var.project_prefix}-misconfigured-sg"
  description = "Demo security group - SSH restricted (REMEDIATED)"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_security_group_rule" "ssh_restricted" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.allowed_ssh_cidr]
  security_group_id = aws_security_group.demo.id
  description       = "SSH from allowed CIDR only"
}
