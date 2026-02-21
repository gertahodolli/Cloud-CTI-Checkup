# =============================================================================
# CTI-Checkup Demo: MISCONFIGURED AWS Resources
# =============================================================================
# Apply this to create resources that will trigger security findings when you
# run: cti-checkup cloud aws scan
#
# Expected findings by severity:
#   CRITICAL: EC2 security_group_all_ports_open_to_world (all ports 0.0.0.0/0)
#   HIGH:     S3 public_access_enabled, EC2 security_group_sensitive_port_open,
#             IAM admin_policy_wildcards_detected, policy_privilege_escalation_action
#   MEDIUM:   S3 default_encryption_not_configured,
#             IAM policy_allow_not_action (user with NotAction policy)
#   LOW:      S3 versioning_disabled, S3 server_access_logging_disabled,
#             EC2 security_group_unused
# =============================================================================

variable "project_prefix" {
  description = "Prefix for resource names (must be globally unique for S3)"
  type        = string
  default     = "cti-checkup-demo"
}

variable "region" {
  description = "AWS region for EC2 security group"
  type        = string
  default     = "us-east-1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # S3 bucket names must be globally unique
  bucket_name = "${var.project_prefix}-${local.account_id}-misconfigured"
}

# -----------------------------------------------------------------------------
# S3 Bucket - MISCONFIGURED (triggers multiple findings)
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "demo" {
  bucket = local.bucket_name
}

# Block Public Access DISABLED - must be applied BEFORE the public policy
resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls     = false
  restrict_public_buckets = false
}

# Public bucket policy - TRIGGERS: public_access_enabled
# (depends on public_access_block so block settings are applied first)
resource "aws_s3_bucket_policy" "demo" {
  bucket = aws_s3_bucket.demo.id

  depends_on = [aws_s3_bucket_public_access_block.demo]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.demo.arn}/*"
      }
    ]
  })
}

# NO default encryption - TRIGGERS: default_encryption_not_configured
# (omit aws_s3_bucket_server_side_encryption_configuration)

# NO versioning - TRIGGERS: versioning_disabled
# (omit aws_s3_bucket_versioning)

# NO server access logging - TRIGGERS: server_access_logging_disabled
# (omit aws_s3_bucket_logging)

data "aws_vpc" "default" {
  default = true
}

# -----------------------------------------------------------------------------
# CRITICAL: EC2 Security Group - ALL ports open to 0.0.0.0/0
# TRIGGERS: security_group_all_ports_open_to_world
# -----------------------------------------------------------------------------

resource "aws_security_group" "critical" {
  name        = "${var.project_prefix}-critical-all-ports-open"
  description = "DEMO: All ports open to world - CRITICAL severity"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_security_group_rule" "all_ports_open" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.critical.id
  description       = "All protocols from anywhere - CRITICAL for demo"
}

# -----------------------------------------------------------------------------
# HIGH: EC2 Security Group - SSH (sensitive port) open to 0.0.0.0/0
# TRIGGERS: security_group_sensitive_port_open_to_world
# -----------------------------------------------------------------------------

resource "aws_security_group" "demo" {
  name        = "${var.project_prefix}-misconfigured-sg"
  description = "Demo security group - SSH open to world (INTENTIONALLY INSECURE)"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_security_group_rule" "ssh_open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.demo.id
  description       = "SSH from anywhere - INSECURE for demo"
}

# -----------------------------------------------------------------------------
# HIGH: IAM User with admin-equivalent inline policy (Action * Resource *)
# TRIGGERS: admin_policy_wildcards_detected
# -----------------------------------------------------------------------------

resource "aws_iam_user" "admin_demo" {
  name = "${var.project_prefix}-admin-user"
}

resource "aws_iam_user_policy" "admin_demo" {
  name   = "admin-wildcard-policy"
  user   = aws_iam_user.admin_demo.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# HIGH: IAM User with privilege-escalation action in policy
# TRIGGERS: policy_privilege_escalation_action
# -----------------------------------------------------------------------------

resource "aws_iam_user" "priv_esc_demo" {
  name = "${var.project_prefix}-priv-esc-user"
}

resource "aws_iam_user_policy" "priv_esc_demo" {
  name   = "privilege-escalation-policy"
  user   = aws_iam_user.priv_esc_demo.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PutUserPolicy", "iam:AttachUserPolicy"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# MEDIUM: IAM User with NotAction (risky policy pattern)
# TRIGGERS: policy_allow_not_action
# -----------------------------------------------------------------------------

resource "aws_iam_user" "notaction_demo" {
  name = "${var.project_prefix}-notaction-user"
}

resource "aws_iam_user_policy" "notaction_demo" {
  name   = "notaction-risky-policy"
  user   = aws_iam_user.notaction_demo.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      NotAction = ["iam:DeleteUser"]
      Resource  = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# LOW: Unused security group (no ENIs attached, not attached to any instance)
# TRIGGERS: security_group_unused
# -----------------------------------------------------------------------------

resource "aws_security_group" "unused" {
  name        = "${var.project_prefix}-unused-sg"
  description = "DEMO: Unused security group - LOW severity"
  vpc_id      = data.aws_vpc.default.id
}
