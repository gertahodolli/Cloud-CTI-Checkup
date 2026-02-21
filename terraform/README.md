# CTI-Checkup Terraform Demo

Terraform configurations to demonstrate **CTI-Checkup** security scanning. Deploy misconfigured AWS resources, run the scan to see findings, then apply fixes and scan again.

## Prerequisites

- [Terraform](https://www.terraform.io/downloads) >= 1.0
- AWS credentials configured (`aws configure` or env vars)
- [CTI-Checkup](../../README.md) CLI installed  
- Ensure the Terraform `region` (default `us-east-1`) is in your CTI-Checkup `config/ready.yaml` under `aws.regions`, or the EC2 findings will not be detected

### S3 Block Public Access (for misconfigured demo)

To create the intentionally public S3 bucket, **account-level** Block Public Access must allow it. If `terraform apply` fails with `public policies are prevented by the BlockPublicPolicy setting`:

1. Open **AWS Console** → **S3** → **Block Public Access settings for this account**
2. Click **Edit** and uncheck **"Block public access to buckets and objects granted through new public bucket or access point policies"** (and optionally the ACL option if you use ACL-based public access)
3. Save changes

This is temporary for the demo; re-enable after you run the fixed config.

## Demo Workflow

### Step 1: Deploy misconfigured resources

```bash
cd terraform

# Temporarily hide the fixed config so Terraform only sees misconfigured
mv 2-fixed.tf 2-fixed.tf.bak

terraform init
terraform apply -auto-approve
```

This creates:

- **S3 bucket** with public read policy, no encryption, no versioning, no logging
- **EC2 security group** with SSH (port 22) open to `0.0.0.0/0`

### Step 2: Run CTI-Checkup scan (see findings)

```bash
cti-checkup cloud aws scan --config config/ready.yaml --output json
# Or start the web UI and run a scan from there
```

Expected findings (at least one per severity):

| Severity  | Issue                                  | Resource                |
|-----------|----------------------------------------|-------------------------|
| Critical  | `security_group_all_ports_open_to_world` | EC2 security group    |
| High      | `public_access_enabled`                | S3 bucket               |
| High      | `security_group_sensitive_port_open_to_world` | EC2 security group |
| High      | `admin_policy_wildcards_detected`       | IAM user + policy       |
| High      | `policy_privilege_escalation_action`    | IAM user + policy       |
| Medium    | `default_encryption_not_configured`     | S3 bucket               |
| Medium    | `policy_allow_not_action`               | IAM user + policy       |
| Low       | `versioning_disabled`                   | S3 bucket               |
| Low       | `server_access_logging_disabled`        | S3 bucket               |
| Low       | `security_group_unused`                 | EC2 security group      |

### Step 3: Apply fixes

```bash
# Switch to fixed config (Terraform will update existing resources)
mv 1-misconfigured.tf 1-misconfigured.tf.bak
mv 2-fixed.tf.bak 2-fixed.tf

terraform apply -auto-approve
```

### Step 4: Run scan again (findings resolved)

```bash
cti-checkup cloud aws scan --config config/ready.yaml
```

The same resources should now pass; findings for the demo bucket and security group should be gone.

### Cleanup

```bash
# Ensure 2-fixed.tf is active (has all resources), then destroy
terraform destroy -auto-approve

# Restore both configs for next demo
mv 1-misconfigured.tf.bak 1-misconfigured.tf
# (2-fixed.tf is already in place)
```

## Files

| File              | Purpose                                                      |
|-------------------|--------------------------------------------------------------|
| `1-misconfigured.tf` | AWS resources with security issues (for “before” scan)   |
| `2-fixed.tf`      | Remediated configuration (for “after” scan)                  |
| `versions.tf`     | Terraform and provider requirements                          |

**Note:** Terraform loads all .tf files. Keep only one of `1-misconfigured.tf` or `2-fixed.tf` active when applying Rename the other to .bak to switch between “before” and “after” states.

## Customization

- `project_prefix` (default: `cti-checkup-demo`) – prefix for resource names
- `region` (default: `us-east-1`) – AWS region for EC2
- `allowed_ssh_cidr` (in 2-fixed.tf only) – CIDR allowed for SSH after remediation (default: `10.0.0.0/8`)
