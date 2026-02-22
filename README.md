# NAS Financial Group – AWS Platform

Terraform-managed AWS infrastructure for NAS Financial Group: public web application, internal intranet, database and storage, access control, monitoring, and disaster recovery.

**Region:** Primary `us-east-1`; DR backups in `us-west-2`.

---

## What This Repo Does

- **Public website** – HTTPS, highly available, behind CloudFront with geographic access rules and a static “access restricted” page for non‑US visitors.
- **Intranet app** – Internal-only HTTP application in the VPC (e.g. for VPN users).
- **Compute** – Auto Scaling web tier and intranet tier in private subnets; outbound via NAT.
- **Data** – Multi-AZ RDS (MySQL), EFS for shared app storage, S3 for customer PII with encryption and lifecycle (30-day hot, then archive, 5-year retention).
- **Access control** – IAM groups for CloudSpace Engineers (admin, no billing), NAS Security (full admin), NAS Operations (us-east-1 only). Web server management restricted to CloudSpace via SSM Session Manager.
- **Monitoring** – Two CloudWatch alarms (ALB 5xx, unhealthy targets) with SNS for notifications.
- **Disaster recovery** – AWS Backup for RDS and EFS with daily backups and cross-region copy to `us-west-2`.
- **Auditing** – Optional cross-account IAM role for N2G Auditing with Trusted Advisor–only access.

---

## Architecture (High Level)

```
                    Internet
                        │
                        ▼
              ┌─────────────────┐
              │   CloudFront    │  HTTPS, geo (US → app; others → sorry page)
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐     ┌─────────────────┐
              │  Public ALB     │     │  Intranet ALB    │  HTTP, VPC-only
              │  (HTTPS)        │     │  (internal)      │
              └────────┬────────┘     └────────┬────────┘
                       │                       │
         ┌─────────────┼─────────────┐        │
         ▼             ▼             ▼        ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ Web ASG  │  │ Web ASG  │  │ Intranet │  │ Intranet │
   │ (priv)   │  │ (priv)   │  │   ASG    │  │   ASG    │
   └────┬─────┘  └────┬─────┘  └──────────┘  └──────────┘
        │             │
        └──────┬──────┘
               │
        ┌──────┴──────┐
        ▼             ▼
   ┌─────────┐   ┌─────────┐   ┌─────────────┐
   │   RDS   │   │   EFS   │   │ S3 (PII)    │
   │ Multi-AZ│   │ (shared)│   │ encrypt+lifecycle
   └─────────┘   └─────────┘   └─────────────┘
```

| Layer        | Components |
|-------------|------------|
| Edge        | CloudFront (custom domain, TLS), Route 53 A record |
| Public web  | ALB (HTTPS), ASG in private subnets, EFS mount targets |
| Intranet    | Internal ALB (HTTP), ASG in private subnets |
| Data        | RDS MySQL (private), EFS (private), S3 PII bucket |
| DR          | AWS Backup → primary vault (us-east-1) and DR vault (us-west-2) |
| Management  | SSM Session Manager (VPC endpoints), no SSH to web tier |

---

## Access Control (IAM)

| Group                     | Scope |
|---------------------------|--------|
| CloudSpace-Engineers      | Full admin **except** billing; only group that can use SSM to manage web servers |
| Nas_Financial_security    | Full admin including billing |
| Nas_Financial_Operations | Full admin **only in us-east-1** |

Web servers are tagged and IAM is configured so only CloudSpace Engineers can start SSM sessions or run commands on them.

---

## Prerequisites

- [Terraform](https://www.terraform.io/downloads) (1.x)
- AWS CLI/credentials with permissions to create the resources in this repo
- **ACM certificate** in `us-east-1` for the public ALB/CloudFront
- **Route 53 hosted zone** for the public domain

---

## Usage

1. **Clone and enter the repo**
   ```bash
   git clone <repo-url>
   cd NAS-Financial-aws-terraform
   ```

2. **Create `terraform.tfvars`** (do not commit; it is in `.gitignore`):
   ```hcl
   instance_type   = "t2.micro"
   certificate_arn = "arn:aws:acm:us-east-1:ACCOUNT_ID:certificate/CERT_ID"
   zone_id         = "Z0XXXXXXXXXXXX"
   db_username     = "admin"
   db_password     = "YOUR_SECURE_PASSWORD"

   # Optional
   alert_email           = "ops@example.com"   # SNS alerts; confirm via email after apply
   cloudfront_aliases    = ["www.yourdomain.com"]
   n2g_auditing_account_id = "123456789012"    # N2G AWS account for Trusted Advisor role
   ```

3. **Apply**
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

4. **After apply**
   - If you set `alert_email`, confirm the SNS subscription from the inbox.
   - Use `terraform output` for endpoints, bucket names, and role ARNs.

---

## Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `instance_type` | EC2 type for web and intranet tiers | No (default `t2.micro`) |
| `certificate_arn` | ACM certificate ARN for HTTPS | Yes |
| `zone_id` | Route 53 hosted zone ID | Yes |
| `db_username` | RDS master username | Yes |
| `db_password` | RDS master password | Yes (sensitive) |
| `cloudfront_aliases` | Custom domain(s) for CloudFront | No (default `["www.fcjnwudo.com"]`) |
| `alert_email` | Email for website-down SNS alerts | No |
| `n2g_auditing_account_id` | N2G AWS account ID for Trusted Advisor role | No |

---

## Outputs

| Output | Description |
|--------|-------------|
| `rds_endpoint` / `rds_address` | RDS connection details for app config |
| `efs_id` / `efs_dns_name` | EFS mount details for web servers |
| `backup_plan_id` / `dr_vault_arn` | DR backup plan and us-west-2 vault |
| `website_alerts_sns_topic_arn` | SNS topic for website alarms |
| `intranet_alb_dns_name` | Internal ALB hostname (HTTP, VPC-only) |
| `n2g_trusted_advisor_role_arn` | Role for N2G to assume (Trusted Advisor only) |
| `customer_pii_bucket` | S3 bucket for PII (encrypted, lifecycle) |

---

## Project Structure

```
NAS-Financial-aws-terraform/
├── main.tf        # IAM, VPC, ALB, ASG, RDS, EFS, S3, CloudFront, Route53, backup, monitoring, intranet, N2G role
├── variables.tf   # Variable definitions
├── output.tf      # Outputs
├── providers.tf   # AWS us-east-1 + us-west-2 (DR)
├── .gitignore     # .tfvars, .tfstate, .terraform
└── README.md
```

---

## Security and Operations

- **Secrets** – Keep `terraform.tfvars` out of version control; use it for `db_password` and other sensitive values.
- **Web tier** – No SSH; use SSM Session Manager (only CloudSpace Engineers have access to web server instances).
- **Data** – RDS and EFS are in private subnets; S3 PII bucket is encrypted (AES-256) and not public.
- **Intranet** – Reachable only from within the VPC (e.g. VPN or private link); no public DNS or internet exposure.
