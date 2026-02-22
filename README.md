# NAS Financial Group – AWS Terraform

**Status: Work in progress**

Infrastructure as Code (Terraform) for the NAS Financial Group AWS environment. This repository provisions IAM access control, a highly available web tier with private subnets, Multi-AZ RDS, and core networking.

---

## Overview

Terraform manages the following in **us-east-1**:

- **IAM** – Groups and policies for CloudSpace Engineers, NAS Security, and NAS Operations
- **Networking** – VPC, public/private subnets, Internet Gateway, NAT Gateway
- **Web tier** – Application Load Balancer (HTTPS), Auto Scaling Group with web servers in **private subnets**
- **Database** – RDS MySQL, Multi-AZ, in private subnets (accessible only by web servers)
- **DNS** – Route53 A record (alias to ALB)

---

## Architecture (high level)

```
Internet → ALB (public subnets, HTTPS)
              → Web servers (private subnets, ASG)
                   → RDS MySQL (private subnets, Multi-AZ)
Outbound: Web servers → NAT Gateway → Internet
```

| Component      | Subnets   | Notes                          |
|----------------|-----------|--------------------------------|
| ALB            | public1, public2 | HTTPS, forwards to target group |
| Web servers    | private1, private2 | No public IP; outbound via NAT  |
| RDS            | private1, private2 | Multi-AZ; only web SG can connect |

---

## IAM groups

| Group                    | Access |
|--------------------------|--------|
| CloudSpace-Engineers     | Full admin **except** billing |
| Nas_Financial_security   | Full admin **including** billing |
| Nas_Financial_Operations | Full admin **only in us-east-1** |

---

## Prerequisites

- [Terraform](https://www.terraform.io/downloads) (e.g. 1.x)
- AWS CLI configured with credentials that can create the resources above
- An **ACM certificate** (us-east-1) for the ALB HTTPS listener
- A **Route53 hosted zone** for the domain

---

## Usage

1. **Clone the repository**
   ```bash
   git clone https://github.com/nwudochika/NAS-Financial-aws-terraform.git
   cd NAS-Financial-aws-terraform
   ```

2. **Create a `terraform.tfvars`** (do not commit; it is in `.gitignore`):
   ```hcl
   instance_type   = "t2.micro"
   certificate_arn = "arn:aws:acm:us-east-1:ACCOUNT_ID:certificate/CERT_ID"
   zone_id         = "YOUR_ROUTE53_ZONE_ID"
   db_username     = "admin"
   db_password     = "YOUR_SECURE_PASSWORD"
   ```

3. **Initialize and apply**
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

---

## Variables

| Variable         | Description                    | Example / note      |
|------------------|--------------------------------|---------------------|
| `instance_type`  | EC2 instance type for web tier | `t2.micro` (default) |
| `certificate_arn`| ACM certificate ARN (HTTPS)    | Required            |
| `zone_id`        | Route53 hosted zone ID         | Required            |
| `db_username`    | RDS master username            | Required            |
| `db_password`    | RDS master password            | Required, sensitive |

---

## Project structure

```
NAS-Financial-aws-terraform/
├── main.tf        # IAM, VPC, ALB, ASG, RDS, Route53, security groups
├── variables.tf   # Variable definitions
├── providers.tf   # AWS provider (us-east-1)
├── output.tf      # Outputs (if any)
├── .gitignore     # Excludes .tfvars, .tfstate, .terraform
└── README.md      # This file
```

---

## Security notes

- **terraform.tfvars** is in `.gitignore`; use it for secrets and do not commit it.
- RDS is in private subnets and only accepts traffic from the web server security group.
- Web servers have no public IP; they use a NAT Gateway for outbound internet.

---


