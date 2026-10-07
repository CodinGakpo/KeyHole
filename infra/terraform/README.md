# Keyhole Infrastructure (Terraform)

One `terraform apply` stands up the whole confidential-execution platform in your own AWS account.

> **Cost posture:** designed for < ~$10/month, and ~$0 when idle. There is **no NAT gateway**
> (that alone would be ~$32/month). Default runs have no network egress; the only paid always-on
> pieces are optional VPC interface endpoints, which are **opt-in** via `enable_egress_endpoints`.
> Start with the free tier: DynamoDB (PAY_PER_REQUEST), S3, Lambda, and Fargate per-second billing
> are all free-tier friendly for light testing.

## Modules

| Module | What it provisions |
|---|---|
| `network`    | VPC, private subnet (no NAT), deny-all security group, S3 gateway endpoint, optional ECR/Logs interface endpoints. |
| `state`      | DynamoDB `keyhole_runs` + append-only `keyhole_audit`; S3 bucket (SSE-KMS, block-public, lifecycle expiry). |
| `registry`   | ECR repos for the sandbox and egress-proxy images (scan-on-push). |
| `execution`  | ECS cluster, sandbox task definition (empty task role), the three IAM roles. |
| `controlplane` | Lambda + API Gateway HTTP API + its scoped role. |
| `guardrails` | AWS Budgets alarm + quota parameters. |

## Usage (when ready — not yet applied)

```bash
cd environments/dev
terraform init
terraform plan     # review every resource before creating anything
terraform apply
# ... use it ...
terraform destroy  # tear down; re-apply on any account to rebuild
```

Nothing here has been applied yet. Review `terraform plan` output before the first apply so you
see exactly what will be created and can confirm it stays within the free tier.
