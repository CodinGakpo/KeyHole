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
| `state`      | DynamoDB `keyhole_runs` + append-only `keyhole_audit`; S3 bucket (SSE-S3, block-public, lifecycle expiry). |
| `registry`   | ECR repos for the sandbox and egress-proxy images (scan-on-push). |
| `execution`  | ECS cluster, sandbox task definition (empty task role), the three IAM roles. |
| `controlplane` | Lambda + API Gateway HTTP API + its scoped role. |
| `guardrails` | AWS Budgets alarm + quota parameters. |

## Usage

Applied and verified end to end on a real account (38 resources with the control plane on), then
destroyed. From the repo root:

```bash
infra/terraform/environments/dev/stack.sh up     # Lambda zip, terraform apply, push sandbox image,
                                                 # export KMS public key to /tmp/kms.pem
infra/terraform/environments/dev/stack.sh down   # terraform destroy
infra/terraform/environments/dev/tf.sh plan      # any other terraform command, same credentials
```

Both scripts read `AWS_ACCESS_KEY` / `AWS_SECRET_KEY` from the repo-root `.env` (parsed, never
sourced) and ignore `AWS_PROFILE`. State is local (`environments/dev/terraform.tfstate`,
gitignored). Cloud runs need `enable_egress_endpoints = true` (in `terraform.tfvars`) so Fargate can
pull the image and write logs — about $0.03/hour while up. The KMS key (~$1/month) is scheduled for
deletion on destroy, with AWS's minimum 7-day wait.
