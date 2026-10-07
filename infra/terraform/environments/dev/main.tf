# Dev environment: wires the modules into a single deployable stack.
# Default apply = the free ($0-idle) data plane. The customer KMS key and the Lambda + API Gateway
# control plane are opt-in via enable_control_plane; the budget alarm is opt-in via alert_email.
# Review `terraform plan` before the first apply.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "alert_email" {
  type        = string
  description = "Email for budget alerts. Empty => no budget alarm created."
  default     = ""
}

variable "monthly_budget_usd" {
  type        = number
  description = "Monthly cost budget; alerts fire at 50/80/100% (actual) + 100% (forecasted)."
  default     = 5
}

variable "enable_control_plane" {
  type        = bool
  description = "Create the KMS key + Lambda/API Gateway control plane (M5). Off => free data plane only."
  default     = false
}

variable "lambda_zip_path" {
  type    = string
  default = "../../../../dist/controlplane.zip"
}

variable "enable_egress_endpoints" {
  type    = bool
  default = false
}

# Customer KMS key for attestation SIGNING only (the private key never leaves KMS). ~$1/mo, so
# only when the control plane is on. The bucket uses free SSE-S3, so KMS is not needed for encryption.
resource "aws_kms_key" "keyhole" {
  count                    = var.enable_control_plane ? 1 : 0
  description              = "keyhole attestation signing (ECDSA P-256)"
  deletion_window_in_days  = 7
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
}

module "network" {
  source                  = "../../modules/network"
  enable_egress_endpoints = var.enable_egress_endpoints
}

module "registry" {
  source = "../../modules/registry"
}

module "state" {
  source = "../../modules/state"
  # Bucket stays on free SSE-S3; the KMS key is a signing key, not an encryption key.
  kms_key_arn = ""
}

module "execution" {
  source        = "../../modules/execution"
  sandbox_image = "${module.registry.sandbox_repo_url}:latest"
}

module "controlplane" {
  count               = var.enable_control_plane ? 1 : 0
  source              = "../../modules/controlplane"
  region              = var.region
  lambda_zip_path     = var.lambda_zip_path
  runs_table          = module.state.runs_table
  audit_table         = module.state.audit_table
  runs_table_arn      = "arn:aws:dynamodb:${var.region}:*:table/${module.state.runs_table}"
  audit_table_arn     = "arn:aws:dynamodb:${var.region}:*:table/${module.state.audit_table}"
  bucket              = module.state.bucket
  bucket_arn          = "arn:aws:s3:::${module.state.bucket}"
  cluster_arn         = "arn:aws:ecs:${var.region}:*:cluster/${module.execution.cluster_name}"
  cluster_name        = module.execution.cluster_name
  task_definition_arn = module.execution.task_definition_arn
  task_role_arn       = module.execution.empty_task_role_arn
  execution_role_arn  = module.execution.execution_role_arn
  subnet_id           = module.network.private_subnet_id
  security_group_id   = module.network.run_security_group_id
  kms_key_arn         = aws_kms_key.keyhole[0].arn
}

module "guardrails" {
  count              = var.alert_email != "" ? 1 : 0
  source             = "../../modules/guardrails"
  alert_email        = var.alert_email
  monthly_budget_usd = var.monthly_budget_usd
}

output "api_endpoint" { value = try(module.controlplane[0].api_endpoint, null) }
output "kms_key_id" { value = try(aws_kms_key.keyhole[0].key_id, null) }
output "sandbox_repo_url" { value = module.registry.sandbox_repo_url }
output "proxy_repo_url" { value = module.registry.proxy_repo_url }
output "cluster_name" { value = module.execution.cluster_name }
output "task_definition_arn" { value = module.execution.task_definition_arn }
output "private_subnet_id" { value = module.network.private_subnet_id }
output "deny_all_security_group_id" { value = module.network.deny_all_security_group_id }
output "run_security_group_id" { value = module.network.run_security_group_id }
output "bucket" { value = module.state.bucket }
output "empty_task_role_arn" { value = module.execution.empty_task_role_arn }
