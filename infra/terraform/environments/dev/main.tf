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
  default = "../../../dist/controlplane.zip"
}

variable "enable_egress_endpoints" {
  type    = bool
  default = false
}

# Customer KMS key (bucket SSE + attestation signing). ~$1/mo, so only when the control plane is on.
resource "aws_kms_key" "mark1" {
  count                   = var.enable_control_plane ? 1 : 0
  description             = "mark1 attestation + encryption"
  deletion_window_in_days = 7
  key_usage               = "ENCRYPT_DECRYPT"
}

module "network" {
  source                  = "../../modules/network"
  enable_egress_endpoints = var.enable_egress_endpoints
}

module "registry" {
  source = "../../modules/registry"
}

module "state" {
  source      = "../../modules/state"
  kms_key_arn = var.enable_control_plane ? aws_kms_key.mark1[0].arn : ""
}

module "execution" {
  source        = "../../modules/execution"
  sandbox_image = "${module.registry.sandbox_repo_url}:latest"
  proxy_image   = "${module.registry.proxy_repo_url}:latest"
}

module "controlplane" {
  count               = var.enable_control_plane ? 1 : 0
  source              = "../../modules/controlplane"
  lambda_zip_path     = var.lambda_zip_path
  runs_table_arn      = "arn:aws:dynamodb:${var.region}:*:table/${module.state.runs_table}"
  audit_table_arn     = "arn:aws:dynamodb:${var.region}:*:table/${module.state.audit_table}"
  bucket_arn          = "arn:aws:s3:::${module.state.bucket}"
  cluster_arn         = "arn:aws:ecs:${var.region}:*:cluster/${module.execution.cluster_name}"
  task_definition_arn = module.execution.task_definition_arn
  task_role_arn       = module.execution.empty_task_role_arn
  execution_role_arn  = module.execution.empty_task_role_arn
  kms_key_arn         = aws_kms_key.mark1[0].arn
}

module "guardrails" {
  count              = var.alert_email != "" ? 1 : 0
  source             = "../../modules/guardrails"
  alert_email        = var.alert_email
  monthly_budget_usd = var.monthly_budget_usd
}

output "api_endpoint" { value = try(module.controlplane[0].api_endpoint, null) }
output "sandbox_repo_url" { value = module.registry.sandbox_repo_url }
output "proxy_repo_url" { value = module.registry.proxy_repo_url }
output "cluster_name" { value = module.execution.cluster_name }
output "task_definition_arn" { value = module.execution.task_definition_arn }
output "private_subnet_id" { value = module.network.private_subnet_id }
output "deny_all_security_group_id" { value = module.network.deny_all_security_group_id }
output "empty_task_role_arn" { value = module.execution.empty_task_role_arn }
