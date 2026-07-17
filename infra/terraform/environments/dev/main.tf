# Dev environment: wires the modules into a single deployable stack.
# Review `terraform plan` before the first apply. Nothing here has been applied yet.

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
  description = "Email for budget alerts"
}

variable "sandbox_image" {
  type        = string
  description = "ECR image URI for the sandbox (from the registry module, after a push)"
  default     = "PLACEHOLDER-push-image-first"
}

variable "lambda_zip_path" {
  type    = string
  default = "../../../dist/controlplane.zip"
}

variable "enable_egress_endpoints" {
  type    = bool
  default = false
}

# KMS key used for bucket encryption and attestation signing.
resource "aws_kms_key" "mark1" {
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
  kms_key_arn = aws_kms_key.mark1.arn
}

module "execution" {
  source        = "../../modules/execution"
  sandbox_image = var.sandbox_image
}

module "controlplane" {
  source              = "../../modules/controlplane"
  lambda_zip_path     = var.lambda_zip_path
  runs_table_arn      = "arn:aws:dynamodb:${var.region}:*:table/${module.state.runs_table}"
  audit_table_arn     = "arn:aws:dynamodb:${var.region}:*:table/${module.state.audit_table}"
  bucket_arn          = "arn:aws:s3:::${module.state.bucket}"
  cluster_arn         = "arn:aws:ecs:${var.region}:*:cluster/${module.execution.cluster_name}"
  task_definition_arn = module.execution.task_definition_arn
  task_role_arn       = module.execution.empty_task_role_arn
  execution_role_arn  = module.execution.empty_task_role_arn
  kms_key_arn         = aws_kms_key.mark1.arn
}

module "guardrails" {
  source      = "../../modules/guardrails"
  alert_email = var.alert_email
}

output "api_endpoint" { value = module.controlplane.api_endpoint }
output "sandbox_repo_url" { value = module.registry.sandbox_repo_url }
output "private_subnet_id" { value = module.network.private_subnet_id }
output "empty_task_role_arn" { value = module.execution.empty_task_role_arn }
