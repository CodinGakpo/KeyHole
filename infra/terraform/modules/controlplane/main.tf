# Control plane: a Lambda behind an API Gateway HTTP API. Scales to zero (~$0 idle) and is fully
# Terraform-expressible. Its role is tightly scoped: launch tasks, pass ONLY the task/exec roles,
# read/write the two tables and the bucket, and use KMS for signing + encryption. The audit table
# is granted PutItem but not Update/Delete (append-only).

variable "name_prefix" {
  type    = string
  default = "keyhole"
}
variable "region" { type = string }
variable "lambda_zip_path" { type = string }
variable "runs_table" { type = string }
variable "audit_table" { type = string }
variable "runs_table_arn" { type = string }
variable "audit_table_arn" { type = string }
variable "bucket" { type = string }
variable "bucket_arn" { type = string }
variable "cluster_arn" { type = string }
variable "cluster_name" { type = string }
variable "task_definition_arn" { type = string }
variable "task_role_arn" { type = string }
variable "execution_role_arn" { type = string }
variable "subnet_id" { type = string }
variable "security_group_id" { type = string }
variable "kms_key_arn" { type = string }

resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-controlplane"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "controlplane"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "*" },
      { Sid = "RunTask", Effect = "Allow", Action = ["ecs:RunTask", "ecs:StopTask", "ecs:DescribeTasks", "ecs:TagResource"], Resource = [var.task_definition_arn, "${var.cluster_arn}/*", "arn:aws:ecs:${var.region}:*:task/${var.cluster_name}/*"] },
      { Sid = "PassOnlyTaskRoles", Effect = "Allow", Action = "iam:PassRole", Resource = [var.task_role_arn, var.execution_role_arn] },
      { Sid = "Runs", Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:Query"], Resource = var.runs_table_arn },
      { Sid = "AuditAppendOnly", Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"], Resource = var.audit_table_arn },
      { Sid = "Artifacts", Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"], Resource = "${var.bucket_arn}/*" },
      # Signing only — the key is a SIGN_VERIFY key; no encrypt/decrypt is needed (bucket is SSE-S3).
      { Sid = "Kms", Effect = "Allow", Action = ["kms:Sign", "kms:GetPublicKey"], Resource = var.kms_key_arn },
    ]
  })
}

resource "aws_lambda_function" "api" {
  function_name    = "${var.name_prefix}-api"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "keyhole.controlplane.app.lambda_handler"
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      KEYHOLE_CLUSTER     = var.cluster_name
      KEYHOLE_TASK_DEF    = var.task_definition_arn
      KEYHOLE_SUBNET      = var.subnet_id
      KEYHOLE_SG          = var.security_group_id
      KEYHOLE_BUCKET      = var.bucket
      KEYHOLE_RUNS_TABLE  = var.runs_table
      KEYHOLE_AUDIT_TABLE = var.audit_table
      KEYHOLE_KMS_KEY_ID  = var.kms_key_arn
    }
  }
}

resource "aws_apigatewayv2_api" "http" {
  name          = "${var.name_prefix}-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

output "api_endpoint" { value = aws_apigatewayv2_stage.default.invoke_url }
