# Execution: the ECS cluster, the sandbox task definition, and the THREE IAM roles.
# The single most important line here is the sandbox task role: it is EMPTY. Even if untrusted
# code reaches the task-metadata endpoint, the credentials it vends can do nothing.

variable "name_prefix" {
  type    = string
  default = "mark1"
}

variable "sandbox_image" {
  type        = string
  description = "ECR image URI for the sandbox container"
}

variable "proxy_image" {
  type        = string
  description = "ECR image URI for the egress-proxy sidecar container"
}

variable "log_group_name" {
  type    = string
  default = "/mark1/sandbox"
}

data "aws_region" "current" {}

resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-cluster"
}

resource "aws_cloudwatch_log_group" "sandbox" {
  name              = var.log_group_name
  retention_in_days = 14
}

# --- Role 1: task EXECUTION role (used by the ECS agent, NOT the code): ECR pull + logs only.
resource "aws_iam_role" "execution" {
  name = "${var.name_prefix}-task-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Role 2: task ROLE (the sandbox's own identity): EMPTY. No policies attached, ever.
# This is the no-reachable-credentials guarantee, made concrete.
resource "aws_iam_role" "task" {
  name = "${var.name_prefix}-task-empty"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  # Deliberately: no aws_iam_role_policy / no attachments. An explicit deny-all is added below to
  # make the intent unmistakable and to resist accidental future attachment.
}

resource "aws_iam_role_policy" "task_deny_all" {
  name = "deny-all"
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

resource "aws_ecs_task_definition" "sandbox" {
  family                   = "${var.name_prefix}-sandbox"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn # the EMPTY role

  container_definitions = jsonencode([
    {
      name                   = "sandbox"
      image                  = var.sandbox_image
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001:10001"
      linuxParameters        = { initProcessEnabled = true }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sandbox.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "sandbox"
        }
      }
    },
    {
      # Egress-proxy sidecar: the sandbox's only intended network path (deny-by-default, logs
      # attempts). Per-run allowlist is injected at launch (M5); default here is deny-all.
      name                   = "egress-proxy"
      image                  = var.proxy_image
      essential              = false
      readonlyRootFilesystem = true
      user                   = "10002:10002"
      environment            = [{ name = "MARK1_ALLOWED_HOSTS", value = "" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sandbox.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "egress-proxy"
        }
      }
    },
  ])
}

output "cluster_name" { value = aws_ecs_cluster.this.name }
output "task_definition_arn" { value = aws_ecs_task_definition.sandbox.arn }
output "empty_task_role_arn" { value = aws_iam_role.task.arn }
