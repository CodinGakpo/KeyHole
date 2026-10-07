# Execution: the ECS cluster, the sandbox task definition, and the THREE IAM roles.
# The single most important line here is the sandbox task role: it is EMPTY. Even if untrusted
# code reaches the task-metadata endpoint, the credentials it vends can do nothing.

variable "name_prefix" {
  type    = string
  default = "keyhole"
}

variable "sandbox_image" {
  type        = string
  description = "ECR image URI for the sandbox container"
}

variable "log_group_name" {
  type    = string
  default = "/keyhole/sandbox"
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

  # Writable ephemeral scratch for the read-only-root container. An empty volume mounted over the
  # image's /sandbox/work inherits that path's ownership (uid 10001), so the non-root sandbox user
  # can write there while the rest of the root filesystem stays read-only.
  volume {
    name = "scratch"
  }

  # A single sandbox container. Network containment is enforced at the subnet/route/SG level
  # (private subnet, no NAT, endpoints-only egress) — NOT by an in-task sidecar, because Fargate
  # awsvpc containers share one network namespace. The egress-proxy image + its Docker harness are
  # retained for the future allowlisted-egress feature, which needs a different enforcement point.
  container_definitions = jsonencode([
    {
      # Init container: runs as root ONLY to chown the shared scratch volume to the sandbox user,
      # then exits. This is the correct way to give a read-only-root, non-root container writable
      # scratch on Fargate (empty volumes mount root-owned). It touches only the volume — no AWS
      # access, no network — so the empty task role and containment are unaffected.
      name                   = "init-scratch"
      image                  = var.sandbox_image
      essential              = false
      readonlyRootFilesystem = true
      user                   = "0:0"
      entryPoint             = ["sh", "-c", "chown 10001:10001 /sandbox/work"]
      mountPoints = [
        { sourceVolume = "scratch", containerPath = "/sandbox/work", readOnly = false }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sandbox.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "init"
        }
      }
    },
    {
      name                   = "sandbox"
      image                  = var.sandbox_image
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001:10001"
      linuxParameters        = { initProcessEnabled = true }
      dependsOn = [
        { containerName = "init-scratch", condition = "SUCCESS" }
      ]
      mountPoints = [
        { sourceVolume = "scratch", containerPath = "/sandbox/work", readOnly = false }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sandbox.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "sandbox"
        }
      }
    },
  ])
}

output "cluster_name" { value = aws_ecs_cluster.this.name }
output "task_definition_arn" { value = aws_ecs_task_definition.sandbox.arn }
output "empty_task_role_arn" { value = aws_iam_role.task.arn }
output "execution_role_arn" { value = aws_iam_role.execution.arn }
