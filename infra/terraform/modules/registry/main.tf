# Registry: ECR repos for the sandbox and egress-proxy images, with scan-on-push and a lifecycle
# policy that keeps only the most recent images (keeps storage negligible).

variable "name_prefix" {
  type    = string
  default = "mark1"
}

locals {
  repos = ["sandbox-python", "egress-proxy"]
}

resource "aws_ecr_repository" "this" {
  for_each = toset(local.repos)
  name     = "${var.name_prefix}/${each.value}"
  # MUTABLE so the dev loop can re-push :latest. Pin to immutable digests for production.
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep last 5 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })
}

output "sandbox_repo_url" { value = aws_ecr_repository.this["sandbox-python"].repository_url }
output "proxy_repo_url" { value = aws_ecr_repository.this["egress-proxy"].repository_url }
