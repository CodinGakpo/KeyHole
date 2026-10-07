# Guardrails: a monthly AWS Budgets alarm so cost never surprises you. The budget is a hard
# backstop; the application-level quotas (see keyhole.controlplane.quotas) are the first line.
# One budget per account is free. Given the expected steady state (~$1/mo for the KMS key plus
# pennies of Fargate), a $5 limit warns well below the ~$10 concern line and catches anything
# unexpected (a stray NAT gateway, a stuck task) early.

variable "name_prefix" {
  type    = string
  default = "keyhole"
}

variable "monthly_budget_usd" {
  type    = number
  default = 5
}

variable "alert_email" {
  type        = string
  description = "Email to notify on budget thresholds"
}

locals {
  # ACTUAL fires on spend already incurred; FORECASTED fires when AWS projects you'll exceed the
  # limit by month end — an earlier heads-up.
  budget_notifications = [
    { type = "ACTUAL", threshold = 50 },
    { type = "ACTUAL", threshold = 80 },
    { type = "ACTUAL", threshold = 100 },
    { type = "FORECASTED", threshold = 100 },
  ]
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = local.budget_notifications
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.alert_email]
    }
  }
}

output "budget_name" { value = aws_budgets_budget.monthly.name }
