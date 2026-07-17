# Guardrails: a monthly AWS Budgets alarm so cost never surprises you. The budget is a hard
# backstop; the application-level quotas (see mark1.controlplane.quotas) are the first line.

variable "name_prefix" {
  type    = string
  default = "mark1"
}

variable "monthly_budget_usd" {
  type    = number
  default = 10
}

variable "alert_email" {
  type        = string
  description = "Email to notify at 50%/80%/100% of budget"
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [50, 80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.alert_email]
    }
  }
}
