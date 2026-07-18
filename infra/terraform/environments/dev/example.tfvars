# Copy to terraform.tfvars (gitignored) and fill in your values.
# Only alert_email is needed to enable the budget alarm.

alert_email        = "you@example.com"
monthly_budget_usd = 5

# Free data plane only by default. Turn these on when you need them (M5+):
# enable_control_plane    = false  # adds ~$1/mo KMS key + Lambda/API Gateway
# enable_egress_endpoints = false  # adds ~$7/mo per interface endpoint (ECR/Logs) for cloud runs
