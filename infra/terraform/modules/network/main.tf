# Network: a private subnet with NO NAT gateway, so default runs have no internet route.
# Image pull and data I/O go through a free S3 gateway endpoint plus optional (opt-in) interface
# endpoints for ECR + Logs. The deny-all security group is the sandbox's only egress posture;
# an egress-proxy sidecar is the sole intended path when a run is explicitly allowlisted.

variable "name_prefix" {
  type    = string
  default = "keyhole"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "private_subnet_cidr" {
  type    = string
  default = "10.42.1.0/24"
}

# Interface endpoints (ECR api/dkr, Logs) cost ~$7/month each. Off by default to keep idle ≈ $0;
# turn on only when you actually need to launch cloud runs.
variable "enable_egress_endpoints" {
  type    = bool
  default = false
}

data "aws_region" "current" {}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.private_subnet_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-private" }
}

# A route table with NO NAT/IGW route: there is simply no path to the internet.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# Deny-all egress: the sandbox cannot open outbound connections.
resource "aws_security_group" "deny_all" {
  name        = "${var.name_prefix}-deny-all"
  description = "No egress; sandbox has no network path out"
  vpc_id      = aws_vpc.this.id
  # No egress rules => all egress denied. No ingress rules => no ingress.
  tags = { Name = "${var.name_prefix}-deny-all" }
}

# The AWS-managed prefix list for S3 in this region (used to scope egress to S3 only).
data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.region}.s3"
}

# Run security group: the sandbox task's egress is limited to AWS service endpoints only —
# S3 (via the gateway endpoint's prefix list) and the in-subnet ECR/Logs interface endpoints.
# There is NO 0.0.0.0/0 rule and no NAT, so the task cannot reach the general internet. Combined
# with the empty task role, any reachable endpoint is useless to untrusted code.
resource "aws_security_group" "run" {
  name        = "${var.name_prefix}-run"
  description = "Sandbox egress: AWS endpoints only (S3/ECR/Logs); no internet"
  vpc_id      = aws_vpc.this.id

  egress {
    description     = "S3 via the gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.s3.id]
  }

  egress {
    description = "In-subnet interface endpoints (ECR/Logs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.private_subnet_cidr]
  }

  tags = { Name = "${var.name_prefix}-run" }
}

# Free S3 gateway endpoint: lets the task read code/data and write results without any internet.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = { Name = "${var.name_prefix}-s3-gw" }
}

# Optional interface endpoints for cloud runs (image pull + logs). Opt-in to control cost.
locals {
  interface_services = var.enable_egress_endpoints ? [
    "ecr.api", "ecr.dkr", "logs",
  ] : []
}

resource "aws_security_group" "endpoints" {
  count       = var.enable_egress_endpoints ? 1 : 0
  name        = "${var.name_prefix}-endpoints"
  description = "Allow the sandbox subnet to reach AWS interface endpoints"
  vpc_id      = aws_vpc.this.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.private_subnet_cidr]
  }
  tags = { Name = "${var.name_prefix}-endpoints" }
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(local.interface_services)
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = { Name = "${var.name_prefix}-${each.value}" }
}

output "vpc_id" { value = aws_vpc.this.id }
output "private_subnet_id" { value = aws_subnet.private.id }
output "deny_all_security_group_id" { value = aws_security_group.deny_all.id }
output "run_security_group_id" { value = aws_security_group.run.id }
