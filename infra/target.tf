# The protected cloud machines: a separate VPC with one victim instance, VPC Flow Logs to S3,
# and a network ACL whose DENY entries belong to the collector.
#
# NETWORK ACL RULE NUMBERS (important, keeps Terraform and the collector from fighting):
#   1 - 90    reserved for the collector's DENY entries (idps.cloud.nacl). Terraform never
#             creates a rule in this range and never manages them.
#   91 - 99   unused
#   100+      ALLOW rules, each its own aws_network_acl_rule below.
# The aws_network_acl resource itself has NO inline ingress/egress blocks. With inline blocks
# Terraform would delete every rule it does not know about, including the collector's denies.
# A deny at a low number beats every allow, because rules are evaluated lowest number first.

resource "aws_vpc" "target" {
  cidr_block           = var.target_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-target" }
}

resource "aws_internet_gateway" "target" {
  vpc_id = aws_vpc.target.id

  tags = { Name = "${var.name_prefix}-target" }
}

resource "aws_subnet" "target" {
  vpc_id                  = aws_vpc.target.id
  cidr_block              = cidrsubnet(var.target_vpc_cidr, 8, 1)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true # needed so SSM can reach AWS without a (paid) NAT gateway

  tags = { Name = "${var.name_prefix}-target" }
}

resource "aws_route_table" "target" {
  vpc_id = aws_vpc.target.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.target.id
  }

  tags = { Name = "${var.name_prefix}-target" }
}

resource "aws_route_table_association" "target" {
  subnet_id      = aws_subnet.target.id
  route_table_id = aws_route_table.target.id
}

resource "aws_default_security_group" "target" {
  vpc_id = aws_vpc.target.id
}

# ---- Victim instance ---------------------------------------------------------------------------

resource "aws_security_group" "victim" {
  name_prefix = "${var.name_prefix}-victim-"
  description = "IDPS victim: web port only if victim_web_open, plus the attacker test hosts"
  vpc_id      = aws_vpc.target.id

  tags = { Name = "${var.name_prefix}-victim" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "victim_web" {
  for_each = var.victim_web_open ? toset(var.victim_web_cidrs) : toset([])

  security_group_id = aws_security_group.victim.id
  description       = "Web (port 80) from ${each.value}"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

locals {
  attacker_rules = {
    for pair in setproduct(var.attacker_ports, var.attacker_cidrs) :
    "${pair[0]}-${pair[1]}" => { port = pair[0], cidr = pair[1] }
  }
}

resource "aws_vpc_security_group_ingress_rule" "victim_attacker" {
  for_each = local.attacker_rules

  security_group_id = aws_security_group.victim.id
  description       = "Test attacker ${each.value.cidr} to TCP ${each.value.port}"
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr
}

resource "aws_vpc_security_group_egress_rule" "victim_all" {
  security_group_id = aws_security_group.victim.id
  description       = "Outbound: package updates and SSM"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_iam_role" "victim" {
  name_prefix        = "${var.name_prefix}-victim-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "victim_ssm_core" {
  role       = aws_iam_role.victim.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "victim" {
  name_prefix = "${var.name_prefix}-victim-"
  role        = aws_iam_role.victim.name
}

locals {
  victim_arch = can(regex("^[a-z]+[0-9]+g[a-z]*\\.", var.victim_instance_type)) ? "arm64" : "x86_64"
}

resource "aws_instance" "victim" {
  ami                    = data.aws_ssm_parameter.al2023[local.victim_arch].insecure_value
  instance_type          = var.victim_instance_type
  subnet_id              = aws_subnet.target.id
  vpc_security_group_ids = [aws_security_group.victim.id]
  iam_instance_profile   = aws_iam_instance_profile.victim.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  dynamic "credit_specification" {
    for_each = can(regex("^t[0-9]", var.victim_instance_type)) ? [1] : []
    content {
      cpu_credits = "standard"
    }
  }

  # A newer Amazon Linux release must not replace the instance.
  lifecycle {
    ignore_changes = [ami]
  }

  user_data_replace_on_change = true
  user_data                   = file("${path.module}/templates/victim-user-data.sh")

  tags = { Name = "${var.name_prefix}-victim" }
}

# ---- Network ACL: Terraform's ALLOW rules (100+) ----------------------------------------------

resource "aws_network_acl" "target" {
  vpc_id     = aws_vpc.target.id
  subnet_ids = [aws_subnet.target.id]

  # No inline ingress/egress: see the rule-number note at the top of this file.

  tags = { Name = "${var.name_prefix}-target" }
}

# Replies to connections the victim started (updates, SSM): network ACLs are stateless.
resource "aws_network_acl_rule" "in_ephemeral_tcp" {
  network_acl_id = aws_network_acl.target.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "in_ephemeral_udp" {
  network_acl_id = aws_network_acl.target.id
  rule_number    = 101
  egress         = false
  protocol       = "udp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Web port, only when victim_web_open. The security group is the finer filter.
resource "aws_network_acl_rule" "in_web" {
  count = var.victim_web_open ? length(var.victim_web_cidrs) : 0

  network_acl_id = aws_network_acl.target.id
  rule_number    = 110 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.victim_web_cidrs[count.index]
  from_port      = 80
  to_port        = 80
}

# Test attackers: everything is let through the NACL, the security group decides the ports.
# Closed ports then show up as REJECT records in the flow logs.
resource "aws_network_acl_rule" "in_attacker" {
  count = length(var.attacker_cidrs)

  network_acl_id = aws_network_acl.target.id
  rule_number    = 200 + count.index
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.attacker_cidrs[count.index]
}

resource "aws_network_acl_rule" "out_all" {
  network_acl_id = aws_network_acl.target.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# ---- VPC Flow Logs -> S3 ---------------------------------------------------------------------

data "aws_iam_policy_document" "flowlog_delivery" {
  statement {
    sid       = "AWSLogDeliveryWrite"
    actions   = ["s3:PutObject"]
    resources = ["${local.flowlog_bucket_arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${local.account_id}:*"]
    }
  }

  statement {
    sid       = "AWSLogDeliveryAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [local.flowlog_bucket_arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

module "flowlog_bucket" {
  source = "./modules/secure_bucket"

  bucket_name            = local.flowlog_bucket_name
  versioning             = false
  expire_days            = var.flow_log_retention_days
  force_destroy          = var.force_destroy_buckets
  extra_policy_documents = [data.aws_iam_policy_document.flowlog_delivery.json]
}

resource "aws_flow_log" "target" {
  vpc_id                   = aws_vpc.target.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = module.flowlog_bucket.arn
  max_aggregation_interval = 60 # the collector's model assumes 60 s windows (idps.cloud.flowlogs)
  # No log_format: the default version-2 format that idps.cloud.flowlogs parses.

  tags = { Name = "${var.name_prefix}-target" }

  depends_on = [module.flowlog_bucket]
}
