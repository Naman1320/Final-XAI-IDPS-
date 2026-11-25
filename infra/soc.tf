# ---- SOC VPC: one public subnet ----------------------------------------------------------------

resource "aws_vpc" "soc" {
  cidr_block           = var.soc_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-soc" }
}

resource "aws_internet_gateway" "soc" {
  vpc_id = aws_vpc.soc.id

  tags = { Name = "${var.name_prefix}-soc" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "soc_public" {
  vpc_id                  = aws_vpc.soc.id
  cidr_block              = cidrsubnet(var.soc_vpc_cidr, 8, 1)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false # the Elastic IP below is the only public address

  tags = { Name = "${var.name_prefix}-soc-public" }
}

resource "aws_route_table" "soc_public" {
  vpc_id = aws_vpc.soc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.soc.id
  }

  tags = { Name = "${var.name_prefix}-soc-public" }
}

resource "aws_route_table_association" "soc_public" {
  subnet_id      = aws_subnet.soc_public.id
  route_table_id = aws_route_table.soc_public.id
}

# The VPC's default security group allows all traffic between its members: empty it.
resource "aws_default_security_group" "soc" {
  vpc_id = aws_vpc.soc.id
}

# ---- Security group: 443 and 80 from admin_cidrs and sensor_cidrs only; no SSH -----------------
# Shell access is SSM Session Manager (outbound only), so port 22 is never opened.
# Port 80 only redirects to HTTPS: the Caddy certificate is issued by Caddy's own CA for the
# Elastic IP, because Let's Encrypt's validation servers are not in admin_cidrs (see README.md).

locals {
  soc_ingress_cidrs = distinct(concat(var.admin_cidrs, var.sensor_cidrs))
  soc_ingress_rules = {
    for pair in setproduct([80, 443], local.soc_ingress_cidrs) :
    "${pair[0]}-${pair[1]}" => { port = pair[0], cidr = pair[1] }
  }
}

resource "aws_security_group" "soc" {
  name_prefix = "${var.name_prefix}-soc-"
  description = "IDPS SOC: HTTPS from admins and sensors only"
  vpc_id      = aws_vpc.soc.id

  tags = { Name = "${var.name_prefix}-soc" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "soc" {
  for_each = local.soc_ingress_rules

  security_group_id = aws_security_group.soc.id
  description       = "TCP ${each.value.port} from ${each.value.cidr}"
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr
}

resource "aws_vpc_security_group_egress_rule" "soc_all" {
  security_group_id = aws_security_group.soc.id
  description       = "Outbound: package and image downloads, SSM, Anthropic API"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ---- Instance role: SSM Session Manager + read the SOC parameters (see secrets.tf) --------------

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "soc" {
  name_prefix        = "${var.name_prefix}-soc-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "soc_ssm_core" {
  role       = aws_iam_role.soc.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "soc_read_secrets" {
  statement {
    sid       = "ReadSocSecretsOnly"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = local.ssm_parameter_arns # everything under ssm_prefix: created with the CLI
  }

  # The parameters use the customer-managed key in secrets.tf, whose key policy lets only this
  # role decrypt (through SSM).
  statement {
    sid       = "DecryptSocSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.ssm.arn]
  }
}

resource "aws_iam_role_policy" "soc_read_secrets" {
  name   = "read-soc-secrets"
  role   = aws_iam_role.soc.id
  policy = data.aws_iam_policy_document.soc_read_secrets.json
}

resource "aws_iam_instance_profile" "soc" {
  name_prefix = "${var.name_prefix}-soc-"
  role        = aws_iam_role.soc.name
}

# ---- The instance ------------------------------------------------------------------------------

locals {
  # Graviton instance families end in "g" (t4g, c7g, m6g, ...): they need the arm64 image.
  soc_arch = can(regex("^[a-z]+[0-9]+g[a-z]*\\.", var.soc_instance_type)) ? "arm64" : "x86_64"
}

data "aws_ssm_parameter" "al2023" {
  for_each = toset(["x86_64", "arm64"])
  name     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${each.key}"
}

resource "aws_instance" "soc" {
  ami                    = data.aws_ssm_parameter.al2023[local.soc_arch].insecure_value
  instance_type          = var.soc_instance_type
  subnet_id              = aws_subnet.soc_public.id
  vpc_security_group_ids = [aws_security_group.soc.id]
  iam_instance_profile   = aws_iam_instance_profile.soc.name

  # No key pair: there is no SSH. Use `aws ssm start-session`.

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # containers cannot reach the instance credentials
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.soc_root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  # A burstable instance that runs out of credits is throttled, not billed extra.
  dynamic "credit_specification" {
    for_each = can(regex("^t[0-9]", var.soc_instance_type)) ? [1] : []
    content {
      cpu_credits = "standard"
    }
  }

  # A newer Amazon Linux release must not replace the instance: that would wipe the SOC database.
  # (Changing the user data does replace it, see user_data_replace_on_change.)
  lifecycle {
    ignore_changes = [ami]
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/soc-user-data.sh.tftpl", {
    region          = var.aws_region
    ssm_prefix      = var.ssm_prefix
    soc_public_ip   = aws_eip.soc.public_ip
    repo_url        = var.repo_url
    repo_ref        = var.repo_ref
    compose_version = var.compose_version
    block_allowlist = join(",", var.block_allowlist)
  })

  tags = { Name = "${var.name_prefix}-soc" }

  # Wait for the IAM policy so the first boot can already read the parameters (once they exist).
  depends_on = [aws_iam_role_policy.soc_read_secrets]
}

resource "aws_eip" "soc" {
  domain = "vpc"

  tags = { Name = "${var.name_prefix}-soc" }

  depends_on = [aws_internet_gateway.soc]
}

resource "aws_eip_association" "soc" {
  instance_id   = aws_instance.soc.id
  allocation_id = aws_eip.soc.id
}

# ---- Trained models ----------------------------------------------------------------------------

module "models_bucket" {
  source = "./modules/secure_bucket"

  bucket_name   = local.models_bucket_name
  versioning    = true
  force_destroy = var.force_destroy_buckets
}
