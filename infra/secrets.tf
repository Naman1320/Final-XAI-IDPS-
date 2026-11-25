# SOC secrets in SSM Parameter Store: NOT managed by Terraform.
#
# An aws_ssm_parameter resource would write the decrypted value into terraform.tfstate on every
# refresh (ignore_changes does not prevent that), so the parameters are created once by hand with
# the AWS CLI and Terraform only manages who may read them:
#
#   KEY=$(terraform output -raw ssm_kms_key_id)
#   aws ssm put-parameter --name /idps-fyp/jwt-secret --type SecureString --key-id "$KEY" \
#     --value "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
#   (same for /idps-fyp/anthropic-api-key and /idps-fyp/maxmind-key; see README.md)
#
# Who can read them:
#   - The parameters are encrypted with the customer-managed key below, NOT with alias/aws/ssm:
#     the AWS-managed key lets every principal in the account decrypt through SSM, so any role
#     with ssm:GetParameter on "*" (which AmazonSSMManagedInstanceCore grants) could read them.
#   - The key policy allows kms:Decrypt only to the SOC instance role (and only through SSM).
#     The account root keeps administration (and Encrypt, so put-parameter works) but not Decrypt.
#     Anyone who can edit the key policy (kms:PutKeyPolicy) can still give themselves access: this
#     keeps the victim instance and ordinary roles out, it is not protection from an account admin.
#   - The victim role has an explicit IAM Deny on the parameter path and on kms:Decrypt for the
#     key, which beats the "*" allow in AmazonSSMManagedInstanceCore.
#
# `terraform destroy` schedules the key for deletion (7 days) and does NOT delete the parameters;
# delete them with the CLI (README.md), they are unreadable without the key anyway.

locals {
  secret_names = {
    jwt_secret        = "${var.ssm_prefix}/jwt-secret"
    anthropic_api_key = "${var.ssm_prefix}/anthropic-api-key"
    maxmind_key       = "${var.ssm_prefix}/maxmind-key"
  }

  # ssm_prefix starts with "/", which is what a parameter ARN expects after "parameter".
  ssm_arn_base       = "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${local.account_id}:parameter"
  ssm_parameter_arns = ["${local.ssm_arn_base}${var.ssm_prefix}/*"]
  # GetParametersByPath is authorised on the path itself.
  ssm_path_arns = concat(local.ssm_parameter_arns, ["${local.ssm_arn_base}${var.ssm_prefix}"])
}

data "aws_iam_policy_document" "ssm_key" {
  statement {
    sid    = "AccountAdministration"
    effect = "Allow"
    actions = [
      "kms:CreateAlias",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }

  # Encrypt-only: lets you run aws ssm put-parameter. Cannot read anything back.
  statement {
    sid       = "AccountMayWriteParameters"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "OnlyTheSocInstanceRoleMayDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.soc.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "ssm" {
  description             = "IDPS SOC secrets in SSM Parameter Store (decrypt: SOC instance role only)"
  enable_key_rotation     = true # about 1 USD/month for the key, plus a few cents of requests
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.ssm_key.json
}

resource "aws_kms_alias" "ssm" {
  name          = "alias/${var.name_prefix}-ssm"
  target_key_id = aws_kms_key.ssm.key_id
}

# The victim instance must not be able to read the SOC's secrets, whatever else it is allowed.
data "aws_iam_policy_document" "victim_deny_soc_secrets" {
  statement {
    sid    = "DenyReadingSocSecrets"
    effect = "Deny"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:GetParameterHistory",
    ]
    resources = local.ssm_path_arns
  }

  statement {
    sid       = "DenyDecryptingSocSecrets"
    effect    = "Deny"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.ssm.arn]
  }
}

resource "aws_iam_role_policy" "victim_deny_soc_secrets" {
  name   = "deny-soc-secrets"
  role   = aws_iam_role.victim.id
  policy = data.aws_iam_policy_document.victim_deny_soc_secrets.json
}
