# The cloud collector (python -m idps.cloud collect) runs wherever you run it, as this role.
# It may only:
#   - list the flow-log bucket (this account's flow-log prefix only) and read those objects;
#   - create / replace / delete entries on the ONE target network ACL.
# It cannot read the models bucket, the SOC secrets or any other S3 bucket, and it cannot touch
# any other network ACL.
#
# The role is only created when collector_trusted_principal_arns lists who may assume it: there is
# no default trust (not even "anyone in this account").
#
# ec2:DescribeNetworkAcls does not support resource-level permissions, so it is granted on "*".
# It is read-only and returns network ACL metadata for the region.
#
# The role can edit entries numbered 100+ as well (IAM cannot condition on the rule number). The
# collector code never touches them, and tests enforce that, but IAM does not.

locals {
  create_collector_role = length(var.collector_trusted_principal_arns) > 0
  flow_log_prefix       = "AWSLogs/${local.account_id}/vpcflowlogs/${var.aws_region}/"
}

data "aws_iam_policy_document" "collector_trust" {
  count = local.create_collector_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.collector_trusted_principal_arns
    }
  }
}

resource "aws_iam_role" "collector" {
  count = local.create_collector_role ? 1 : 0

  name_prefix          = "${var.name_prefix}-collector-"
  description          = "IDPS cloud collector: read flow logs, edit one network ACL"
  assume_role_policy   = data.aws_iam_policy_document.collector_trust[0].json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "collector" {
  statement {
    sid       = "ListFlowLogBucket"
    actions   = ["s3:ListBucket"]
    resources = [module.flowlog_bucket.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.flow_log_prefix}*"]
    }
  }

  statement {
    sid       = "ReadFlowLogObjects"
    actions   = ["s3:GetObject"]
    resources = ["${module.flowlog_bucket.arn}/${local.flow_log_prefix}*"]
  }

  statement {
    sid = "EditTargetNetworkAclEntries"
    actions = [
      "ec2:CreateNetworkAclEntry",
      "ec2:ReplaceNetworkAclEntry",
      "ec2:DeleteNetworkAclEntry",
    ]
    resources = [aws_network_acl.target.arn]
  }

  statement {
    sid       = "DescribeNetworkAclsCannotBeScoped"
    actions   = ["ec2:DescribeNetworkAcls"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "collector" {
  count = local.create_collector_role ? 1 : 0

  name   = "collector"
  role   = aws_iam_role.collector[0].id
  policy = data.aws_iam_policy_document.collector.json
}
