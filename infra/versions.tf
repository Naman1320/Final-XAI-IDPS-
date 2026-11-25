terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Local state on purpose: one person, one account. *.tfstate is git-ignored.
  # The SOC secrets are NOT in Terraform at all (SSM parameters are created with the AWS CLI,
  # see secrets.tf), so they cannot end up in state. State still holds resource ids, ARNs and the
  # rendered user data: keep it private and do not share it.
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource that supports tags gets these.
  default_tags {
    tags = {
      Project   = "idps-fyp"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # S3 bucket names are global: the account id makes them unique and recognisable.
  models_bucket_name  = "${var.name_prefix}-models-${local.account_id}"
  flowlog_bucket_name = "${var.name_prefix}-flowlogs-${local.account_id}"
  flowlog_bucket_arn  = "arn:${data.aws_partition.current.partition}:s3:::${local.flowlog_bucket_name}"
}
