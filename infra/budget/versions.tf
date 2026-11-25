# A separate root module from ../ : the budget is created once and is NOT destroyed with the lab
# stack. Its own local state (terraform.tfstate, git-ignored) lives in this directory.
terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "idps-fyp"
      ManagedBy = "terraform"
    }
  }
}
