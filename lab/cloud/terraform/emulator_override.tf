# Applied only by lab/cloud/tf.sh, which copies infra/ into a separate work folder and adds this
# file. Terraform merges *_override.tf over the real files, so infra/ itself stays the real AWS
# design, unchanged. Every service infra/ uses is pinned to the local emulator; nothing reaches
# real AWS. Region, default_tags and everything else come from infra/versions.tf.

provider "aws" {
  access_key = "test"
  secret_key = "test"

  # The emulator accepts any fake key; these skip the checks that would call real AWS.
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    ec2     = "http://127.0.0.1:4566"
    iam     = "http://127.0.0.1:4566"
    kms     = "http://127.0.0.1:4566"
    s3      = "http://127.0.0.1:4566"
    ssm     = "http://127.0.0.1:4566"
    sts     = "http://127.0.0.1:4566"
    budgets = "http://127.0.0.1:4566"
    # S3 Control puts the account id in front of the host (000000000000.<host>). A name under
    # .localhost resolves to this machine; one under 127.0.0.1 doesn't resolve at all.
    s3control = "http://localhost:4566"
  }
}
