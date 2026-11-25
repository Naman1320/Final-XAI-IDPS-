# Point every AWS tool in this shell at the emulator, never at real AWS.
#   source lab/cloud/env.sh
# Fake credentials only. The real config and credential files are hidden, so no profile,
# SSO session or stored key can be picked up by accident.

unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_SESSION_TOKEN AWS_SECURITY_TOKEN \
      AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE AWS_CONTAINER_CREDENTIALS_FULL_URI \
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_AUTHORIZATION_TOKEN \
      AWS_CA_BUNDLE HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
# Per-service endpoint overrides (AWS_ENDPOINT_URL_S3, ...) could point one service elsewhere.
for v in $(env | sed -n 's/^\(AWS_ENDPOINT_URL_[A-Z0-9_]*\)=.*/\1/p'); do unset "$v"; done
unset v
# Talk to the emulator directly, never through a proxy set in the user's own shell.
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_REGION=eu-west-1
export AWS_DEFAULT_REGION=eu-west-1
export AWS_ENDPOINT_URL=http://127.0.0.1:4566
export AWS_CONFIG_FILE=/dev/null
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_EC2_METADATA_DISABLED=true

# The emulator's account id (lab/cloud/docker-compose.yml, MOTO_ACCOUNT_ID).
export IDPS_EMULATOR_ACCOUNT=000000000000

# Stop Terraform calling HashiCorp to check for new versions.
export CHECKPOINT_DISABLE=1
