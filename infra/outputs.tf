output "soc_instance_id" {
  description = "SOC host. Shell: aws ssm start-session --target <id>"
  value       = aws_instance.soc.id
}

output "soc_public_ip" {
  description = "SOC host address (HTTPS on 443; the certificate is issued for this address by Caddy's own CA)."
  value       = aws_eip.soc.public_ip
}

output "flow_log_bucket" {
  description = "Bucket the target VPC's flow logs are delivered to (IDPS_CLOUD_BUCKET)."
  value       = module.flowlog_bucket.id
}

output "flow_log_prefix" {
  description = "Key prefix of the flow logs (IDPS_CLOUD_PREFIX, required by the collector)."
  value       = local.flow_log_prefix
}

output "target_nacl_id" {
  description = "The network ACL the collector blocks with (IDPS_CLOUD_NACL_ID)."
  value       = aws_network_acl.target.id
}

output "collector_role_arn" {
  description = "Role the collector assumes (null until collector_trusted_principal_arns is set)."
  value       = one(aws_iam_role.collector[*].arn)
}

output "models_bucket" {
  description = "Bucket for trained models."
  value       = module.models_bucket.id
}

output "victim_instance_id" {
  value = aws_instance.victim.id
}

output "victim_private_ip" {
  description = "Put the target VPC CIDR (and this address) on the collector's IDPS_ALLOWLIST."
  value       = aws_instance.victim.private_ip
}

output "target_vpc_cidr" {
  value = aws_vpc.target.cidr_block
}

output "ssm_parameter_names" {
  description = "Create each once with: aws ssm put-parameter --type SecureString --key-id <ssm_kms_key_id> --name <name> --value ..."
  value       = local.secret_names
}

output "ssm_kms_key_id" {
  description = "Customer-managed KMS key for the SOC parameters: pass it as --key-id to aws ssm put-parameter."
  value       = aws_kms_key.ssm.key_id
}

output "ssm_kms_key_arn" {
  value = aws_kms_key.ssm.arn
}
