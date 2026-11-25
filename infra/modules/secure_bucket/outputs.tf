output "id" {
  value = aws_s3_bucket.this.id
}

output "arn" {
  value = aws_s3_bucket.this.arn
}

# Callers use this to wait for the bucket policy before pointing a service at the bucket.
output "policy_id" {
  value = aws_s3_bucket_policy.this.id
}
