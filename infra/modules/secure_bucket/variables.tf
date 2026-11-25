variable "bucket_name" {
  description = "Globally unique bucket name."
  type        = string
}

variable "versioning" {
  description = "Keep old object versions."
  type        = bool
  default     = false
}

variable "expire_days" {
  description = "Delete objects (and old versions) after this many days. 0 = keep forever."
  type        = number
  default     = 0
}

variable "force_destroy" {
  description = "Allow terraform destroy to delete a non-empty bucket."
  type        = bool
  default     = false
}

variable "extra_policy_documents" {
  description = "JSON policy documents merged into the bucket policy (the TLS-only rule is always there)."
  type        = list(string)
  default     = []
}
