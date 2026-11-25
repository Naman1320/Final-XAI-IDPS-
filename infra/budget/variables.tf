variable "budget_email" {
  description = "Email address that receives the AWS Budgets alerts (80% and 100% of actual spend, 100% forecast)."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
    error_message = "budget_email must look like an email address."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget in USD."
  type        = number
  default     = 10

  validation {
    condition     = var.monthly_budget_usd > 0
    error_message = "monthly_budget_usd must be positive."
  }
}

variable "name_prefix" {
  description = "Prefix of the budget name (lowercase letters, digits, hyphens)."
  type        = string
  default     = "idps-fyp"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-32 characters: lowercase letters, digits and hyphens."
  }
}

variable "aws_region" {
  description = "Region for the provider (budgets are account-wide)."
  type        = string
  default     = "eu-west-1"
}
