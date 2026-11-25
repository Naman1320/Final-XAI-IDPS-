# ---- Required (no defaults: you must decide these) ---------------------------------------------

variable "admin_cidrs" {
  description = "Public IPv4 CIDRs allowed to reach the SOC on 443 and 80, e.g. [\"203.0.113.25/32\"]. Each must be a /24 or narrower with no host bits set. Never the whole internet."
  type        = list(string)
  # Deliberately no default.

  validation {
    condition     = length(var.admin_cidrs) > 0
    error_message = "admin_cidrs must contain at least one CIDR (your own public IP as x.x.x.x/32)."
  }

  validation {
    condition = alltrue([
      for c in var.admin_cidrs :
      can(cidrnetmask(c)) ? (tonumber(split("/", c)[1]) >= 24 && cidrhost(c, 0) == split("/", c)[0]) : false
    ])
    error_message = "Every admin_cidrs entry must be an IPv4 CIDR of /24 or narrower with no host bits set (203.0.113.25/32, not 203.0.113.25/24)."
  }

  validation {
    condition     = !contains(var.admin_cidrs, "0.0.0.0/0")
    error_message = "admin_cidrs must not contain 0.0.0.0/0: the SOC dashboard must not be open to the internet."
  }
}

# ---- General -----------------------------------------------------------------------------------

variable "aws_region" {
  description = "Region for everything."
  type        = string
  default     = "eu-west-1"
}

variable "name_prefix" {
  description = "Prefix for resource names (lowercase letters, digits, hyphens; used in S3 bucket names)."
  type        = string
  default     = "idps-fyp"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-32 characters: lowercase letters, digits and hyphens."
  }
}

variable "force_destroy_buckets" {
  description = "Let terraform destroy delete the S3 buckets even when they hold objects (flow logs, trained models). Keep a local copy of models."
  type        = bool
  default     = true
}

variable "ssm_prefix" {
  description = "Parameter Store path prefix for the SOC secrets."
  type        = string
  default     = "/idps-fyp"

  validation {
    condition     = can(regex("^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$", var.ssm_prefix))
    error_message = "ssm_prefix must start with / and contain no trailing slash, e.g. /idps-fyp."
  }
}

# ---- SOC host ----------------------------------------------------------------------------------

variable "soc_vpc_cidr" {
  description = "CIDR of the SOC VPC (one public subnet is carved from it)."
  type        = string
  default     = "10.50.0.0/16"
}

variable "soc_instance_type" {
  description = "EC2 type of the SOC host. t3.micro is free-tier eligible on most accounts but has only 1 GB of RAM; t3.small is more comfortable."
  type        = string
  default     = "t3.micro"
}

variable "soc_root_volume_gb" {
  description = "Root volume size of the SOC host (GB, gp3, encrypted)."
  type        = number
  default     = 20
}

variable "sensor_cidrs" {
  description = "Public IPv4 CIDRs of the lab sensor and of wherever the cloud collector runs; they may reach the SOC on 443/80 like the admins. Empty = none."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for c in var.sensor_cidrs :
      can(cidrnetmask(c)) ? (tonumber(split("/", c)[1]) >= 24 && cidrhost(c, 0) == split("/", c)[0]) : false
    ])
    error_message = "Every sensor_cidrs entry must be an IPv4 CIDR of /24 or narrower with no host bits set."
  }
}

variable "repo_url" {
  description = "HTTPS URL of a public git repository holding this project; cloned to /opt/idps/repo on first boot. Empty = copy the code there yourself through SSM."
  type        = string
  default     = ""

  validation {
    # It is pasted into a boot script: only URL characters, no quotes, spaces, $, ; or backticks.
    condition     = var.repo_url == "" || can(regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[A-Za-z0-9._~/-]+$", var.repo_url))
    error_message = "repo_url must be empty or an https:// URL made of letters, digits and . _ ~ / - only (no credentials, query or fragment)."
  }
}

variable "repo_ref" {
  description = "Branch or tag of repo_url to clone."
  type        = string
  default     = "main"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$", var.repo_ref))
    error_message = "repo_ref must be a branch or tag name: letters, digits and . _ / - only, not starting with a dash."
  }
}

variable "block_allowlist" {
  description = "Addresses/networks the SOC must never ask a sensor to block (IDPS_SOC_BLOCK_ALLOWLIST). Empty = the SOC refuses every block request."
  type        = list(string)
  default     = []
}

variable "compose_version" {
  description = "Docker Compose release installed on the SOC host."
  type        = string
  default     = "v2.40.3"
}

# ---- Target VPC (the protected cloud machines) -------------------------------------------------

variable "target_vpc_cidr" {
  description = "CIDR of the target VPC."
  type        = string
  default     = "10.60.0.0/16"
}

variable "victim_instance_type" {
  description = "EC2 type of the victim instance."
  type        = string
  default     = "t3.micro"
}

variable "victim_web_open" {
  description = "Open the victim's web port (80) to victim_web_cidrs. Default: closed."
  type        = bool
  default     = false
}

variable "victim_web_cidrs" {
  description = "Who may reach port 80 on the victim when victim_web_open is true."
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition = length(var.victim_web_cidrs) <= 4 && alltrue([
      for c in var.victim_web_cidrs : can(cidrnetmask(c))
    ])
    error_message = "victim_web_cidrs: at most 4 valid IPv4 CIDRs (each one is a network ACL rule)."
  }
}

variable "attacker_cidrs" {
  description = "Public /32s of your own attacker machine(s) for test sessions (e.g. a second EC2 instance). They may reach the victim on attacker_ports. At most 4 (NACL rule quota)."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.attacker_cidrs) <= 4
    error_message = "At most 4 attacker_cidrs (network ACLs allow 20 rules per direction by default and the collector needs room for its deny entries)."
  }

  validation {
    condition = alltrue([
      for c in var.attacker_cidrs :
      can(cidrnetmask(c)) ? tonumber(split("/", c)[1]) >= 16 : false
    ])
    error_message = "Every attacker_cidrs entry must be an IPv4 CIDR with a prefix of /16 or longer."
  }
}

variable "attacker_ports" {
  description = "TCP ports the attacker CIDRs may reach on the victim (scans of closed ports show up as REJECT flows)."
  type        = list(number)
  default     = [22, 80]
}

variable "flow_log_retention_days" {
  description = "Flow-log objects are deleted after this many days."
  type        = number
  default     = 7

  validation {
    condition     = var.flow_log_retention_days >= 1
    error_message = "flow_log_retention_days must be at least 1."
  }
}

# ---- Collector ---------------------------------------------------------------------------------

variable "collector_trusted_principal_arns" {
  description = "IAM users/roles that may assume the collector role. Empty (the default) = the collector role is NOT created. The account root is not accepted: list the specific principals."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for a in var.collector_trusted_principal_arns :
      can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(user|role)/[A-Za-z0-9+=,.@_/-]+$", a))
    ])
    error_message = "Each entry must be an IAM user or role ARN, e.g. arn:aws:iam::111122223333:user/you (not the account root)."
  }
}
