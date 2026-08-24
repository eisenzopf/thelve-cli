variable "region" {
  type    = string
  default = "us-west-2"
}

variable "availability_zone" {
  type    = string
  default = "us-west-2a"
}

variable "name" {
  type    = string
  default = "thelve"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.name))
    error_message = "name must be a 3-32 character lowercase resource prefix."
  }
}

variable "environment" {
  type    = string
  default = "test"
  validation {
    condition     = contains(["test", "staging", "production"], var.environment)
    error_message = "environment must be test, staging, or production."
  }
}

variable "ami_id" {
  description = "Exact active Thelve AMI from a verified machine-image catalog."
  type        = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id must be an exact AMI ID."
  }
}

variable "compute_profile" {
  description = "Portable Thelve capacity profile. The module owns the exact EC2 instance-type mapping."
  type        = string
  default     = "recommended_test"
  validation {
    condition = contains([
      "budget_smoke",
      "recommended_test",
      "production_baseline",
      "production_growth"
    ], var.compute_profile)
    error_message = "compute_profile must be budget_smoke, recommended_test, production_baseline, or production_growth."
  }
}

variable "instance_state" {
  description = "running or stopped. Stopped retains the EIP and EBS volume while stopping compute charges."
  type        = string
  default     = "running"
  validation {
    condition     = contains(["running", "stopped"], var.instance_state)
    error_message = "instance_state must be running or stopped."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.83.0.0/24"
}

variable "subnet_cidr" {
  type    = string
  default = "10.83.0.0/28"
}

variable "root_volume_size_gb" {
  type    = number
  default = 50
  validation {
    condition     = var.root_volume_size_gb >= 30
    error_message = "root_volume_size_gb must be at least 30 GiB."
  }
}

variable "delete_root_volume_on_termination" {
  type    = bool
  default = true
}

variable "https_source_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "enable_acme_http" {
  type    = bool
  default = true
}

variable "telnyx_signaling_cidrs" {
  description = "Current authoritative Telnyx SIP source ranges. Never use 0.0.0.0/0."
  type        = list(string)
  validation {
    condition     = length(var.telnyx_signaling_cidrs) > 0 && !contains(var.telnyx_signaling_cidrs, "0.0.0.0/0")
    error_message = "telnyx_signaling_cidrs must be explicit and non-empty."
  }
}

variable "telnyx_media_cidrs" {
  description = "Current authoritative Telnyx RTP source ranges. Never use 0.0.0.0/0."
  type        = list(string)
  validation {
    condition     = length(var.telnyx_media_cidrs) > 0 && !contains(var.telnyx_media_cidrs, "0.0.0.0/0")
    error_message = "telnyx_media_cidrs must be explicit and non-empty."
  }
}

variable "telnyx_cidr_source_version" {
  type = string
  validation {
    condition     = length(trimspace(var.telnyx_cidr_source_version)) >= 8
    error_message = "telnyx_cidr_source_version must identify the source and observation date."
  }
}

variable "sip_port" {
  type    = number
  default = 5060
}

variable "rtp_port_start" {
  type    = number
  default = 16384
  validation {
    condition     = var.rtp_port_start == 16384
    error_message = "The pinned RVoIP allocator requires rtp_port_start=16384."
  }
}

variable "rtp_port_end" {
  type    = number
  default = 32767
  validation {
    condition     = var.rtp_port_end == 32767
    error_message = "The pinned RVoIP allocator requires rtp_port_end=32767."
  }
}

variable "admin_ssh_cidrs" {
  description = "Optional emergency SSH sources. Empty uses SSM Session Manager only."
  type        = list(string)
  default     = []
  validation {
    condition     = !contains(var.admin_ssh_cidrs, "0.0.0.0/0")
    error_message = "Emergency SSH must never be open to the internet."
  }
}

variable "secret_version_stages" {
  description = "Logical secret ID to admitted stage reference. Terraform creates containers, never values."
  type        = map(string)
  validation {
    condition = length(var.secret_version_stages) > 0 && alltrue([
      for stage in values(var.secret_version_stages) : can(regex("^[A-Z][A-Z0-9_-]{1,63}$", stage))
    ])
    error_message = "Every secret must use an explicit admitted Secrets Manager stage."
  }
}

variable "secrets_kms_key_arn" {
  description = "Optional customer-managed KMS key ARN for secret containers."
  type        = string
  default     = ""
}

variable "secret_recovery_window_days" {
  type    = number
  default = 30
  validation {
    condition     = var.secret_recovery_window_days >= 7 && var.secret_recovery_window_days <= 30
    error_message = "secret_recovery_window_days must be 7-30."
  }
}

variable "create_backup_bucket" {
  type    = bool
  default = true
}

variable "backup_bucket_name" {
  type    = string
  default = ""
}

variable "backup_kms_key_arn" {
  type    = string
  default = ""
}

variable "backup_retention_days" {
  type    = number
  default = 30
  validation {
    condition     = var.backup_retention_days >= 7
    error_message = "backup_retention_days must be at least seven days."
  }
}

variable "enable_backup_object_lock" {
  type    = bool
  default = false
}

variable "enable_cloudwatch_agent" {
  type    = bool
  default = false
}

variable "cloudwatch_agent_package_url" {
  description = "Pinned CloudWatch Agent .deb URL. Required when agent installation is enabled."
  type        = string
  default     = ""
}

variable "cloudwatch_agent_package_sha256" {
  description = "Lowercase SHA-256 of the pinned CloudWatch Agent package."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "route53_zone_id" {
  description = "Optional existing Route 53 hosted zone ID."
  type        = string
  default     = ""
}

variable "domains" {
  description = "Optional app/api/media/sip FQDNs. Required when Route 53 is enabled."
  type        = map(string)
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}
