variable "project_id" {
  description = "Google Cloud project that owns the single-node deployment."
  type        = string
}

variable "region" {
  type    = string
  default = "us-west1"
}

variable "zone" {
  type    = string
  default = "us-west1-b"
}

variable "name" {
  type    = string
  default = "thelve"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,28}[a-z0-9]$", var.name))
    error_message = "name must be a 3-30 character lowercase Google resource prefix."
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

variable "source_image" {
  description = "Exact active Thelve host image from a verified machine-image catalog. Image families are refused."
  type        = string
  validation {
    condition     = can(regex("^projects/[a-z0-9-]+/global/images/[a-zA-Z0-9-]+$", var.source_image))
    error_message = "source_image must be an exact projects/.../global/images/... resource, not a family."
  }
}

variable "compute_profile" {
  description = "Portable Thelve capacity profile. The module owns the exact GCE machine-type mapping."
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

variable "instance_status" {
  description = "RUNNING or TERMINATED. TERMINATED keeps the disk and static address while stopping compute charges."
  type        = string
  default     = "RUNNING"
  validation {
    condition     = contains(["RUNNING", "TERMINATED"], var.instance_status)
    error_message = "instance_status must be RUNNING or TERMINATED."
  }
}

variable "boot_disk_size_gb" {
  type    = number
  default = 50
  validation {
    condition     = var.boot_disk_size_gb >= 30
    error_message = "boot_disk_size_gb must be at least 30 GiB."
  }
}

variable "boot_disk_type" {
  type    = string
  default = "pd-balanced"
  validation {
    condition     = contains(["pd-balanced", "pd-ssd"], var.boot_disk_type)
    error_message = "boot_disk_type must be pd-balanced or pd-ssd."
  }
}

variable "deletion_protection" {
  type    = bool
  default = false
}

variable "subnet_cidr" {
  type    = string
  default = "10.82.0.0/28"
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
  description = "Auditable source/date identifier for the supplied Telnyx ranges."
  type        = string
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

variable "enable_iap_ssh" {
  description = "Allow SSH only through Google IAP. OS Login remains required."
  type        = bool
  default     = true
}

variable "admin_principals" {
  description = "IAM members granted OS Admin Login and IAP tunnel access. Empty means no module-managed interactive login."
  type        = set(string)
  default     = []
}

variable "secret_versions" {
  description = "Logical secret ID to numeric Secret Manager version. Values are references, never payloads."
  type        = map(string)
  validation {
    condition = length(var.secret_versions) > 0 && alltrue([
      for version in values(var.secret_versions) : can(regex("^[1-9][0-9]*$", version))
    ])
    error_message = "Every secret reference must use an explicit numeric version."
  }
}

variable "secret_deletion_protection" {
  type    = bool
  default = true
}

variable "create_backup_bucket" {
  type    = bool
  default = true
}

variable "backup_bucket_name" {
  description = "Optional globally unique bucket name; an empty value derives one from project/name/environment."
  type        = string
  default     = ""
}

variable "backup_retention_days" {
  type    = number
  default = 30
  validation {
    condition     = var.backup_retention_days >= 7
    error_message = "backup_retention_days must be at least seven days."
  }
}

variable "enable_ops_agent" {
  type    = bool
  default = false
}

variable "ops_agent_package_url" {
  description = "Immutable Google Cloud Ops Agent .deb URL. Required when agent installation is enabled."
  type        = string
  default     = ""
}

variable "ops_agent_package_sha256" {
  description = "Lowercase SHA-256 of the pinned Google Cloud Ops Agent package."
  type        = string
  default     = ""
}

variable "dns_managed_zone" {
  description = "Optional existing Cloud DNS managed-zone name. Empty leaves DNS outside this module."
  type        = string
  default     = ""
}

variable "domains" {
  description = "Optional app/api/media/sip FQDNs. Required when dns_managed_zone is set."
  type        = map(string)
  default     = {}
  validation {
    condition     = var.dns_managed_zone == "" || alltrue([for key in ["app", "api", "media", "sip"] : contains(keys(var.domains), key)])
    error_message = "domains must provide app, api, media, and sip when Cloud DNS is enabled."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}
