terraform {
  required_version = ">= 1.7.0"

  # Initialize with an IAM-restricted, versioned GCS state bucket. The module
  # never places application secret values in state, but state still contains
  # infrastructure identifiers and must be protected.
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.39, < 8.1"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
