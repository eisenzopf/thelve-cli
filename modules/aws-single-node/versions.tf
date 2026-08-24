terraform {
  required_version = ">= 1.7.0"

  # Initialize with an encrypted, versioned S3 backend and DynamoDB/S3 lock
  # posture appropriate to your Terraform version and organization policy.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = local.tags
  }
}
