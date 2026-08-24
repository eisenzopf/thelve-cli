output "public_ip" {
  value = aws_eip.thelve.public_ip
}

output "instance_id" {
  value = aws_instance.thelve.id
}

output "instance_state" {
  value = var.instance_state
}

output "compute_profile" {
  value = {
    profile       = var.compute_profile
    instance_type = local.compute.providers.aws.instanceType
    vcpu          = local.compute.vcpu
    memory_mib    = local.compute.memoryMiB
    production    = local.compute.production
  }
}

output "ssm_start_session_command" {
  value = "aws ssm start-session --region ${var.region} --target ${aws_instance.thelve.id}"
}

output "backup_bucket" {
  value = var.create_backup_bucket ? aws_s3_bucket.backup[0].bucket : null
}

output "backup_destination_url" {
  value = var.create_backup_bucket ? "s3://${aws_s3_bucket.backup[0].bucket}/single-node" : null
}

output "secret_arns" {
  value = { for logical_id, secret in aws_secretsmanager_secret.runtime : logical_id => secret.arn }
}

output "node_config_fragment" {
  value = {
    deploymentTarget = "cloud_dedicated"
    deploymentShape  = "single_node"
    computeProfile   = var.compute_profile
    networking = {
      advertisedIpv4       = aws_eip.thelve.public_ip
      sipPort              = var.sip_port
      rtpStart             = var.rtp_port_start
      rtpEnd               = var.rtp_port_end
      telnyxSignalingCidrs = var.telnyx_signaling_cidrs
      telnyxMediaCidrs     = var.telnyx_media_cidrs
      cidrSourceVersion    = var.telnyx_cidr_source_version
    }
    observability = {
      localRetentionDays = 7
      export             = var.enable_cloudwatch_agent ? "aws_cloudwatch" : "none"
    }
    secretBindings = [
      for logical_id in sort(keys(var.secret_version_stages)) : {
        id = logical_id
        source = {
          provider     = "aws_secrets_manager"
          secretArn    = aws_secretsmanager_secret.runtime[logical_id].arn
          versionStage = var.secret_version_stages[logical_id]
        }
      }
    ]
  }
}

output "secret_values_recorded" {
  value = false
}
