output "public_ip" {
  value = google_compute_address.thelve.address
}

output "network_id" {
  value = google_compute_network.thelve.id
}

output "subnetwork_id" {
  value = google_compute_subnetwork.thelve.id
}

output "static_address_id" {
  value = google_compute_address.thelve.id
}

output "instance_name" {
  value = google_compute_instance.thelve.name
}

output "instance_id" {
  value = google_compute_instance.thelve.instance_id
}

output "boot_disk_name" {
  value = google_compute_instance.thelve.boot_disk[0].device_name
}

output "instance_status" {
  value = var.instance_status
}

output "compute_profile" {
  value = {
    profile      = var.compute_profile
    machine_type = local.compute.providers.gcp.machineType
    vcpu         = local.compute.vcpu
    memory_mib   = local.compute.memoryMiB
    production   = local.compute.production
  }
}

output "runtime_service_account" {
  value = google_service_account.node.email
}

output "backup_bucket" {
  value = var.create_backup_bucket ? google_storage_bucket.backup[0].name : null
}

output "backup_bucket_id" {
  value = var.create_backup_bucket ? google_storage_bucket.backup[0].id : null
}

output "backup_destination_url" {
  value = var.create_backup_bucket ? "gs://${google_storage_bucket.backup[0].name}/single-node" : null
}

output "secret_resources" {
  value = { for logical_id, secret in google_secret_manager_secret.runtime : logical_id => secret.id }
}

output "node_config_fragment" {
  value = {
    deploymentTarget = "cloud_dedicated"
    deploymentShape  = "single_node"
    computeProfile   = var.compute_profile
    networking = {
      advertisedIpv4       = google_compute_address.thelve.address
      sipPort              = var.sip_port
      rtpStart             = var.rtp_port_start
      rtpEnd               = var.rtp_port_end
      webrtcStart          = var.webrtc_port_start
      webrtcEnd            = var.webrtc_port_end
      webrtcMediaCidrs     = var.webrtc_media_cidrs
      telnyxSignalingCidrs = var.telnyx_signaling_cidrs
      telnyxMediaCidrs     = var.telnyx_media_cidrs
      cidrSourceVersion    = var.telnyx_cidr_source_version
    }
    observability = {
      localRetentionDays = 7
      export             = var.enable_ops_agent ? "gcp_ops_agent" : "none"
    }
    secretBindings = [
      for logical_id in sort(keys(var.secret_versions)) : {
        id = logical_id
        source = {
          provider  = "gcp_secret_manager"
          projectId = var.project_id
          secretId  = google_secret_manager_secret.runtime[logical_id].secret_id
          version   = var.secret_versions[logical_id]
        }
      }
    ]
  }
}

output "secret_values_recorded" {
  value = false
}
