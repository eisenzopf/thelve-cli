locals {
  prefix          = "${var.name}-${var.environment}"
  compute_catalog = jsondecode(file("${path.module}/contracts/single-node-compute-profiles-v1.json"))
  compute         = local.compute_catalog.profiles[var.compute_profile]
  labels = merge(var.labels, {
    application      = "thelve"
    deployment_shape = "single-node"
    environment      = var.environment
    compute_profile  = var.compute_profile
    managed_by       = "terraform"
  })
  services = toset(compact([
    "compute.googleapis.com",
    "iam.googleapis.com",
    "secretmanager.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "osconfig.googleapis.com",
    var.dns_managed_zone == "" ? "" : "dns.googleapis.com"
  ]))
  backup_bucket_name = var.backup_bucket_name != "" ? var.backup_bucket_name : "${var.project_id}-${local.prefix}-backup"
  admin_bindings = {
    for pair in setproduct(var.admin_principals, toset([
      "roles/compute.osAdminLogin",
      "roles/iap.tunnelResourceAccessor"
      ])) : "${pair[0]}|${pair[1]}" => {
      member = pair[0]
      role   = pair[1]
    }
  }
}

resource "google_project_service" "required" {
  for_each           = local.services
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_compute_network" "thelve" {
  name                    = "${local.prefix}-network"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.required]
}

resource "google_compute_subnetwork" "thelve" {
  name                     = "${local.prefix}-${var.region}"
  region                   = var.region
  network                  = google_compute_network.thelve.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_address" "thelve" {
  name         = "${local.prefix}-ipv4"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
  depends_on   = [google_project_service.required]
}

resource "google_compute_firewall" "https" {
  name          = "${local.prefix}-https"
  network       = google_compute_network.thelve.name
  direction     = "INGRESS"
  source_ranges = var.https_source_cidrs
  target_tags   = [local.prefix]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "acme_http" {
  count         = var.enable_acme_http ? 1 : 0
  name          = "${local.prefix}-acme-http"
  network       = google_compute_network.thelve.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.prefix]
  allow {
    protocol = "tcp"
    ports    = ["80"]
  }
}

resource "google_compute_firewall" "telnyx_sip" {
  name          = "${local.prefix}-telnyx-sip"
  network       = google_compute_network.thelve.name
  direction     = "INGRESS"
  source_ranges = var.telnyx_signaling_cidrs
  target_tags   = [local.prefix]
  allow {
    protocol = "udp"
    ports    = [tostring(var.sip_port)]
  }
}

resource "google_compute_firewall" "telnyx_rtp" {
  name          = "${local.prefix}-telnyx-rtp"
  network       = google_compute_network.thelve.name
  direction     = "INGRESS"
  source_ranges = var.telnyx_media_cidrs
  target_tags   = [local.prefix]
  allow {
    protocol = "udp"
    ports    = ["${var.rtp_port_start}-${var.rtp_port_end}"]
  }
}

# Telnyx's default AnchorSite=Latency selection measures round-trip time from
# its media network with ICMP. Limit echo traffic to the same explicit carrier
# ranges as RTP so automatic nearest-PoP selection works without opening ICMP
# globally.
resource "google_compute_firewall" "telnyx_anchorsite_icmp" {
  name          = "${local.prefix}-telnyx-icmp"
  network       = google_compute_network.thelve.name
  direction     = "INGRESS"
  source_ranges = var.telnyx_media_cidrs
  target_tags   = [local.prefix]
  allow {
    protocol = "icmp"
  }
}

resource "google_compute_firewall" "iap_ssh" {
  count         = var.enable_iap_ssh ? 1 : 0
  name          = "${local.prefix}-iap-ssh"
  network       = google_compute_network.thelve.name
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = [local.prefix]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_service_account" "node" {
  account_id   = substr(replace("${local.prefix}-node", "_", "-"), 0, 30)
  display_name = "Thelve ${var.environment} single-node runtime"
  depends_on   = [google_project_service.required]
}

resource "google_secret_manager_secret" "runtime" {
  for_each            = var.secret_versions
  project             = var.project_id
  secret_id           = "${local.prefix}-${replace(each.key, "/", "-")}"
  labels              = local.labels
  deletion_protection = var.secret_deletion_protection
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

# Access is bound on each named secret. The node receives no project-level
# Secret Manager role and Terraform deliberately creates no secret versions.
resource "google_secret_manager_secret_iam_member" "node_access" {
  for_each  = google_secret_manager_secret.runtime
  project   = var.project_id
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.node.email}"
}

resource "google_storage_bucket" "backup" {
  count                       = var.create_backup_bucket ? 1 : 0
  name                        = local.backup_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = local.labels

  versioning { enabled = true }
  retention_policy {
    retention_period = var.backup_retention_days * 86400
  }
  lifecycle_rule {
    condition { age = var.backup_retention_days * 2 }
    action { type = "Delete" }
  }
  depends_on = [google_project_service.required]
}

resource "google_storage_bucket_iam_member" "node_backup" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = google_storage_bucket.backup[0].name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.node.email}"
}

resource "google_project_iam_member" "ops_agent" {
  for_each = var.enable_ops_agent ? toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter"
  ]) : toset([])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.node.email}"
}

resource "google_project_iam_member" "administrators" {
  for_each = local.admin_bindings
  project  = var.project_id
  role     = each.value.role
  member   = each.value.member
}

resource "google_compute_instance" "thelve" {
  name                      = local.prefix
  zone                      = var.zone
  machine_type              = local.compute.providers.gcp.machineType
  desired_status            = var.instance_status
  allow_stopping_for_update = true
  deletion_protection       = var.deletion_protection
  tags                      = [local.prefix]
  labels                    = local.labels

  boot_disk {
    auto_delete = !var.deletion_protection
    initialize_params {
      image  = var.source_image
      size   = var.boot_disk_size_gb
      type   = var.boot_disk_type
      labels = local.labels
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.thelve.id
    nic_type   = "GVNIC"
    access_config {
      nat_ip       = google_compute_address.thelve.address
      network_tier = "PREMIUM"
    }
  }

  metadata = {
    enable-oslogin         = "TRUE"
    enable-osconfig        = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
  }
  metadata_startup_script = templatefile("${path.module}/startup.sh.tftpl", {
    enable_ops_agent         = var.enable_ops_agent
    ops_agent_package_url    = var.ops_agent_package_url
    ops_agent_package_sha256 = var.ops_agent_package_sha256
  })

  service_account {
    email  = google_service_account.node.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  lifecycle {
    precondition {
      condition     = !var.enable_ops_agent || (can(regex("^https://", var.ops_agent_package_url)) && can(regex("^[0-9a-f]{64}$", var.ops_agent_package_sha256)))
      error_message = "Google Cloud Ops Agent requires a pinned HTTPS package URL and SHA-256."
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.node_access,
    google_project_iam_member.ops_agent
  ]
}

resource "google_dns_record_set" "thelve" {
  for_each     = var.dns_managed_zone == "" ? {} : var.domains
  managed_zone = var.dns_managed_zone
  name         = "${trimsuffix(each.value, ".")}."
  type         = "A"
  ttl          = 60
  rrdatas      = [google_compute_address.thelve.address]
  depends_on   = [google_project_service.required]
}

check "production_profile" {
  assert {
    condition     = var.environment != "production" || local.compute.production
    error_message = "environment=production requires production_baseline or production_growth."
  }
}

check "compute_catalog_contract" {
  assert {
    condition = (
      local.compute_catalog.schemaVersion == "thelve.single-node-compute-profiles/v1" &&
      local.compute.vcpu >= 2 &&
      local.compute.memoryMiB >= 8192 &&
      (
        startswith(local.compute.providers.gcp.machineType, "e2-") ||
        startswith(local.compute.providers.gcp.machineType, "n2-")
      )
    )
    error_message = "The selected compute profile is incompatible with this GCP adapter."
  }
}

check "zone_matches_region" {
  assert {
    condition     = startswith(var.zone, "${var.region}-")
    error_message = "zone must belong to region."
  }
}
