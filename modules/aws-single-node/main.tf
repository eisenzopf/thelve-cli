data "aws_caller_identity" "current" {}

locals {
  prefix          = "${var.name}-${var.environment}"
  compute_catalog = jsondecode(file("${path.module}/contracts/single-node-compute-profiles-v1.json"))
  compute         = local.compute_catalog.profiles[var.compute_profile]
  tags = merge(var.tags, {
    Application     = "thelve"
    DeploymentShape = "single-node"
    Environment     = var.environment
    ComputeProfile  = var.compute_profile
    ManagedBy       = "terraform"
  })
  backup_bucket_name = var.backup_bucket_name != "" ? var.backup_bucket_name : "${local.prefix}-${data.aws_caller_identity.current.account_id}-${var.region}-backup"
}

resource "aws_vpc" "thelve" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_internet_gateway" "thelve" {
  vpc_id = aws_vpc.thelve.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_subnet" "thelve" {
  vpc_id                  = aws_vpc.thelve.id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.prefix}-subnet" }
}

resource "aws_route_table" "thelve" {
  vpc_id = aws_vpc.thelve.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.thelve.id
  }
  tags = { Name = "${local.prefix}-routes" }
}

resource "aws_route_table_association" "thelve" {
  subnet_id      = aws_subnet.thelve.id
  route_table_id = aws_route_table.thelve.id
}

resource "aws_security_group" "thelve" {
  name        = "${local.prefix}-node"
  description = "Direct HTTPS, Telnyx SIP, and Telnyx RTP for Thelve single-node"
  vpc_id      = aws_vpc.thelve.id
  tags        = { Name = "${local.prefix}-node" }
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  for_each          = toset(var.https_source_cidrs)
  security_group_id = aws_security_group.thelve.id
  description       = "HTTPS and browser WebRTC signaling"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "acme_http" {
  count             = var.enable_acme_http ? 1 : 0
  security_group_id = aws_security_group.thelve.id
  description       = "ACME HTTP challenge"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "telnyx_sip" {
  for_each          = toset(var.telnyx_signaling_cidrs)
  security_group_id = aws_security_group.thelve.id
  description       = "Telnyx SIP signaling"
  ip_protocol       = "udp"
  from_port         = var.sip_port
  to_port           = var.sip_port
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "telnyx_rtp" {
  for_each          = toset(var.telnyx_media_cidrs)
  security_group_id = aws_security_group.thelve.id
  description       = "Telnyx RTP media"
  ip_protocol       = "udp"
  from_port         = var.rtp_port_start
  to_port           = var.rtp_port_end
  cidr_ipv4         = each.value
}

# Telnyx's default AnchorSite=Latency selection measures round-trip time from
# its media network with ICMP. Admit all ICMP types/codes only from the exact
# carrier media ranges; this keeps regional media selection automatic without
# exposing host-wide ICMP to the Internet.
resource "aws_vpc_security_group_ingress_rule" "telnyx_anchorsite_icmp" {
  for_each          = toset(var.telnyx_media_cidrs)
  security_group_id = aws_security_group.thelve.id
  description       = "Telnyx AnchorSite latency probe"
  ip_protocol       = "icmp"
  from_port         = -1
  to_port           = -1
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "emergency_ssh" {
  for_each          = toset(var.admin_ssh_cidrs)
  security_group_id = aws_security_group.thelve.id
  description       = "Restricted emergency SSH; prefer SSM"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.thelve.id
  description       = "DNS, NTP, HTTPS, OIDC, object storage, and carrier responses"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_secretsmanager_secret" "runtime" {
  for_each                = var.secret_version_stages
  name                    = "${local.prefix}/${each.key}"
  description             = "Thelve single-node ${each.key}; value managed outside Terraform"
  kms_key_id              = var.secrets_kms_key_arn != "" ? var.secrets_kms_key_arn : null
  recovery_window_in_days = var.secret_recovery_window_days
}

data "aws_iam_policy_document" "secret_transport" {
  for_each = aws_secretsmanager_secret.runtime
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["secretsmanager:*"]
    resources = [each.value.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "runtime" {
  for_each            = aws_secretsmanager_secret.runtime
  secret_arn          = each.value.arn
  policy              = data.aws_iam_policy_document.secret_transport[each.key].json
  block_public_policy = true
}

resource "aws_s3_bucket" "backup" {
  count               = var.create_backup_bucket ? 1 : 0
  bucket              = local.backup_bucket_name
  object_lock_enabled = var.enable_backup_object_lock
}

resource "aws_s3_bucket_public_access_block" "backup" {
  count                   = var.create_backup_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.backup[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "backup" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "backup" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.backup_kms_key_arn == "" ? "AES256" : "aws:kms"
      kms_master_key_id = var.backup_kms_key_arn == "" ? null : var.backup_kms_key_arn
    }
    bucket_key_enabled = var.backup_kms_key_arn != ""
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backup" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  rule {
    id     = "backup-retention"
    status = "Enabled"
    filter { prefix = "single-node/" }
    expiration { days = var.backup_retention_days * 2 }
    noncurrent_version_expiration { noncurrent_days = var.backup_retention_days * 2 }
  }
  depends_on = [aws_s3_bucket_versioning.backup]
}

resource "aws_s3_bucket_object_lock_configuration" "backup" {
  count  = var.create_backup_bucket && var.enable_backup_object_lock ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.backup_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.backup]
}

resource "aws_cloudwatch_log_group" "thelve" {
  count             = var.enable_cloudwatch_agent ? 1 : 0
  name              = "/thelve/${local.prefix}/journald"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "node" {
  name = "${local.prefix}-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "node" {
  statement {
    sid       = "ReadExactRuntimeSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = values(aws_secretsmanager_secret.runtime)[*].arn
  }

  dynamic "statement" {
    for_each = var.secrets_kms_key_arn == "" ? [] : [var.secrets_kms_key_arn]
    content {
      sid       = "DecryptRuntimeSecrets"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${var.region}.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.create_backup_bucket ? [aws_s3_bucket.backup[0].arn] : []
    content {
      sid       = "ListBackupPrefix"
      effect    = "Allow"
      actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
      resources = [statement.value]
      condition {
        test     = "StringLike"
        variable = "s3:prefix"
        values   = ["single-node", "single-node/*"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.create_backup_bucket ? [aws_s3_bucket.backup[0].arn] : []
    content {
      sid       = "ManageBackupObjects"
      effect    = "Allow"
      actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"]
      resources = ["${statement.value}/single-node/*"]
    }
  }

  dynamic "statement" {
    for_each = var.backup_kms_key_arn == "" ? [] : [var.backup_kms_key_arn]
    content {
      sid       = "EncryptBackups"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
      resources = [statement.value]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${var.region}.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_cloudwatch_agent ? [aws_cloudwatch_log_group.thelve[0].arn] : []
    content {
      sid       = "WriteThelveLogGroup"
      effect    = "Allow"
      actions   = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
      resources = ["${statement.value}:*"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_cloudwatch_agent ? [1] : []
    content {
      sid       = "WriteThelveMetrics"
      effect    = "Allow"
      actions   = ["cloudwatch:PutMetricData"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = ["Thelve/SingleNode"]
      }
    }
  }
}

resource "aws_iam_role_policy" "node" {
  name   = "${local.prefix}-exact-runtime-access"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.node.json
}

resource "aws_iam_instance_profile" "node" {
  name = "${local.prefix}-node"
  role = aws_iam_role.node.name
}

resource "aws_instance" "thelve" {
  ami                         = var.ami_id
  instance_type               = local.compute.providers.aws.instanceType
  availability_zone           = var.availability_zone
  subnet_id                   = aws_subnet.thelve.id
  vpc_security_group_ids      = [aws_security_group.thelve.id]
  iam_instance_profile        = aws_iam_instance_profile.node.name
  associate_public_ip_address = false
  source_dest_check           = true
  monitoring                  = true
  ebs_optimized               = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = var.root_volume_size_gb
    iops                  = 3000
    throughput            = 125
    delete_on_termination = var.delete_root_volume_on_termination
  }

  user_data = templatefile("${path.module}/startup.sh.tftpl", {
    region                          = var.region
    enable_cloudwatch_agent         = var.enable_cloudwatch_agent
    cloudwatch_agent_package_url    = var.cloudwatch_agent_package_url
    cloudwatch_agent_package_sha256 = var.cloudwatch_agent_package_sha256
    cloudwatch_log_group            = var.enable_cloudwatch_agent ? aws_cloudwatch_log_group.thelve[0].name : ""
  })
  user_data_replace_on_change = true

  lifecycle {
    precondition {
      condition     = var.environment != "production" || local.compute.production
      error_message = "environment=production requires production_baseline or production_growth."
    }
    precondition {
      condition     = !var.enable_cloudwatch_agent || (can(regex("^https://", var.cloudwatch_agent_package_url)) && can(regex("^[0-9a-f]{64}$", var.cloudwatch_agent_package_sha256)))
      error_message = "CloudWatch Agent requires a pinned HTTPS package URL and SHA-256."
    }
  }

  depends_on = [
    aws_iam_role_policy.node,
    aws_secretsmanager_secret_policy.runtime,
    aws_route_table_association.thelve
  ]
  tags = { Name = local.prefix }
}

resource "aws_eip" "thelve" {
  domain   = "vpc"
  instance = aws_instance.thelve.id
  tags     = { Name = "${local.prefix}-ipv4" }
}

resource "aws_ec2_instance_state" "thelve" {
  instance_id = aws_instance.thelve.id
  state       = var.instance_state
}

resource "aws_route53_record" "thelve" {
  for_each = var.route53_zone_id == "" ? {} : var.domains
  zone_id  = var.route53_zone_id
  name     = trimsuffix(each.value, ".")
  type     = "A"
  ttl      = 60
  records  = [aws_eip.thelve.public_ip]
}

check "compute_catalog_contract" {
  assert {
    condition = (
      local.compute_catalog.schemaVersion == "thelve.single-node-compute-profiles/v1" &&
      local.compute.vcpu >= 2 &&
      local.compute.memoryMiB >= 8192 &&
      (
        startswith(local.compute.providers.aws.instanceType, "t3.") ||
        startswith(local.compute.providers.aws.instanceType, "m7i.")
      )
    )
    error_message = "The selected compute profile is incompatible with this AWS adapter."
  }
}

check "availability_zone_matches_region" {
  assert {
    condition     = can(regex("^${var.region}([a-z]|-[a-z0-9-]+)$", var.availability_zone))
    error_message = "availability_zone must belong to region."
  }
}

check "route53_domains" {
  assert {
    condition     = var.route53_zone_id == "" || alltrue([for key in ["app", "api", "media", "sip"] : contains(keys(var.domains), key)])
    error_message = "domains must provide app, api, media, and sip when Route 53 is enabled."
  }
}
