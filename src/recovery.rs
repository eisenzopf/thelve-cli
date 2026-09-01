use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tempfile::tempdir;
use uuid::Uuid;

use crate::{
    activation,
    config::{self, CloudDeployment, Provider},
    preview, process,
    process::CommandPlan,
    terraform,
};

const BACKUP_SCHEMA: &str = "thelve.single-node-backup/v1";
const RESTORE_SCHEMA: &str = "thelve.single-node-restore/v1";
const REPLACEMENT_CHECKPOINT_SCHEMA: &str = "thelve.gcp-node-replacement-checkpoint/v1";
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;

pub fn create_backup(config_path: &Path, release_root: &Path, output: &Path) -> Result<()> {
    if output.exists() {
        bail!("refusing to overwrite existing {}", output.display());
    }
    let intent = config::load(config_path)?;
    require_gcp(&intent)?;
    let (target_release, _) = preview::verify_fetched(release_root)?;
    ensure_release_project(&intent, &target_release)?;
    let backup_id = Uuid::new_v4();
    let remote = format!("sudo /opt/thelve/bin/thelve-backup create --backup-id {backup_id}");
    let value = capture_receipt(config_path, remote, "create encrypted single-node backup")?;
    validate_backup_receipt(&value, backup_id, false)?;
    create_private(output, &serde_json::to_vec_pretty(&value)?)?;
    println!(
        "backup {backup_id} created and receipt written to {}",
        output.display()
    );
    Ok(())
}

pub fn verify_backup(config_path: &Path, backup_id: Uuid) -> Result<Value> {
    let intent = config::load(config_path)?;
    require_gcp(&intent)?;
    let remote = format!("sudo /opt/thelve/bin/thelve-backup verify --backup-id {backup_id}");
    let value = capture_receipt(config_path, remote, "verify encrypted single-node backup")?;
    validate_backup_receipt(&value, backup_id, true)?;
    Ok(value)
}

pub fn restore_backup(
    config_path: &Path,
    release_root: &Path,
    backup_id: Uuid,
    output: &Path,
) -> Result<()> {
    if output.exists() {
        bail!("refusing to overwrite existing {}", output.display());
    }
    let intent = config::load(config_path)?;
    require_gcp(&intent)?;
    let (target_release, _) = preview::verify_fetched(release_root)?;
    ensure_release_project(&intent, &target_release)?;
    verify_backup(config_path, backup_id)?;

    let restore = restore_on_active_node(
        config_path,
        backup_id,
        &target_release.deployment_release_sha256,
    )?;
    let mut bytes = serde_json::to_vec_pretty(&restore)?;
    bytes.push(b'\n');
    create_private(output, &bytes)?;
    println!(
        "backup {backup_id} restored and receipt written to {}",
        output.display()
    );
    Ok(())
}

pub fn replace_gcp_node(
    config_path: &Path,
    release_root: &Path,
    backup_id: Uuid,
    receipt_path: &Path,
) -> Result<()> {
    if receipt_path.exists() {
        bail!("refusing to overwrite existing {}", receipt_path.display());
    }
    let checkpoint_path = replacement_checkpoint_path(receipt_path);
    let intent = config::load(config_path)?;
    require_gcp(&intent)?;
    let (target_release, _) = preview::verify_fetched(release_root)?;
    ensure_release_project(&intent, &target_release)?;
    let backup = verify_backup(config_path, backup_id)?;
    let (checkpoint, resumed) = if checkpoint_path.exists() {
        let checkpoint = read_replacement_checkpoint(&checkpoint_path)?;
        let current = cloud_identity(config_path, &intent)?;
        validate_replacement_checkpoint(
            &checkpoint,
            &intent.metadata.name,
            backup_id,
            &target_release.release,
            &target_release.deployment_release_sha256,
            &current,
        )?;
        eprintln!(
            "resuming the already-applied node replacement from {} without replacing compute again",
            checkpoint_path.display()
        );
        (checkpoint, true)
    } else {
        let tls_contact_email = activation::capture_gcp_remote(
            config_path,
            "sudo awk '$1 == \"contactEmail:\" {print $2; exit}' /etc/thelve/node.yaml",
            "read non-secret TLS contact from current node",
        )?;
        let tls_contact_email = tls_contact_email.trim();
        if !activation::valid_email(tls_contact_email) {
            bail!("current node has no valid TLS contact email");
        }

        let before = cloud_identity(config_path, &intent)?;
        let applied = terraform::replace_gcp_node(config_path)?;
        let after = cloud_identity(config_path, &intent)?;
        validate_replacement_identities(&before, &after, &applied)?;
        let checkpoint = json!({
            "schemaVersion": REPLACEMENT_CHECKPOINT_SCHEMA,
            "deployment": intent.metadata.name,
            "backupId": backup_id,
            "targetRelease": target_release.release,
            "targetDeploymentReleaseSha256": target_release.deployment_release_sha256,
            "tlsContactEmail": tls_contact_email,
            "createdAt": chrono::Utc::now(),
            "before": before,
            "after": after,
            "terraform": applied,
            "secretValuesRecorded": false
        });
        create_private(&checkpoint_path, &serde_json::to_vec_pretty(&checkpoint)?)?;
        (checkpoint, false)
    };

    let tls_contact_email = checkpoint
        .get("tlsContactEmail")
        .and_then(Value::as_str)
        .context("replacement checkpoint is missing the TLS contact email")?;
    let before = checkpoint
        .get("before")
        .cloned()
        .context("replacement checkpoint is missing the prior cloud identity")?;
    let after = checkpoint
        .get("after")
        .cloned()
        .context("replacement checkpoint is missing the replacement cloud identity")?;
    let applied = checkpoint
        .get("terraform")
        .cloned()
        .context("replacement checkpoint is missing Terraform evidence")?;

    let completion = (|| -> Result<(Value, Value)> {
        let working = tempdir().context("create private replacement workspace")?;
        let node_config = working.path().join("node.yaml");
        let activation_receipt = working.path().join("activation-receipt.json");
        activation::render_node_config(config_path, release_root, &node_config, tls_contact_email)?;
        activation::activate_gcp(config_path, release_root, &node_config, &activation_receipt)?;

        let restore = restore_on_active_node(
            config_path,
            backup_id,
            &target_release.deployment_release_sha256,
        )?;
        let activation: Value = serde_json::from_slice(
            &fs::read(&activation_receipt).context("read activation receipt")?,
        )
        .context("parse activation receipt")?;
        Ok((activation, restore))
    })();
    let (activation, restore) = completion.map_err(|error| {
        error.context(format!(
            "replacement checkpoint {} was retained; rerun the exact replace-node command to resume without replacing compute again",
            checkpoint_path.display()
        ))
    })?;
    let completed_at = chrono::Utc::now();
    let receipt = json!({
        "schemaVersion": "thelve.gcp-node-replacement/v1",
        "deployment": intent.metadata.name,
        "backupId": backup_id,
        "targetRelease": target_release.release,
        "targetDeploymentReleaseSha256": target_release.deployment_release_sha256,
        "completedAt": completed_at,
        "before": before,
        "after": after,
        "terraform": applied,
        "backup": {
            "archiveSha256": backup.pointer("/archive/sha256"),
            "verified": true,
            "retained": true
        },
        "activation": {
            "operationId": activation.get("operationId"),
            "ready": activation_is_ready(&activation),
            "secretValuesRecorded": false
        },
        "restore": restore,
        "orchestrationResumed": resumed,
        "staticAddressRetained": true,
        "networkRetained": true,
        "backupBucketRetained": true,
        "runtimeIdentityRetained": true,
        "secretContainersRetained": true,
        "carrierResourcesManagedOutsideTerraform": true,
        "secretValuesRecorded": false
    });
    create_private(receipt_path, &serde_json::to_vec_pretty(&receipt)?)?;
    if let Err(error) = fs::remove_file(&checkpoint_path) {
        eprintln!(
            "warning: replacement completed but stale checkpoint {} could not be removed: {error}",
            checkpoint_path.display()
        );
    }
    println!(
        "replacement node restored and ready; receipt written to {}",
        receipt_path.display()
    );
    Ok(())
}

fn replacement_checkpoint_path(receipt_path: &Path) -> PathBuf {
    let mut value = receipt_path.as_os_str().to_os_string();
    value.push(".pending");
    PathBuf::from(value)
}

fn read_replacement_checkpoint(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect replacement checkpoint {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RECEIPT_BYTES as u64
    {
        bail!("replacement checkpoint is not a bounded regular file");
    }
    let bytes = fs::read(path)
        .with_context(|| format!("read replacement checkpoint {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parse replacement checkpoint")
}

fn validate_replacement_checkpoint(
    checkpoint: &Value,
    deployment: &str,
    backup_id: Uuid,
    target_release: &str,
    target_deployment_release_sha256: &str,
    current: &Value,
) -> Result<()> {
    let backup_id_string = backup_id.to_string();
    let valid_header = checkpoint.get("schemaVersion").and_then(Value::as_str)
        == Some(REPLACEMENT_CHECKPOINT_SCHEMA)
        && checkpoint.get("deployment").and_then(Value::as_str) == Some(deployment)
        && checkpoint.get("backupId").and_then(Value::as_str) == Some(backup_id_string.as_str())
        && checkpoint.get("targetRelease").and_then(Value::as_str) == Some(target_release)
        && checkpoint
            .get("targetDeploymentReleaseSha256")
            .and_then(Value::as_str)
            == Some(target_deployment_release_sha256)
        && checkpoint
            .get("secretValuesRecorded")
            .and_then(Value::as_bool)
            == Some(false)
        && checkpoint
            .get("tlsContactEmail")
            .and_then(Value::as_str)
            .is_some_and(activation::valid_email);
    if !valid_header {
        bail!("replacement checkpoint does not match this deployment, backup, and release");
    }
    let before = checkpoint
        .get("before")
        .context("replacement checkpoint is missing prior cloud identity")?;
    let after = checkpoint
        .get("after")
        .context("replacement checkpoint is missing replacement cloud identity")?;
    let applied = checkpoint
        .get("terraform")
        .context("replacement checkpoint is missing Terraform evidence")?;
    validate_replacement_identities(before, after, applied)?;
    for field in [
        "instanceId",
        "bootDiskId",
        "instanceName",
        "publicIp",
        "staticAddressId",
        "networkId",
        "subnetworkId",
        "backupBucket",
        "backupBucketIdentity",
        "runtimeServiceAccount",
        "secretResources",
        "stateBucket",
        "statePrefix",
    ] {
        if after.get(field) != current.get(field) {
            bail!("current cloud identity {field:?} does not match the pending replacement");
        }
    }
    if current.get("instanceStatus").and_then(Value::as_str) != Some("RUNNING") {
        bail!("pending replacement node must be running before orchestration can resume");
    }
    Ok(())
}

fn restore_on_active_node(
    config_path: &Path,
    backup_id: Uuid,
    target_release: &str,
) -> Result<Value> {
    let restore_command = format!("sudo /opt/thelve/bin/thelve-restore --backup-id {backup_id}");
    let result = capture_receipt(
        config_path,
        restore_command,
        "restore verified backup on active node",
    )
    .and_then(|value| {
        validate_restore_receipt(&value, backup_id, target_release)?;
        Ok(value)
    });
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let _ = activation::capture_gcp_remote(
                config_path,
                "sudo systemctl stop thelve.service",
                "fail-close node after restore failure",
            );
            Err(error.context("node was left fail-closed; retained backup was not deleted"))
        }
    }
}

fn capture_receipt(config_path: &Path, remote_command: String, label: &str) -> Result<Value> {
    let output = activation::capture_gcp_remote(config_path, remote_command, label)?;
    if output.is_empty() || output.len() > MAX_RECEIPT_BYTES {
        bail!("{label} returned an empty or oversized receipt");
    }
    serde_json::from_str(&output).with_context(|| format!("{label} did not return JSON"))
}

fn validate_backup_receipt(value: &Value, backup_id: Uuid, verified: bool) -> Result<()> {
    let valid = value.get("schemaVersion").and_then(Value::as_str) == Some(BACKUP_SCHEMA)
        && value.get("backupId").and_then(Value::as_str) == Some(backup_id.to_string().as_str())
        && value.get("encryptedAtRest").and_then(Value::as_bool) == Some(true)
        && value.get("redisIncluded").and_then(Value::as_bool) == Some(false)
        && value.get("secretsIncluded").and_then(Value::as_bool) == Some(false)
        && value.get("secretValuesRecorded").and_then(Value::as_bool) == Some(false)
        && value
            .pointer("/archive/sha256")
            .and_then(Value::as_str)
            .is_some_and(valid_sha256)
        && value.pointer("/database/format").and_then(Value::as_str) == Some("postgres-custom")
        && (!verified || value.get("verified").and_then(Value::as_bool) == Some(true));
    if !valid {
        bail!("remote backup receipt failed the recovery contract");
    }
    Ok(())
}

fn validate_restore_receipt(value: &Value, backup_id: Uuid, target_release: &str) -> Result<()> {
    let valid = value.get("schemaVersion").and_then(Value::as_str) == Some(RESTORE_SCHEMA)
        && value.get("backupId").and_then(Value::as_str) == Some(backup_id.to_string().as_str())
        && value.get("databaseRestored").and_then(Value::as_bool) == Some(true)
        && value
            .get("objectsRestoredOrRetained")
            .and_then(Value::as_bool)
            == Some(true)
        && value.get("migrationsApplied").and_then(Value::as_bool) == Some(true)
        && value.pointer("/readiness/status").and_then(Value::as_str) == Some("ready")
        && value
            .pointer("/readiness/blockers")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && value
            .get("targetDeploymentReleaseSha256")
            .and_then(Value::as_str)
            == Some(target_release)
        && value.get("secretsRestored").and_then(Value::as_bool) == Some(false)
        && value.get("secretValuesRecorded").and_then(Value::as_bool) == Some(false);
    if !valid {
        bail!("remote restore receipt failed the recovery contract");
    }
    Ok(())
}

fn activation_is_ready(value: &Value) -> bool {
    value.pointer("/readiness/status").and_then(Value::as_str) == Some("ready")
}

fn cloud_identity(config_path: &Path, intent: &CloudDeployment) -> Result<Value> {
    let Provider::Gcp {
        project_id,
        region,
        zone,
        ..
    } = &intent.spec.provider
    else {
        bail!("cloud identity inspection requires GCP");
    };
    let outputs = terraform::outputs(config_path, intent)?;
    let instance_name = output_string(&outputs, "instance_name")?;
    let instance_text = process::capture_named(
        &CommandPlan::new("gcloud").args([
            "compute",
            "instances",
            "describe",
            instance_name,
            "--project",
            project_id,
            "--zone",
            zone,
            "--format=json(id,name,status,disks,networkInterfaces,serviceAccounts)",
        ]),
        "inspect GCP instance identity",
    )?;
    let instance: Value =
        serde_json::from_str(&instance_text).context("parse GCP instance identity")?;
    let disk_source = instance
        .pointer("/disks/0/source")
        .and_then(Value::as_str)
        .context("GCP instance has no boot disk source")?;
    let disk_name = disk_source
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .context("GCP boot disk source is malformed")?;
    let disk_text = process::capture_named(
        &CommandPlan::new("gcloud").args([
            "compute",
            "disks",
            "describe",
            disk_name,
            "--project",
            project_id,
            "--zone",
            zone,
            "--format=json(id,name,selfLink)",
        ]),
        "inspect GCP boot disk identity",
    )?;
    let disk: Value = serde_json::from_str(&disk_text).context("parse GCP boot disk identity")?;
    let resource_prefix = format!("{}-{}", intent.metadata.name, intent.spec.environment);
    let network = gcloud_json(
        [
            "compute",
            "networks",
            "describe",
            &format!("{resource_prefix}-network"),
            "--project",
            project_id,
            "--format=json(id,name,selfLink)",
        ],
        "inspect retained GCP network identity",
    )?;
    let subnetwork = gcloud_json(
        [
            "compute",
            "networks",
            "subnets",
            "describe",
            &format!("{resource_prefix}-{region}"),
            "--project",
            project_id,
            "--region",
            region,
            "--format=json(id,name,selfLink)",
        ],
        "inspect retained GCP subnetwork identity",
    )?;
    let address = gcloud_json(
        [
            "compute",
            "addresses",
            "describe",
            &format!("{resource_prefix}-ipv4"),
            "--project",
            project_id,
            "--region",
            region,
            "--format=json(id,name,address,selfLink)",
        ],
        "inspect retained GCP static address identity",
    )?;
    let backup_bucket = output_string(&outputs, "backup_bucket")?;
    let bucket = gcloud_json(
        [
            "storage",
            "buckets",
            "describe",
            &format!("gs://{backup_bucket}"),
            "--format=json(name,location,metageneration)",
        ],
        "inspect retained GCP backup bucket identity",
    )?;
    Ok(json!({
        "instanceId": instance.get("id"),
        "instanceName": instance.get("name"),
        "instanceStatus": instance.get("status"),
        "bootDiskId": disk.get("id"),
        "bootDiskName": disk.get("name"),
        "publicIp": output_json(&outputs, "public_ip")?,
        "staticAddressId": address.get("id"),
        "networkId": network.get("id"),
        "subnetworkId": subnetwork.get("id"),
        "backupBucket": output_json(&outputs, "backup_bucket")?,
        "backupBucketIdentity": bucket,
        "runtimeServiceAccount": output_json(&outputs, "runtime_service_account")?,
        "secretResources": output_json(&outputs, "secret_resources")?,
        "stateBucket": intent.spec.state.bucket,
        "statePrefix": intent.spec.state.prefix,
        "secretValuesRecorded": false
    }))
}

fn validate_replacement_identities(before: &Value, after: &Value, applied: &Value) -> Result<()> {
    if before.get("instanceId") == after.get("instanceId")
        || before.get("bootDiskId") == after.get("bootDiskId")
    {
        bail!("replacement did not change both instance and boot disk identity");
    }
    for field in [
        "instanceName",
        "publicIp",
        "staticAddressId",
        "networkId",
        "subnetworkId",
        "backupBucket",
        "backupBucketIdentity",
        "runtimeServiceAccount",
        "secretResources",
        "stateBucket",
        "statePrefix",
    ] {
        if before.get(field) != after.get(field) {
            bail!("preserved cloud identity {field:?} changed during replacement");
        }
    }
    if after.get("instanceStatus").and_then(Value::as_str) != Some("RUNNING")
        || applied
            .get("exactResourceReplacement")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("replacement node is not a running exact-resource replacement");
    }
    Ok(())
}

fn require_gcp(intent: &CloudDeployment) -> Result<()> {
    if !matches!(intent.spec.provider, Provider::Gcp { .. }) {
        bail!("this recovery release currently supports GCP single-node deployments");
    }
    Ok(())
}

fn ensure_release_project(intent: &CloudDeployment, receipt: &preview::FetchReceipt) -> Result<()> {
    let Provider::Gcp {
        project_id, region, ..
    } = &intent.spec.provider
    else {
        bail!("signed private release is currently GCP-only");
    };
    if project_id != &receipt.project_id || region != &receipt.region {
        bail!("signed release project and region do not match the deployment intent");
    }
    Ok(())
}

fn output_string<'a>(outputs: &'a Value, name: &str) -> Result<&'a str> {
    output_json(outputs, name)?
        .as_str()
        .with_context(|| format!("Terraform output {name:?} is not a string"))
}

fn output_json<'a>(outputs: &'a Value, name: &str) -> Result<&'a Value> {
    outputs
        .get(name)
        .and_then(|value| value.get("value"))
        .with_context(|| format!("Terraform output {name:?} is unavailable"))
}

fn gcloud_json<I, S>(arguments: I, label: &str) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let output = process::capture_named(&CommandPlan::new("gcloud").args(arguments), label)?;
    serde_json::from_str(&output).with_context(|| format!("parse {label}"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?
        .write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup(verified: bool) -> Value {
        json!({
            "schemaVersion": BACKUP_SCHEMA,
            "backupId": "223e4567-e89b-42d3-a456-426614174000",
            "archive": {"sha256": format!("sha256:{}", "a".repeat(64))},
            "database": {"format": "postgres-custom"},
            "encryptedAtRest": true,
            "redisIncluded": false,
            "secretsIncluded": false,
            "secretValuesRecorded": false,
            "verified": verified
        })
    }

    fn restore(readiness: Value) -> Value {
        json!({
            "schemaVersion": RESTORE_SCHEMA,
            "backupId": "223e4567-e89b-42d3-a456-426614174000",
            "databaseRestored": true,
            "objectsRestoredOrRetained": true,
            "migrationsApplied": true,
            "readiness": readiness,
            "targetDeploymentReleaseSha256": format!("sha256:{}", "b".repeat(64)),
            "secretsRestored": false,
            "secretValuesRecorded": false
        })
    }

    #[test]
    fn backup_receipt_requires_verification_and_secret_exclusion() {
        let id = Uuid::parse_str("223e4567-e89b-42d3-a456-426614174000").unwrap();
        assert!(validate_backup_receipt(&backup(true), id, true).is_ok());
        assert!(validate_backup_receipt(&backup(false), id, true).is_err());
        let mut unsafe_receipt = backup(true);
        unsafe_receipt["secretsIncluded"] = true.into();
        assert!(validate_backup_receipt(&unsafe_receipt, id, true).is_err());
    }

    #[test]
    fn replacement_requires_new_compute_and_stable_retained_identity() {
        let before = json!({
            "instanceId":"1", "bootDiskId":"2", "instanceName":"node",
            "publicIp":"203.0.113.2", "staticAddressId":"ip", "networkId":"net",
            "subnetworkId":"subnet", "backupBucket":"backup", "backupBucketIdentity":{"name":"backup"},
            "runtimeServiceAccount":"node@example.test", "secretResources":{"a":"a"},
            "stateBucket":"state", "statePrefix":"prefix"
        });
        let after = json!({
            "instanceId":"3", "bootDiskId":"4", "instanceName":"node",
            "instanceStatus":"RUNNING", "publicIp":"203.0.113.2", "staticAddressId":"ip",
            "networkId":"net", "subnetworkId":"subnet", "backupBucket":"backup",
            "backupBucketIdentity":{"name":"backup"}, "runtimeServiceAccount":"node@example.test",
            "secretResources":{"a":"a"}, "stateBucket":"state", "statePrefix":"prefix"
        });
        let applied = json!({"exactResourceReplacement":true});
        assert!(validate_replacement_identities(&before, &after, &applied).is_ok());
        let mut wrong = after;
        wrong["publicIp"] = "203.0.113.9".into();
        assert!(validate_replacement_identities(&before, &wrong, &applied).is_err());
    }

    #[test]
    fn replacement_checkpoint_resumes_only_the_exact_applied_replacement() {
        let backup_id = Uuid::parse_str("223e4567-e89b-42d3-a456-426614174000").unwrap();
        let before = json!({
            "instanceId":"1", "bootDiskId":"2", "instanceName":"node",
            "instanceStatus":"RUNNING", "publicIp":"203.0.113.2", "staticAddressId":"ip",
            "networkId":"net", "subnetworkId":"subnet", "backupBucket":"backup",
            "backupBucketIdentity":{"name":"backup"}, "runtimeServiceAccount":"node@example.test",
            "secretResources":{"a":"a"}, "stateBucket":"state", "statePrefix":"prefix",
            "secretValuesRecorded":false
        });
        let after = json!({
            "instanceId":"3", "bootDiskId":"4", "instanceName":"node",
            "instanceStatus":"RUNNING", "publicIp":"203.0.113.2", "staticAddressId":"ip",
            "networkId":"net", "subnetworkId":"subnet", "backupBucket":"backup",
            "backupBucketIdentity":{"name":"backup"}, "runtimeServiceAccount":"node@example.test",
            "secretResources":{"a":"a"}, "stateBucket":"state", "statePrefix":"prefix",
            "secretValuesRecorded":false
        });
        let release_sha = format!("sha256:{}", "b".repeat(64));
        let checkpoint = json!({
            "schemaVersion":REPLACEMENT_CHECKPOINT_SCHEMA,
            "deployment":"preview",
            "backupId":backup_id,
            "targetRelease":"0.1.0-preview.47",
            "targetDeploymentReleaseSha256":release_sha,
            "tlsContactEmail":"operator@example.test",
            "before":before,
            "after":after,
            "terraform":{"exactResourceReplacement":true},
            "secretValuesRecorded":false
        });
        assert!(
            validate_replacement_checkpoint(
                &checkpoint,
                "preview",
                backup_id,
                "0.1.0-preview.47",
                &release_sha,
                &after,
            )
            .is_ok()
        );

        let mut wrong_node = after.clone();
        wrong_node["instanceId"] = "5".into();
        assert!(
            validate_replacement_checkpoint(
                &checkpoint,
                "preview",
                backup_id,
                "0.1.0-preview.47",
                &release_sha,
                &wrong_node,
            )
            .is_err()
        );

        let mut unsafe_checkpoint = checkpoint;
        unsafe_checkpoint["secretValuesRecorded"] = true.into();
        assert!(
            validate_replacement_checkpoint(
                &unsafe_checkpoint,
                "preview",
                backup_id,
                "0.1.0-preview.47",
                &release_sha,
                &after,
            )
            .is_err()
        );
    }

    #[test]
    fn replacement_checkpoint_uses_a_distinct_sibling_path() {
        assert_eq!(
            replacement_checkpoint_path(Path::new("receipts/replacement.json")),
            PathBuf::from("receipts/replacement.json.pending")
        );
    }

    #[test]
    fn replacement_projects_the_current_activation_readiness_contract() {
        let ready = json!({"readiness":{"status":"ready"}});
        assert!(activation_is_ready(&ready));

        for stale_or_failed in [
            json!({"readiness":{"ready":true}}),
            json!({"readiness":{"status":"blocked"}}),
            json!({}),
        ] {
            assert!(!activation_is_ready(&stale_or_failed));
        }
    }

    #[test]
    fn restore_requires_the_current_gateway_readiness_contract() {
        let id = Uuid::parse_str("223e4567-e89b-42d3-a456-426614174000").unwrap();
        let release = format!("sha256:{}", "b".repeat(64));
        assert!(
            validate_restore_receipt(
                &restore(json!({"status":"ready", "blockers":[]})),
                id,
                &release,
            )
            .is_ok()
        );
        for stale_or_blocked in [
            json!({"ready":true}),
            json!({"status":"ready", "blockers":["database"]}),
            json!({"status":"blocked", "blockers":[]}),
        ] {
            assert!(validate_restore_receipt(&restore(stale_or_blocked), id, &release).is_err());
        }
    }
}
