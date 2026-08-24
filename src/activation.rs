use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

use crate::{
    config::{self, CloudDeployment, Provider},
    preview,
    process::{self, CommandPlan},
    terraform,
};

const MAX_NODE_CONFIG_BYTES: u64 = 1024 * 1024;

pub fn render_node_config(
    config_path: &Path,
    release_root: &Path,
    output: &Path,
    tls_contact_email: &str,
) -> Result<()> {
    let intent = config::load(config_path)?;
    let (receipt, _) = preview::verify_fetched(release_root)?;
    ensure_release_provider(&intent, &receipt)?;
    if output.exists() {
        bail!("refusing to overwrite existing {}", output.display());
    }
    if !valid_email(tls_contact_email) {
        bail!("--tls-contact-email must be a valid operator address");
    }
    let domains = required_domains(&intent)?;
    let outputs = terraform::outputs(config_path, &intent)?;
    let fragment = output_value(&outputs, "node_config_fragment")?.clone();
    let public_ip = output_value(&outputs, "public_ip")?
        .as_str()
        .context("Terraform public_ip output is not a string")?;
    let object_store_url = output_value(&outputs, "backup_destination_url")?
        .as_str()
        .context("Terraform backup_destination_url output is not a string")?
        .trim_end_matches('/');
    if fragment
        .pointer("/networking/advertisedIpv4")
        .and_then(Value::as_str)
        != Some(public_ip)
    {
        bail!("Terraform node fragment and public address disagree");
    }
    let networking = fragment
        .get("networking")
        .cloned()
        .context("Terraform node fragment is missing networking")?;
    let observability = fragment
        .get("observability")
        .cloned()
        .context("Terraform node fragment is missing observability")?;
    let secret_bindings = fragment
        .get("secretBindings")
        .cloned()
        .context("Terraform node fragment is missing secret bindings")?;
    let document = json!({
        "apiVersion": "thelve.io/v1alpha1",
        "kind": "SingleNode",
        "metadata": {"name": intent.metadata.name},
        "spec": {
            "deploymentTarget": "cloud_dedicated",
            "deploymentShape": "single_node",
            "computeProfile": intent.spec.compute_profile,
            "releaseRef": receipt.deployment_release_sha256,
            "domains": domains,
            "networking": networking,
            "data": {
                "postgres": {"mode": "bundled"},
                "redis": {"mode": "bundled"},
                "objects": {"mode": "gcs", "url": format!("{object_store_url}/objects")}
            },
            "identity": {"mode": "preview_demo"},
            "tls": {"mode": "acme", "contactEmail": tls_contact_email},
            "backup": {"destinationRef": "secret://backup/destination", "schedule": "0 3 * * *"},
            "observability": observability,
            "security": {"manageHostFirewall": false},
            "secretBindings": secret_bindings
        }
    });
    let bytes = serde_yaml::to_string(&document)
        .context("serialize single-node activation configuration")?;
    if bytes.len() as u64 > MAX_NODE_CONFIG_BYTES
        || bytes.contains("REPLACE_WITH")
        || bytes.contains("telnyx_api_key")
    {
        bail!("rendered node configuration failed its value-free boundary");
    }
    create_private(output, bytes.as_bytes())?;
    println!(
        "wrote value-free node activation configuration to {}",
        output.display()
    );
    Ok(())
}

pub fn activate_gcp(
    config_path: &Path,
    release_root: &Path,
    node_config_path: &Path,
    receipt_path: &Path,
) -> Result<()> {
    if receipt_path.exists() {
        bail!("refusing to overwrite existing {}", receipt_path.display());
    }
    let intent = config::load(config_path)?;
    let Provider::Gcp {
        project_id, zone, ..
    } = &intent.spec.provider
    else {
        bail!("deploy activate-gcp requires a GCP deployment intent");
    };
    let (release_receipt, _) = preview::verify_fetched(release_root)?;
    ensure_release_provider(&intent, &release_receipt)?;
    let outputs = terraform::outputs(config_path, &intent)?;
    let instance = output_value(&outputs, "instance_name")?
        .as_str()
        .context("Terraform instance_name output is not a string")?;
    let instance_status = output_value(&outputs, "instance_status")?
        .as_str()
        .context("Terraform instance_status output is not a string")?;
    let public_ip = output_value(&outputs, "public_ip")?
        .as_str()
        .context("Terraform public_ip output is not a string")?;
    if instance_status != "RUNNING" {
        bail!("GCP instance is not running; run `thelve deploy up` first");
    }

    let node_config = read_regular_bounded(
        node_config_path,
        MAX_NODE_CONFIG_BYTES,
        "single-node configuration",
    )?;
    validate_node_config(
        &node_config,
        &intent,
        &release_receipt.deployment_release_sha256,
        public_ip,
    )?;

    let local_stage = tempdir().context("create local activation staging directory")?;
    let files = [
        (
            preview::required_file(release_root, "thelve-node")?,
            "thelve-node",
        ),
        (
            preview::required_file(release_root, "thelve-deployment-bundle.tar.gz")?,
            "bundle.tar.gz",
        ),
        (
            preview::required_file(release_root, "offline-trust.json")?,
            "offline-trust.json",
        ),
        (node_config_path.to_path_buf(), "node.yaml"),
    ];
    for (source, name) in &files {
        let destination = local_stage.path().join(name);
        fs::copy(source, &destination).with_context(|| format!("stage activation file {name}"))?;
        #[cfg(unix)]
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
    }

    let operation_id = Uuid::new_v4();
    let stage_name = format!("thelve-activation-{operation_id}");
    let remote_stage = format!("/tmp/{stage_name}");
    let target = format!("{instance}:{remote_stage}/");
    let ssh_base = |command: String| {
        CommandPlan::new("gcloud").args([
            "compute".into(),
            "ssh".into(),
            instance.into(),
            "--project".into(),
            project_id.clone(),
            "--zone".into(),
            zone.clone(),
            "--tunnel-through-iap".into(),
            "--quiet".into(),
            "--command".into(),
            command,
        ])
    };
    process::inherit(&ssh_base(format!(
        "set -eu; umask 077; test ! -e {remote_stage}; mkdir {remote_stage}"
    )))?;

    let result = (|| {
        let mut scp = CommandPlan::new("gcloud").args([
            "compute".into(),
            "scp".into(),
            "--project".into(),
            project_id.clone(),
            "--zone".into(),
            zone.clone(),
            "--tunnel-through-iap".into(),
            "--quiet".into(),
        ]);
        for (_, name) in &files {
            scp = scp.arg(local_stage.path().join(name).display().to_string());
        }
        scp = scp.arg(target);
        process::inherit(&scp)?;

        let node_sha = digest_hex(
            &release_receipt
                .artifacts
                .get("nodeManager")
                .context("release receipt is missing node manager")?
                .sha256,
        )?;
        let bundle_sha = digest_hex(
            &release_receipt
                .artifacts
                .get("deploymentBundle")
                .context("release receipt is missing deployment bundle")?
                .sha256,
        )?;
        let trust_sha = digest_hex(
            &release_receipt
                .artifacts
                .get("offlineTrustStore")
                .context("release receipt is missing offline trust store")?
                .sha256,
        )?;
        let config_sha = format!("{:x}", Sha256::digest(&node_config));
        let remote_command = remote_activation_command(
            &remote_stage,
            operation_id,
            node_sha,
            bundle_sha,
            trust_sha,
            &config_sha,
        );
        let output = process::capture(&ssh_base(remote_command))?;
        let receipt: Value =
            serde_json::from_str(&output).context("remote activation receipt is not JSON")?;
        if receipt.get("schemaVersion").and_then(Value::as_str)
            != Some("thelve.gcp-activation-receipt/v1")
            || receipt.get("secretValuesRecorded").and_then(Value::as_bool) != Some(false)
            || receipt.pointer("/readiness/ready").and_then(Value::as_bool) != Some(true)
        {
            bail!("remote activation did not return a ready, redacted receipt");
        }
        let mut bytes = serde_json::to_vec_pretty(&receipt)?;
        bytes.push(b'\n');
        create_private(receipt_path, &bytes)?;
        println!(
            "GCP node activated and ready; receipt written to {}",
            receipt_path.display()
        );
        Ok(())
    })();
    let _ = process::inherit(&ssh_base(format!(
        "set -eu; case {remote_stage} in /tmp/thelve-activation-*) rm -rf -- {remote_stage} ;; *) exit 1 ;; esac"
    )));
    result
}

fn remote_activation_command(
    stage: &str,
    operation_id: Uuid,
    node_sha: &str,
    bundle_sha: &str,
    trust_sha: &str,
    config_sha: &str,
) -> String {
    format!(
        r#"set -euo pipefail
stage={stage}
cleanup() {{ rm -rf -- "$stage"; }}
trap cleanup EXIT
printf '%s  %s\n' {node_sha} "$stage/thelve-node" | sha256sum --check --strict -
printf '%s  %s\n' {bundle_sha} "$stage/bundle.tar.gz" | sha256sum --check --strict -
printf '%s  %s\n' {trust_sha} "$stage/offline-trust.json" | sha256sum --check --strict -
printf '%s  %s\n' {config_sha} "$stage/node.yaml" | sha256sum --check --strict -
chmod 0700 "$stage/thelve-node"
tar -tzf "$stage/bundle.tar.gz" > "$stage/bundle.list"
test -s "$stage/bundle.list"
awk 'index($0, "/../") || $0 ~ /^\.\.\// || $0 ~ /^\// || $0 !~ /^bundle\// {{ exit 1 }}' "$stage/bundle.list"
mkdir "$stage/release"
tar --no-same-owner --no-same-permissions -xzf "$stage/bundle.tar.gz" -C "$stage/release"
sudo "$stage/thelve-node" verify --bundle "$stage/release/bundle" --trust-store "$stage/offline-trust.json" > "$stage/verify.json"
sudo "$stage/thelve-node" preflight --activation --config "$stage/node.yaml" --bundle "$stage/release/bundle" --trust-store "$stage/offline-trust.json" > "$stage/preflight.json"
sudo "$stage/thelve-node" install --config "$stage/node.yaml" --bundle "$stage/release/bundle" --trust-store "$stage/offline-trust.json" --operation-id {operation_id} > "$stage/install.json"
sudo /opt/thelve/bin/thelve-node activate-secrets --config /etc/thelve/node.yaml > "$stage/secrets.json"
sudo /opt/thelve/bin/thelve-node start > "$stage/start.json"
sudo /opt/thelve/bin/thelve-node readiness > "$stage/readiness.json"
jq -n --arg operationId {operation_id} --slurpfile verify "$stage/verify.json" --slurpfile preflight "$stage/preflight.json" --slurpfile install "$stage/install.json" --slurpfile secrets "$stage/secrets.json" --slurpfile start "$stage/start.json" --slurpfile readiness "$stage/readiness.json" '{{schemaVersion:"thelve.gcp-activation-receipt/v1",operationId:$operationId,verification:$verify[0],preflight:$preflight[0],install:$install[0],secretActivation:$secrets[0],serviceAction:$start[0],readiness:$readiness[0],secretValuesRecorded:false}}'"#
    )
}

fn ensure_release_provider(
    intent: &CloudDeployment,
    receipt: &preview::FetchReceipt,
) -> Result<()> {
    let Provider::Gcp {
        project_id, region, ..
    } = &intent.spec.provider
    else {
        bail!("the fetched private preview is currently GCP-only");
    };
    if project_id != &receipt.project_id || region != &receipt.region {
        bail!("signed preview release and deployment provider do not match");
    }
    Ok(())
}

fn required_domains(intent: &CloudDeployment) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for name in ["app", "api", "media", "sip"] {
        let value = intent
            .spec
            .domains
            .get(name)
            .with_context(|| format!("spec.domains.{name} is required for activation"))?;
        if !valid_fqdn(value) {
            bail!("spec.domains.{name} is not a valid FQDN");
        }
        result.insert(name.into(), value.clone().into());
    }
    if result
        .values()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != 4
    {
        bail!("the four public endpoint domains must be distinct");
    }
    Ok(Value::Object(result))
}

fn validate_node_config(
    bytes: &[u8],
    intent: &CloudDeployment,
    release_sha256: &str,
    public_ip: &str,
) -> Result<()> {
    let value: Value = serde_yaml::from_slice(bytes).context("parse single-node configuration")?;
    if value.get("apiVersion").and_then(Value::as_str) != Some("thelve.io/v1alpha1")
        || value.get("kind").and_then(Value::as_str) != Some("SingleNode")
        || value.pointer("/metadata/name").and_then(Value::as_str)
            != Some(intent.metadata.name.as_str())
        || value.pointer("/spec/releaseRef").and_then(Value::as_str) != Some(release_sha256)
        || value
            .pointer("/spec/networking/advertisedIpv4")
            .and_then(Value::as_str)
            != Some(public_ip)
        || value
            .pointer("/spec/secretBindings")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        bail!("single-node configuration does not match the applied host and signed release");
    }
    Ok(())
}

fn output_value<'a>(outputs: &'a Value, name: &str) -> Result<&'a Value> {
    outputs
        .get(name)
        .and_then(|output| output.get("value"))
        .with_context(|| format!("Terraform output {name:?} is unavailable"))
}

fn read_regular_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("{label} must be a bounded non-empty regular file");
    }
    fs::read(path).with_context(|| format!("read {label}"))
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

fn digest_hex(value: &str) -> Result<&str> {
    let digest = value
        .strip_prefix("sha256:")
        .context("artifact digest is not SHA-256")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("artifact digest is not lowercase SHA-256");
    }
    Ok(digest)
}

fn valid_email(value: &str) -> bool {
    value.len() <= 254
        && !value.chars().any(char::is_whitespace)
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && valid_fqdn(domain))
}

fn valid_fqdn(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_command_carries_only_fixed_paths_ids_and_hashes() {
        let operation = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        let command = remote_activation_command(
            "/tmp/thelve-activation-123e4567-e89b-12d3-a456-426614174000",
            operation,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
        );
        assert!(command.contains("--operation-id 123e4567-e89b-12d3-a456-426614174000"));
        assert!(command.contains("secretValuesRecorded:false"));
        assert!(!command.contains("api-key"));
    }

    #[test]
    fn endpoint_validation_requires_real_fqdns() {
        assert!(valid_fqdn("app.example.com"));
        assert!(!valid_fqdn("localhost"));
        assert!(!valid_email("not-an-email"));
    }
}
