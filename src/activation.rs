use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
    thread,
    time::Duration,
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
const ARTIFACT_REGISTRY_READER_ROLE: &str = "roles/artifactregistry.reader";
const GCP_SSH_READY_ATTEMPTS: u8 = 24;
const GCP_SSH_READY_RETRY_DELAY: Duration = Duration::from_secs(5);
const GCP_ACTIVATION_PREFLIGHT_ATTEMPTS: u8 = 24;
const GCP_ACTIVATION_PREFLIGHT_RETRY_SECONDS: u8 = 5;

#[derive(Debug, Eq, PartialEq)]
struct GcpRegistryTarget {
    host: String,
    repository: String,
    prefix: String,
}

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
    let mut secret_bindings = fragment
        .get("secretBindings")
        .cloned()
        .context("Terraform node fragment is missing secret bindings")?;
    let pinned_secret_count = pin_latest_gcp_secret_versions(
        &mut secret_bindings,
        &intent.spec.provider,
        &intent.spec.secret_names,
    )?;
    let document = json!({
        "apiVersion": "thelve.io/v1alpha1",
        "kind": "SingleNode",
        "metadata": {"name": intent.metadata.name},
        "spec": {
            "deploymentTarget": "cloud_dedicated",
            "deploymentShape": "single_node",
            "computeProfile": intent.spec.compute_profile,
            "releaseRef": receipt.deployment_release_sha256,
            "capacity": {
                "maxConcurrentInboundCalls": intent.spec.max_concurrent_inbound_calls
            },
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
        "wrote value-free node activation configuration to {}; pinned {pinned_secret_count} enabled GCP secret versions",
        output.display(),
    );
    Ok(())
}

fn pin_latest_gcp_secret_versions(
    bindings: &mut Value,
    provider: &Provider,
    expected_names: &[String],
) -> Result<usize> {
    let Provider::Gcp { project_id, .. } = provider else {
        bail!("preview node configuration currently requires a GCP provider");
    };
    pin_gcp_secret_versions_with(bindings, project_id, expected_names, |secret_id| {
        let output = process::capture_named(
            &CommandPlan::new("gcloud").args([
                "secrets",
                "versions",
                "list",
                secret_id,
                "--project",
                project_id,
                "--filter=state=ENABLED",
                "--sort-by=~name",
                "--limit=1",
                "--format=value(name)",
            ]),
            "resolve enabled GCP secret version",
        )?;
        parse_gcp_secret_version(&output)
    })
}

fn pin_gcp_secret_versions_with<F>(
    bindings: &mut Value,
    project_id: &str,
    expected_names: &[String],
    mut resolve: F,
) -> Result<usize>
where
    F: FnMut(&str) -> Result<String>,
{
    let items = bindings
        .as_array_mut()
        .context("Terraform secret bindings output is not an array")?;
    let expected = expected_names
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let mut actual = std::collections::BTreeSet::new();
    for binding in items.iter_mut() {
        let id = binding
            .get("id")
            .and_then(Value::as_str)
            .context("Terraform secret binding has no ID")?;
        if !actual.insert(id.to_owned()) {
            bail!("Terraform secret bindings contain a duplicate ID");
        }
        let source = binding
            .get_mut("source")
            .and_then(Value::as_object_mut)
            .context("Terraform secret binding has no source")?;
        if source.get("provider").and_then(Value::as_str) != Some("gcp_secret_manager")
            || source.get("projectId").and_then(Value::as_str) != Some(project_id)
        {
            bail!("Terraform secret binding is outside the exact GCP project");
        }
        let secret_id = source
            .get("secretId")
            .and_then(Value::as_str)
            .context("Terraform secret binding has no secret ID")?
            .to_owned();
        let version = resolve(&secret_id)?;
        source.insert("version".into(), version.into());
    }
    if actual
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        bail!("Terraform secret bindings do not match the deployment intent");
    }
    Ok(items.len())
}

fn parse_gcp_secret_version(output: &str) -> Result<String> {
    let version = output.trim();
    if version.is_empty()
        || version.len() > 20
        || version == "0"
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("GCP secret has no valid enabled numeric version");
    }
    Ok(version.to_owned())
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
        project_id,
        region,
        zone,
        ..
    } = &intent.spec.provider
    else {
        bail!("deploy activate-gcp requires a GCP deployment intent");
    };
    let (release_receipt, release) = preview::verify_fetched(release_root)?;
    ensure_release_provider(&intent, &release_receipt)?;
    let registry = parse_gcp_registry_prefix(&release.spec.registry_prefix, project_id, region)?;
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
    let runtime_service_account = output_value(&outputs, "runtime_service_account")?
        .as_str()
        .context("Terraform runtime_service_account output is not a string")?;
    if !valid_gcp_service_account(runtime_service_account, project_id) {
        bail!("Terraform runtime_service_account output is not the deployment service account");
    }
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

    wait_for_gcp_ssh(instance, project_id, zone)?;

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
    let ssh_base = |command: String| gcp_activation_ssh_plan(instance, project_id, zone, command);
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
            "--scp-flag=-oConnectTimeout=15".into(),
            "--scp-flag=-oConnectionAttempts=3".into(),
        ]);
        for (_, name) in &files {
            scp = scp.arg(local_stage.path().join(name).display().to_string());
        }
        scp = scp.arg(target);
        process::inherit(&scp)?;

        grant_registry_reader(
            project_id,
            region,
            &registry.repository,
            runtime_service_account,
        )?;

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
            &registry.host,
        );
        let output = process::capture_named(&ssh_base(remote_command), "remote GCP activation")?;
        let mut receipt: Value =
            serde_json::from_str(&output).context("remote activation receipt is not JSON")?;
        if !valid_gcp_activation_receipt(&receipt, &registry.host) {
            bail!("remote activation did not return a ready, redacted receipt");
        }
        let registry_access = receipt
            .pointer_mut("/registryAccess")
            .and_then(Value::as_object_mut)
            .context("remote activation receipt is missing registry access evidence")?;
        registry_access.insert("repository".into(), registry.prefix.clone().into());
        registry_access.insert(
            "runtimeServiceAccount".into(),
            runtime_service_account.into(),
        );
        registry_access.insert("iamRole".into(), ARTIFACT_REGISTRY_READER_ROLE.into());
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

fn valid_gcp_activation_receipt(receipt: &Value, registry_host: &str) -> bool {
    receipt.get("schemaVersion").and_then(Value::as_str) == Some("thelve.gcp-activation-receipt/v1")
        && receipt.get("secretValuesRecorded").and_then(Value::as_bool) == Some(false)
        && receipt
            .pointer("/serviceAction/schemaVersion")
            .and_then(Value::as_str)
            == Some("thelve.single-node-service-action/v1")
        && receipt
            .pointer("/serviceAction/service")
            .and_then(Value::as_str)
            == Some("thelve.service")
        && receipt
            .pointer("/serviceAction/status")
            .and_then(Value::as_str)
            == Some("active")
        && receipt
            .pointer("/serviceAction/action")
            .and_then(Value::as_str)
            .is_some_and(|action| matches!(action, "start" | "restart"))
        && receipt
            .pointer("/serviceAction/completedAt")
            .and_then(Value::as_str)
            .is_some_and(|completed_at| !completed_at.is_empty())
        && receipt
            .pointer("/serviceAction/priorManagedServiceStopped")
            .and_then(Value::as_bool)
            .is_some()
        && receipt
            .pointer("/serviceAction/secretValuesRecorded")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt.pointer("/readiness/status").and_then(Value::as_str) == Some("ready")
        && receipt
            .pointer("/readiness/blockers")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && receipt
            .pointer("/readiness/ingress_configured")
            .and_then(Value::as_bool)
            == Some(true)
        && receipt
            .pointer("/readiness/draining")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .pointer("/registryAccess/host")
            .and_then(Value::as_str)
            == Some(registry_host)
        && receipt
            .pointer("/registryAccess/credentialHelper")
            .and_then(Value::as_str)
            == Some("docker-credential-gcr")
        && receipt
            .pointer("/registryAccess/accessTokenPersisted")
            .and_then(Value::as_bool)
            == Some(false)
}

fn wait_for_gcp_ssh(instance: &str, project_id: &str, zone: &str) -> Result<()> {
    let probe = gcp_ssh_plan(instance, project_id, zone, "true");
    let attempts = retry_until_ready(
        GCP_SSH_READY_ATTEMPTS,
        GCP_SSH_READY_RETRY_DELAY,
        || process::capture(&probe).map(|_| ()),
        |attempt, delay| {
            eprintln!(
                "GCP node SSH is not ready yet (probe {attempt}/{GCP_SSH_READY_ATTEMPTS}); retrying in {} seconds",
                delay.as_secs()
            );
            thread::sleep(delay);
        },
    )
    .context("GCP node did not become reachable through IAP/SSH")?;
    println!("GCP node SSH is ready after {attempts} probe(s)");
    Ok(())
}

fn gcp_ssh_plan(
    instance: &str,
    project_id: &str,
    zone: &str,
    command: impl Into<String>,
) -> CommandPlan {
    CommandPlan::new("gcloud").args([
        "compute".into(),
        "ssh".into(),
        instance.into(),
        "--project".into(),
        project_id.into(),
        "--zone".into(),
        zone.into(),
        "--tunnel-through-iap".into(),
        "--quiet".into(),
        "--ssh-flag=-oBatchMode=yes".into(),
        "--ssh-flag=-oConnectTimeout=5".into(),
        "--ssh-flag=-oConnectionAttempts=1".into(),
        "--command".into(),
        command.into(),
    ])
}

fn gcp_activation_ssh_plan(
    instance: &str,
    project_id: &str,
    zone: &str,
    command: impl Into<String>,
) -> CommandPlan {
    CommandPlan::new("gcloud").args([
        "compute".into(),
        "ssh".into(),
        instance.into(),
        "--project".into(),
        project_id.into(),
        "--zone".into(),
        zone.into(),
        "--tunnel-through-iap".into(),
        "--quiet".into(),
        "--ssh-flag=-oBatchMode=yes".into(),
        "--ssh-flag=-oConnectTimeout=15".into(),
        "--ssh-flag=-oConnectionAttempts=3".into(),
        "--ssh-flag=-oServerAliveInterval=15".into(),
        "--ssh-flag=-oServerAliveCountMax=20".into(),
        "--command".into(),
        command.into(),
    ])
}

fn retry_until_ready<F, W>(attempts: u8, delay: Duration, mut probe: F, mut wait: W) -> Result<u8>
where
    F: FnMut() -> Result<()>,
    W: FnMut(u8, Duration),
{
    if attempts == 0 {
        bail!("readiness retry policy must include at least one attempt");
    }
    for attempt in 1..=attempts {
        match probe() {
            Ok(()) => return Ok(attempt),
            Err(error) if attempt == attempts => return Err(error),
            Err(_) => wait(attempt, delay),
        }
    }
    unreachable!("a positive bounded retry loop always returns")
}

fn remote_activation_command(
    stage: &str,
    operation_id: Uuid,
    node_sha: &str,
    bundle_sha: &str,
    trust_sha: &str,
    config_sha: &str,
    registry_host: &str,
) -> String {
    let preflight_attempts = GCP_ACTIVATION_PREFLIGHT_ATTEMPTS;
    let preflight_retry_seconds = GCP_ACTIVATION_PREFLIGHT_RETRY_SECONDS;
    format!(
        r#"set -Eeuo pipefail
umask 077
ulimit -n 65536
stage={stage}
registry_host={registry_host}
activation_stage=initialization
cleanup() {{ rm -rf -- "$stage" || true; }}
failure() {{ code=$?; printf 'Thelve activation failed at stage %s (exit %s)\n' "$activation_stage" "$code" >&2; exit "$code"; }}
sudo_node() {{ sudo sh -c 'ulimit -n 65536; exec "$@"' thelve-node "$@"; }}
trap failure ERR
trap cleanup EXIT
activation_stage=verify-artifact-digests
printf '%s  %s\n' {node_sha} "$stage/thelve-node" | sha256sum --check --strict - >/dev/null
printf '%s  %s\n' {bundle_sha} "$stage/bundle.tar.gz" | sha256sum --check --strict - >/dev/null
printf '%s  %s\n' {trust_sha} "$stage/offline-trust.json" | sha256sum --check --strict - >/dev/null
printf '%s  %s\n' {config_sha} "$stage/node.yaml" | sha256sum --check --strict - >/dev/null
chmod 0700 "$stage/thelve-node"
activation_stage=inspect-bundle
tar -tzf "$stage/bundle.tar.gz" > "$stage/bundle.list"
tar -tvzf "$stage/bundle.tar.gz" > "$stage/bundle.verbose"
test -s "$stage/bundle.list"
test "$(wc -l < "$stage/bundle.list" | tr -d ' ')" -le 4096
test -z "$(LC_ALL=C sort "$stage/bundle.list" | uniq -d)"
awk 'index($0, "/../") || $0 ~ /^\.\.\// || $0 ~ /^\// || $0 !~ /^bundle\// {{ exit 1 }}' "$stage/bundle.list"
awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" {{ exit 1 }}' "$stage/bundle.verbose"
mkdir "$stage/release"
tar --no-same-owner --no-same-permissions -xzf "$stage/bundle.tar.gz" -C "$stage/release"
activation_stage=verify-release
sudo_node "$stage/thelve-node" verify --bundle "$stage/release/bundle" --trust-store "$stage/offline-trust.json" > "$stage/verify.json"
managed_service_stopped=false
if sudo systemctl is-active --quiet thelve.service; then
  activation_stage=verify-managed-service
  test "$(sudo systemctl show thelve.service --property=FragmentPath --value)" = /etc/systemd/system/thelve.service
  test "$(sudo stat -c '%U:%G:%a' /etc/systemd/system/thelve.service)" = root:root:644
  sudo test -L /opt/thelve/current
  current_release="$(sudo readlink -f -- /opt/thelve/current)"
  case "$current_release" in /opt/thelve/releases/*) ;; *) false ;; esac
  current_release_leaf="${{current_release#/opt/thelve/releases/}}"
  case "$current_release_leaf" in ''|*/*) false ;; esac
  sudo test -d "$current_release"
  sudo_node "$stage/thelve-node" verify --bundle "$current_release/bundle" --trust-store "$stage/offline-trust.json" > "$stage/existing-verify.json"
  current_unit_path="$(sudo jq -er '.spec.artifacts | map(select(.kind == "systemd_unit")) | if length == 1 then .[0].path else error("systemd unit cardinality") end' "$current_release/bundle/deployment.release.json")"
  case "$current_unit_path" in /*|../*|*/../*|*/..) false ;; esac
  sudo cmp --silent -- /etc/systemd/system/thelve.service "$current_release/bundle/$current_unit_path"
  activation_stage=stop-managed-service
  sudo_node "$stage/thelve-node" stop > "$stage/stop.json"
  managed_service_stopped=true
fi
activation_stage=activation-preflight
preflight_attempt=1
while [ "$preflight_attempt" -le {preflight_attempts} ]; do
  if sudo_node "$stage/thelve-node" preflight --activation --config "$stage/node.yaml" --bundle "$stage/release/bundle" --trust-store "$stage/offline-trust.json" > "$stage/preflight.json" 2> "$stage/preflight.stderr"; then
    break
  fi
  if [ "$preflight_attempt" -eq {preflight_attempts} ]; then
    jq -c '{{schemaVersion,activation,activationAllowed,checks,secretValuesRecorded}}' "$stage/preflight.json" >&2 || true
    tail -n 5 "$stage/preflight.stderr" >&2 || true
    false
  fi
  preflight_attempt=$((preflight_attempt + 1))
  sleep {preflight_retry_seconds}
done
activation_stage=install-release
sudo_node "$stage/thelve-node" install --config "$stage/node.yaml" --bundle "$stage/release/bundle" --trust-store "$stage/offline-trust.json" --operation-id {operation_id} > "$stage/install.json"
activation_stage=configure-registry
test -x /usr/local/bin/docker-credential-gcr
sudo grep -Fqx 'Environment=DOCKER_CONFIG=/etc/thelve/docker' /etc/systemd/system/thelve.service
sudo install -d -o root -g root -m 0700 /etc/thelve/docker
sudo grep -Fqx 'Environment=PATH=/usr/local/bin:/usr/bin:/bin' /etc/systemd/system/thelve.service
sudo env HOME=/root DOCKER_CONFIG=/etc/thelve/docker PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/docker-credential-gcr configure-docker --registries="$registry_host" >/dev/null
sudo jq -e --arg host "$registry_host" '((keys - ["auths", "credHelpers"]) | length == 0) and ((.auths // {{}}) | type == "object" and length == 0) and (.credHelpers | type == "object" and length == 1) and .credHelpers[$host] == "gcr"' /etc/thelve/docker/config.json >/dev/null
test "$(sudo stat -c '%U:%G:%a' /etc/thelve/docker/config.json)" = root:root:600
activation_stage=materialize-secrets
sudo_node /opt/thelve/bin/thelve-node activate-secrets --config /etc/thelve/node.yaml > "$stage/secrets.json"
activation_stage=start-services
sudo_node /opt/thelve/bin/thelve-node start > "$stage/start-command.json"
sudo systemctl is-active --quiet thelve.service
jq -n --argjson priorManagedServiceStopped "$managed_service_stopped" --slurpfile command "$stage/start-command.json" '{{schemaVersion:"thelve.single-node-service-action/v1",service:"thelve.service",action:(if $priorManagedServiceStopped then "restart" else "start" end),status:"active",priorManagedServiceStopped:$priorManagedServiceStopped,completedAt:$command[0].completedAt,secretValuesRecorded:false}}' > "$stage/start.json"
activation_stage=verify-readiness
sudo_node /opt/thelve/bin/thelve-node readiness > "$stage/readiness.json"
activation_stage=render-receipt
jq -n --arg operationId {operation_id} --arg registryHost "$registry_host" --slurpfile verify "$stage/verify.json" --slurpfile preflight "$stage/preflight.json" --slurpfile install "$stage/install.json" --slurpfile secrets "$stage/secrets.json" --slurpfile start "$stage/start.json" --slurpfile readiness "$stage/readiness.json" '{{schemaVersion:"thelve.gcp-activation-receipt/v1",operationId:$operationId,verification:$verify[0],preflight:$preflight[0],install:$install[0],secretActivation:$secrets[0],registryAccess:{{host:$registryHost,credentialHelper:"docker-credential-gcr",dockerConfig:"/etc/thelve/docker/config.json",accessTokenPersisted:false}},serviceAction:$start[0],readiness:$readiness[0],secretValuesRecorded:false}}'"#
    )
}

fn grant_registry_reader(
    project_id: &str,
    region: &str,
    repository: &str,
    runtime_service_account: &str,
) -> Result<()> {
    process::inherit(&CommandPlan::new("gcloud").args([
        "artifacts".into(),
        "repositories".into(),
        "add-iam-policy-binding".into(),
        repository.into(),
        "--project".into(),
        project_id.into(),
        "--location".into(),
        region.into(),
        "--member".into(),
        format!("serviceAccount:{runtime_service_account}"),
        "--role".into(),
        ARTIFACT_REGISTRY_READER_ROLE.into(),
        "--condition=None".into(),
        "--quiet".into(),
    ]))
    .context("grant exact Artifact Registry repository read access to the runtime identity")
}

fn parse_gcp_registry_prefix(
    prefix: &str,
    project_id: &str,
    region: &str,
) -> Result<GcpRegistryTarget> {
    let parts = prefix.split('/').collect::<Vec<_>>();
    let expected_host = format!("{region}-docker.pkg.dev");
    if parts.len() != 3
        || parts[0] != expected_host
        || parts[1] != project_id
        || !valid_registry_repository(parts[2])
    {
        bail!("signed preview registry is not the exact deployment repository");
    }
    Ok(GcpRegistryTarget {
        host: parts[0].into(),
        repository: parts[2].into(),
        prefix: prefix.into(),
    })
}

fn valid_registry_repository(value: &str) -> bool {
    value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_gcp_service_account(value: &str, project_id: &str) -> bool {
    let Some(account_id) = value.strip_suffix(&format!("@{project_id}.iam.gserviceaccount.com"))
    else {
        return false;
    };
    (6..=30).contains(&account_id.len())
        && account_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && account_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        && account_id
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
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
            .pointer("/spec/capacity/maxConcurrentInboundCalls")
            .and_then(Value::as_u64)
            != Some(u64::from(intent.spec.max_concurrent_inbound_calls))
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

    fn ready_activation_receipt() -> Value {
        json!({
            "schemaVersion": "thelve.gcp-activation-receipt/v1",
            "serviceAction": {
                "schemaVersion": "thelve.single-node-service-action/v1",
                "service": "thelve.service",
                "action": "restart",
                "status": "active",
                "priorManagedServiceStopped": true,
                "completedAt": "2026-08-25T10:50:28Z",
                "secretValuesRecorded": false
            },
            "readiness": {
                "status": "ready",
                "blockers": [],
                "draining": false,
                "ingress_configured": true,
                "active_connections": 0,
                "max_active_connections": 100,
                "service": "thelve-realtime-gateway"
            },
            "registryAccess": {
                "host": "us-west1-docker.pkg.dev",
                "credentialHelper": "docker-credential-gcr",
                "accessTokenPersisted": false
            },
            "secretValuesRecorded": false
        })
    }

    #[test]
    fn activation_receipt_requires_the_current_ready_gateway_contract() {
        let receipt = ready_activation_receipt();
        assert!(valid_gcp_activation_receipt(
            &receipt,
            "us-west1-docker.pkg.dev"
        ));

        for pointer in [
            "/readiness/status",
            "/readiness/blockers",
            "/readiness/draining",
            "/readiness/ingress_configured",
            "/serviceAction/status",
            "/serviceAction/action",
            "/serviceAction/completedAt",
            "/serviceAction/priorManagedServiceStopped",
            "/serviceAction/secretValuesRecorded",
            "/registryAccess/accessTokenPersisted",
            "/secretValuesRecorded",
        ] {
            let mut invalid = receipt.clone();
            *invalid.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(!valid_gcp_activation_receipt(
                &invalid,
                "us-west1-docker.pkg.dev"
            ));
        }

        let legacy = json!({
            "schemaVersion": "thelve.gcp-activation-receipt/v1",
            "readiness": {"ready": true},
            "registryAccess": {
                "host": "us-west1-docker.pkg.dev",
                "credentialHelper": "docker-credential-gcr",
                "accessTokenPersisted": false
            },
            "secretValuesRecorded": false
        });
        assert!(!valid_gcp_activation_receipt(
            &legacy,
            "us-west1-docker.pkg.dev"
        ));
    }

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
            "us-west1-docker.pkg.dev",
        );
        assert!(command.contains("--operation-id 123e4567-e89b-12d3-a456-426614174000"));
        assert!(command.contains("DOCKER_CONFIG=/etc/thelve/docker"));
        assert!(command.contains("docker-credential-gcr configure-docker"));
        assert!(command.contains("keys - [\"auths\", \"credHelpers\"]"));
        assert!(command.contains("(.auths // {})"));
        assert!(command.contains("length == 0"));
        assert!(command.contains("accessTokenPersisted:false"));
        assert!(command.contains("ulimit -n 65536"));
        assert!(command.contains("sudo_node()"));
        assert!(!command.contains("sudo \"$stage/thelve-node\" preflight"));
        assert!(command.contains("activation_stage=activation-preflight"));
        assert!(command.contains("activation_stage=verify-managed-service"));
        assert!(command.contains("systemctl show thelve.service --property=FragmentPath"));
        assert!(command.contains("verify --bundle \"$current_release/bundle\""));
        assert!(command.contains("current_release_leaf="));
        assert!(command.contains("current_unit_path="));
        assert!(command.contains("cmp --silent -- /etc/systemd/system/thelve.service"));
        assert!(command.contains("activation_stage=stop-managed-service"));
        assert!(command.contains("sudo_node \"$stage/thelve-node\" stop"));
        assert!(command.contains("preflight_attempt=1"));
        assert!(command.contains("while [ \"$preflight_attempt\" -le 24 ]"));
        assert!(command.contains("sleep 5"));
        assert!(command.contains("schemaVersion,activation,activationAllowed,checks"));
        assert!(command.contains("$stage/preflight.stderr"));
        assert!(command.contains("activation_stage=start-services"));
        assert!(command.contains("priorManagedServiceStopped"));
        assert!(command.contains("Thelve activation failed at stage"));
        assert!(command.contains("secretValuesRecorded:false"));
        assert!(!command.contains("api-key"));
        assert!(!command.contains("oauth2accesstoken"));
    }

    #[test]
    fn endpoint_validation_requires_real_fqdns() {
        assert!(valid_fqdn("app.example.com"));
        assert!(!valid_fqdn("localhost"));
        assert!(!valid_email("not-an-email"));
    }

    #[test]
    fn node_config_capacity_must_match_deployment_intent() {
        let intent = CloudDeployment::template(
            crate::config::CloudProvider::Gcp,
            "thelve-test".into(),
            Some("thelve-preview-123456".into()),
            "us-west1".into(),
            "us-west1-b".into(),
        )
        .expect("deployment intent");
        let mut document = json!({
            "apiVersion": "thelve.io/v1alpha1",
            "kind": "SingleNode",
            "metadata": {"name": "thelve-test"},
            "spec": {
                "releaseRef": format!("sha256:{}", "a".repeat(64)),
                "capacity": {"maxConcurrentInboundCalls": 2},
                "networking": {"advertisedIpv4": "203.0.113.10"},
                "secretBindings": [{"id": "database-url"}]
            }
        });
        let release = format!("sha256:{}", "a".repeat(64));
        let bytes = serde_yaml::to_string(&document).expect("node config");
        validate_node_config(bytes.as_bytes(), &intent, &release, "203.0.113.10")
            .expect("matching capacity");

        *document
            .pointer_mut("/spec/capacity/maxConcurrentInboundCalls")
            .expect("capacity") = json!(3);
        let bytes = serde_yaml::to_string(&document).expect("node config");
        assert!(validate_node_config(bytes.as_bytes(), &intent, &release, "203.0.113.10").is_err());
    }

    #[test]
    fn node_config_pins_exact_enabled_gcp_secret_versions() {
        let mut bindings = json!([
            {
                "id": "database-url",
                "source": {
                    "provider": "gcp_secret_manager",
                    "projectId": "thelve-preview-123456",
                    "secretId": "thelve-database-url",
                    "version": "1"
                }
            },
            {
                "id": "realtime-callback-database-url",
                "source": {
                    "provider": "gcp_secret_manager",
                    "projectId": "thelve-preview-123456",
                    "secretId": "thelve-realtime-callback-database-url",
                    "version": "1"
                }
            }
        ]);
        let expected = vec![
            "database-url".to_owned(),
            "realtime-callback-database-url".to_owned(),
        ];
        let count = pin_gcp_secret_versions_with(
            &mut bindings,
            "thelve-preview-123456",
            &expected,
            |secret_id| {
                Ok(if secret_id == "thelve-database-url" {
                    "2".into()
                } else {
                    "7".into()
                })
            },
        )
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            bindings
                .pointer("/0/source/version")
                .and_then(Value::as_str),
            Some("2")
        );
        assert_eq!(
            bindings
                .pointer("/1/source/version")
                .and_then(Value::as_str),
            Some("7")
        );
        assert_eq!(parse_gcp_secret_version("42\n").unwrap(), "42");
        for invalid in ["", "0", "latest", "-1"] {
            assert!(parse_gcp_secret_version(invalid).is_err());
        }
    }

    #[test]
    fn signed_registry_prefix_is_exact_and_argument_safe() {
        let target = parse_gcp_registry_prefix(
            "us-west1-docker.pkg.dev/thelve-preview-123456/thelve-preview",
            "thelve-preview-123456",
            "us-west1",
        )
        .unwrap();
        assert_eq!(target.host, "us-west1-docker.pkg.dev");
        assert_eq!(target.repository, "thelve-preview");
        assert!(
            parse_gcp_registry_prefix(
                "us-west1-docker.pkg.dev/other-project/thelve-preview",
                "thelve-preview-123456",
                "us-west1",
            )
            .is_err()
        );
        assert!(
            parse_gcp_registry_prefix(
                "us-west1-docker.pkg.dev/thelve-preview-123456/repo;id",
                "thelve-preview-123456",
                "us-west1",
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_identity_must_belong_to_exact_project() {
        assert!(valid_gcp_service_account(
            "thelve-test-node@thelve-preview-123456.iam.gserviceaccount.com",
            "thelve-preview-123456"
        ));
        assert!(!valid_gcp_service_account(
            "thelve-test-node@other-project.iam.gserviceaccount.com",
            "thelve-preview-123456"
        ));
    }

    #[test]
    fn gcp_ssh_plan_uses_iap_and_bounded_noninteractive_ssh() {
        let plan = gcp_ssh_plan(
            "thelve-preview-test",
            "thelve-preview-123456",
            "us-west1-b",
            "true",
        );
        assert_eq!(plan.program, "gcloud");
        assert!(
            plan.args
                .windows(2)
                .any(|args| args == ["--project", "thelve-preview-123456"])
        );
        assert!(
            plan.args
                .windows(2)
                .any(|args| args == ["--zone", "us-west1-b"])
        );
        assert!(plan.args.contains(&"--tunnel-through-iap".into()));
        assert!(plan.args.contains(&"--ssh-flag=-oBatchMode=yes".into()));
        assert!(plan.args.contains(&"--ssh-flag=-oConnectTimeout=5".into()));
        assert!(
            plan.args
                .contains(&"--ssh-flag=-oConnectionAttempts=1".into())
        );
        assert_eq!(plan.args.last().map(String::as_str), Some("true"));
    }

    #[test]
    fn gcp_activation_ssh_tolerates_iap_banner_delay_and_keeps_the_session_live() {
        let plan = gcp_activation_ssh_plan(
            "thelve-preview-test",
            "thelve-preview-123456",
            "us-west1-b",
            "true",
        );
        assert!(plan.args.contains(&"--tunnel-through-iap".into()));
        assert!(plan.args.contains(&"--ssh-flag=-oBatchMode=yes".into()));
        assert!(plan.args.contains(&"--ssh-flag=-oConnectTimeout=15".into()));
        assert!(
            plan.args
                .contains(&"--ssh-flag=-oConnectionAttempts=3".into())
        );
        assert!(
            plan.args
                .contains(&"--ssh-flag=-oServerAliveInterval=15".into())
        );
        assert!(
            plan.args
                .contains(&"--ssh-flag=-oServerAliveCountMax=20".into())
        );
        assert_eq!(plan.args.last().map(String::as_str), Some("true"));
    }

    #[test]
    fn readiness_retry_stops_on_success_without_sleeping_afterward() {
        let mut probes = 0;
        let mut waits = Vec::new();
        let succeeded_at = retry_until_ready(
            4,
            Duration::from_secs(5),
            || {
                probes += 1;
                if probes < 3 {
                    bail!("not ready")
                }
                Ok(())
            },
            |attempt, delay| waits.push((attempt, delay)),
        )
        .unwrap();
        assert_eq!(succeeded_at, 3);
        assert_eq!(probes, 3);
        assert_eq!(
            waits,
            vec![(1, Duration::from_secs(5)), (2, Duration::from_secs(5))]
        );
    }

    #[test]
    fn readiness_retry_returns_the_final_probe_error() {
        let error =
            retry_until_ready(2, Duration::ZERO, || bail!("still booting"), |_, _| {}).unwrap_err();
        assert_eq!(error.to_string(), "still booting");
        assert!(retry_until_ready(0, Duration::ZERO, || Ok(()), |_, _| {}).is_err());
    }
}
