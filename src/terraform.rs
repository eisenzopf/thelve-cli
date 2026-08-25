use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use include_dir::{Dir, include_dir};

use crate::{
    config::{CloudDeployment, CloudProvider, Provider, load},
    process::{self, CommandPlan},
};

static GCP_MODULE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/modules/gcp-single-node");
static AWS_MODULE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/modules/aws-single-node");
const COMPUTE_CATALOG: &[u8] = include_bytes!("../contracts/single-node-compute-profiles-v1.json");
const BACKEND_ARGS_FILE: &str = ".thelve-backend-args.json";
const LEGACY_BACKEND_BLOCK_FILE: &str = "backend.auto.tf.json";

#[derive(Clone, Copy, Debug)]
pub enum HostState {
    Running,
    Stopped,
}

pub fn iac_binary() -> Result<String> {
    if let Ok(value) = env::var("THELVE_IAC_BIN")
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    for candidate in ["tofu", "terraform"] {
        if std::process::Command::new(candidate)
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(candidate.into());
        }
    }
    bail!("OpenTofu or Terraform is required; set THELVE_IAC_BIN to an audited compatible runner")
}

pub fn workspace(config_path: &Path, intent: &CloudDeployment) -> Result<PathBuf> {
    let parent = config_path
        .canonicalize()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .or_else(|| config_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(parent.join(".thelve").join("workspaces").join(format!(
        "{}-{}",
        intent.metadata.name,
        intent.spec.provider.kind()
    )))
}

pub fn plan(config_path: &Path, state: HostState) -> Result<()> {
    let intent = load(config_path)?;
    let directory = prepare_workspace(config_path, &intent, state)?;
    init(&directory)?;
    let binary = iac_binary()?;
    process::inherit(&CommandPlan::new(binary).args([
        format!("-chdir={}", directory.display()),
        "plan".into(),
        "-input=false".into(),
        "-lock-timeout=5m".into(),
        "-no-color".into(),
        "-out=thelve.tfplan".into(),
    ]))?;
    println!(
        "plan saved locally at {} (contains no application secret values)",
        directory.join("thelve.tfplan").display()
    );
    Ok(())
}

pub fn apply(config_path: &Path, state: HostState, destroy: bool) -> Result<()> {
    let intent = load(config_path)?;
    let directory = prepare_workspace(config_path, &intent, state)?;
    init(&directory)?;
    let binary = iac_binary()?;
    if destroy {
        process::inherit(&CommandPlan::new(&binary).args([
            format!("-chdir={}", directory.display()),
            "plan".into(),
            "-destroy".into(),
            "-input=false".into(),
            "-lock-timeout=5m".into(),
            "-no-color".into(),
            "-out=thelve-destroy.tfplan".into(),
        ]))?;
        process::inherit(&CommandPlan::new(binary).args([
            format!("-chdir={}", directory.display()),
            "apply".into(),
            "-input=false".into(),
            "-lock-timeout=5m".into(),
            "-no-color".into(),
            "thelve-destroy.tfplan".into(),
        ]))?;
        println!("destroy completed for {}", intent.metadata.name);
        return Ok(());
    }
    process::inherit(&CommandPlan::new(&binary).args([
        format!("-chdir={}", directory.display()),
        "plan".into(),
        "-input=false".into(),
        "-lock-timeout=5m".into(),
        "-no-color".into(),
        "-out=thelve.tfplan".into(),
    ]))?;
    process::inherit(&CommandPlan::new(binary).args([
        format!("-chdir={}", directory.display()),
        "apply".into(),
        "-input=false".into(),
        "-lock-timeout=5m".into(),
        "-no-color".into(),
        "thelve.tfplan".into(),
    ]))?;
    Ok(())
}

pub fn status(config_path: &Path) -> Result<()> {
    let intent = load(config_path)?;
    let value = outputs(config_path, &intent)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub fn outputs(config_path: &Path, intent: &CloudDeployment) -> Result<serde_json::Value> {
    let directory = prepare_workspace(config_path, intent, HostState::Running)?;
    init(&directory)?;
    let output = process::capture(&CommandPlan::new(iac_binary()?).args([
        format!("-chdir={}", directory.display()),
        "output".into(),
        "-json".into(),
    ]))?;
    serde_json::from_str(&output).context("parse Terraform output document")
}

pub fn secret_resources(
    directory: &Path,
    provider: CloudProvider,
) -> Result<BTreeMap<String, String>> {
    init(directory)?;
    let output_name = match provider {
        CloudProvider::Gcp => "secret_resources",
        CloudProvider::Aws => "secret_arns",
    };
    let output = process::capture(&CommandPlan::new(iac_binary()?).args([
        format!("-chdir={}", directory.display()),
        "output".into(),
        "-json".into(),
        output_name.into(),
    ]))?;
    serde_json::from_str(&output).context("parse Terraform secret resource output")
}

fn init(directory: &Path) -> Result<()> {
    let backend_bytes = fs::read(directory.join(BACKEND_ARGS_FILE)).with_context(|| {
        format!(
            "read generated backend configuration {}",
            directory.join(BACKEND_ARGS_FILE).display()
        )
    })?;
    let backend_args: Vec<String> =
        serde_json::from_slice(&backend_bytes).context("parse generated backend configuration")?;
    let mut args = vec![
        format!("-chdir={}", directory.display()),
        "init".into(),
        "-input=false".into(),
        "-no-color".into(),
    ];
    args.extend(backend_args);
    process::inherit(&CommandPlan::new(iac_binary()?).args(args))
}

fn prepare_workspace(
    config_path: &Path,
    intent: &CloudDeployment,
    state: HostState,
) -> Result<PathBuf> {
    let directory = workspace(config_path, intent)?;
    fs::create_dir_all(&directory)
        .with_context(|| format!("create IaC workspace {}", directory.display()))?;
    let module = match intent.spec.provider.kind() {
        CloudProvider::Gcp => &GCP_MODULE,
        CloudProvider::Aws => &AWS_MODULE,
    };
    materialize(module, &directory)?;
    let contracts = directory.join("contracts");
    fs::create_dir_all(&contracts)?;
    write_if_changed(
        &contracts.join("single-node-compute-profiles-v1.json"),
        COMPUTE_CATALOG,
    )?;
    // Old preview builds wrote a complete backend declaration beside the
    // module's own `backend "gcs" {}` / `backend "s3" {}` declaration.
    // Terraform correctly rejects two declarations, so remove only that exact
    // generated legacy file during the idempotent workspace refresh.
    let legacy_backend = directory.join(LEGACY_BACKEND_BLOCK_FILE);
    if legacy_backend.exists() {
        fs::remove_file(&legacy_backend)
            .with_context(|| format!("remove legacy backend block {}", legacy_backend.display()))?;
    }
    write_if_changed(
        &directory.join(BACKEND_ARGS_FILE),
        &serde_json::to_vec_pretty(&backend_args(intent))?,
    )?;
    let variables = variables(intent, state);
    write_if_changed(
        &directory.join("deployment.auto.tfvars.json"),
        &serde_json::to_vec_pretty(&variables)?,
    )?;
    Ok(directory)
}

fn materialize(module: &Dir<'_>, destination: &Path) -> Result<()> {
    for file in module.files() {
        let target = destination.join(file.path());
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        write_if_changed(&target, file.contents())?;
    }
    Ok(())
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if fs::read(path).ok().as_deref() != Some(bytes) {
        fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

fn backend_args(intent: &CloudDeployment) -> Vec<String> {
    match &intent.spec.provider {
        Provider::Gcp { .. } => vec![
            format!("-backend-config=bucket={}", intent.spec.state.bucket),
            format!("-backend-config=prefix={}", intent.spec.state.prefix),
        ],
        Provider::Aws { region, .. } => vec![
            format!("-backend-config=bucket={}", intent.spec.state.bucket),
            format!(
                "-backend-config=key={}/terraform.tfstate",
                intent.spec.state.prefix.trim_end_matches('/')
            ),
            format!("-backend-config=region={region}"),
            "-backend-config=encrypt=true".into(),
            "-backend-config=use_lockfile=true".into(),
        ],
    }
}

fn variables(intent: &CloudDeployment, state: HostState) -> serde_json::Value {
    let networking = &intent.spec.networking;
    let common = serde_json::json!({
        "name": intent.metadata.name,
        "environment": intent.spec.environment.to_string(),
        "compute_profile": intent.spec.compute_profile,
        "telnyx_cidr_source_version": networking.telnyx_cidr_source_version,
        "telnyx_signaling_cidrs": networking.telnyx_signaling_cidrs,
        "telnyx_media_cidrs": networking.telnyx_media_cidrs,
        "https_source_cidrs": networking.https_source_cidrs,
        "sip_port": networking.sip_port,
        "rtp_port_start": networking.rtp_port_start,
        "rtp_port_end": networking.rtp_port_end,
        "webrtc_port_start": networking.webrtc_port_start,
        "webrtc_port_end": networking.webrtc_port_end,
        "webrtc_media_cidrs": networking.webrtc_media_cidrs,
        "domains": intent.spec.domains,
    });
    let mut value = common.as_object().cloned().expect("JSON object");
    match &intent.spec.provider {
        Provider::Gcp {
            project_id,
            region,
            zone,
            admin_principals,
            dns_managed_zone,
            ops_agent_package,
        } => {
            value.insert("project_id".into(), project_id.clone().into());
            value.insert("region".into(), region.clone().into());
            value.insert("zone".into(), zone.clone().into());
            value.insert("source_image".into(), intent.spec.host_image.clone().into());
            value.insert(
                "instance_status".into(),
                match state {
                    HostState::Running => "RUNNING",
                    HostState::Stopped => "TERMINATED",
                }
                .into(),
            );
            value.insert(
                "deletion_protection".into(),
                intent.spec.deletion_protection.into(),
            );
            value.insert(
                "admin_principals".into(),
                serde_json::json!(admin_principals),
            );
            value.insert("dns_managed_zone".into(), dns_managed_zone.clone().into());
            value.insert(
                "enable_ops_agent".into(),
                ops_agent_package.is_some().into(),
            );
            value.insert(
                "ops_agent_package_url".into(),
                ops_agent_package
                    .as_ref()
                    .map_or("", |package| package.url.as_str())
                    .into(),
            );
            value.insert(
                "ops_agent_package_sha256".into(),
                ops_agent_package
                    .as_ref()
                    .map_or("", |package| package.sha256.as_str())
                    .into(),
            );
            value.insert(
                "secret_versions".into(),
                serde_json::json!(
                    intent
                        .spec
                        .secret_names
                        .iter()
                        .map(|name| (name.clone(), "1"))
                        .collect::<BTreeMap<_, _>>()
                ),
            );
        }
        Provider::Aws {
            region,
            availability_zone,
            route53_zone_id,
            cloudwatch_agent_package,
        } => {
            value.insert("region".into(), region.clone().into());
            value.insert("availability_zone".into(), availability_zone.clone().into());
            value.insert("ami_id".into(), intent.spec.host_image.clone().into());
            value.insert("route53_zone_id".into(), route53_zone_id.clone().into());
            value.insert(
                "enable_cloudwatch_agent".into(),
                cloudwatch_agent_package.is_some().into(),
            );
            value.insert(
                "cloudwatch_agent_package_url".into(),
                cloudwatch_agent_package
                    .as_ref()
                    .map_or("", |package| package.url.as_str())
                    .into(),
            );
            value.insert(
                "cloudwatch_agent_package_sha256".into(),
                cloudwatch_agent_package
                    .as_ref()
                    .map_or("", |package| package.sha256.as_str())
                    .into(),
            );
            value.insert(
                "instance_state".into(),
                match state {
                    HostState::Running => "running",
                    HostState::Stopped => "stopped",
                }
                .into(),
            );
            value.insert(
                "secret_version_stages".into(),
                serde_json::json!(
                    intent
                        .spec
                        .secret_names
                        .iter()
                        .map(|name| (name.clone(), "AWSCURRENT"))
                        .collect::<BTreeMap<_, _>>()
                ),
            );
        }
    }
    serde_json::Value::Object(value)
}

#[cfg(test)]
mod tests {
    use crate::config::{CloudProvider, tests::deployable};

    use super::*;

    #[test]
    fn tfvars_never_contain_secret_payload_fields() {
        for provider in [CloudProvider::Gcp, CloudProvider::Aws] {
            let value =
                serde_json::to_string(&variables(&deployable(provider), HostState::Running))
                    .unwrap();
            assert!(!value.contains("secret_value"));
            assert!(!value.contains("api_key_value"));
        }
    }

    #[test]
    fn provider_backends_are_remote_and_locked_or_versionable() {
        let gcp = backend_args(&deployable(CloudProvider::Gcp));
        assert!(
            gcp.iter()
                .any(|argument| argument == "-backend-config=bucket=thelve-test-state-123")
        );
        assert!(
            gcp.iter()
                .any(|argument| argument == "-backend-config=prefix=thelve/thelve-test/test")
        );
        let aws = backend_args(&deployable(CloudProvider::Aws));
        assert!(
            aws.iter()
                .any(|argument| argument == "-backend-config=encrypt=true")
        );
        assert!(
            aws.iter()
                .any(|argument| argument == "-backend-config=use_lockfile=true")
        );
    }

    #[test]
    fn gcp_startup_preserves_only_dns_at_the_shared_metadata_address() {
        let startup = GCP_MODULE
            .get_file("startup.sh.tftpl")
            .and_then(|file| file.contents_utf8())
            .unwrap();
        let uid_reject = startup.find("ip daddr 169.254.169.254 meta skuid").unwrap();
        let forward_reject = startup.find("ip daddr 169.254.169.254 reject").unwrap();

        for rule in [
            "ip daddr 169.254.169.254 udp dport 53 accept",
            "ip daddr 169.254.169.254 tcp dport 53 accept",
        ] {
            assert_eq!(startup.matches(rule).count(), 2);
            let mut matches = startup.match_indices(rule).map(|(index, _)| index);
            assert!(matches.next().unwrap() < uid_reject);
            assert!(matches.next().unwrap() < forward_reject);
        }
        assert!(startup.contains("gcp-v2.complete"));
        assert!(startup.contains("schema=thelve.single-node-cloud-bootstrap/v2"));
    }

    #[test]
    fn workspace_keeps_one_backend_declaration_and_removes_legacy_duplicate() {
        let temporary = tempfile::tempdir().unwrap();
        let config_path = temporary.path().join("deployment.yaml");
        let intent = deployable(CloudProvider::Gcp);
        let directory = workspace(&config_path, &intent).unwrap();
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(LEGACY_BACKEND_BLOCK_FILE),
            br#"{"terraform":{"backend":{"gcs":{}}}}"#,
        )
        .unwrap();

        prepare_workspace(&config_path, &intent, HostState::Stopped).unwrap();

        assert!(!directory.join(LEGACY_BACKEND_BLOCK_FILE).exists());
        assert!(directory.join(BACKEND_ARGS_FILE).is_file());
        let versions = fs::read_to_string(directory.join("versions.tf")).unwrap();
        assert_eq!(versions.matches("backend \"gcs\"").count(), 1);
    }
}
