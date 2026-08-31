use std::{
    collections::BTreeMap,
    io::{self, Read},
    path::Path,
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore as _, rngs::OsRng};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    config::{CloudDeployment, Provider},
    process::{self, CommandPlan},
    terraform,
};

const MAX_SECRET_BYTES: usize = 65_536;
const INTERNAL_SECRET_NAMES: &[&str] = &[
    "database-url",
    "migration-database-url",
    "realtime-callback-database-url",
    "realtime-internal-token",
    "control-api-service-token",
    "postgres-password",
    "redis-password",
    "keycloak-database-password",
    "minio-root-user",
    "minio-root-password",
    "oidc/client-secret",
    "backup/destination",
    "sip-egress-root",
];

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct AwsSecretWrite<'a> {
    secret_id: &'a str,
    secret_string: &'a str,
}

pub fn read_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    let value = rpassword::prompt_password(prompt).context("read hidden secret")?;
    validate_value(value)
}

pub fn read_stdin() -> Result<Zeroizing<String>> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SECRET_BYTES {
        bail!("secret exceeds {MAX_SECRET_BYTES} byte limit");
    }
    while bytes
        .last()
        .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
    {
        bytes.pop();
    }
    validate_value(String::from_utf8(bytes).context("secret input must be UTF-8")?)
}

fn validate_value(value: String) -> Result<Zeroizing<String>> {
    if value.is_empty() {
        bail!("secret value may not be empty");
    }
    if value.len() > MAX_SECRET_BYTES {
        bail!("secret exceeds {MAX_SECRET_BYTES} byte limit");
    }
    Ok(Zeroizing::new(value))
}

pub fn set(
    config_path: &Path,
    intent: &CloudDeployment,
    name: &str,
    value: Zeroizing<String>,
) -> Result<()> {
    let directory = terraform::workspace(config_path, intent)?;
    let resources = terraform::secret_resources(&directory, intent.spec.provider.kind())?;
    let resource = resources.get(name).with_context(|| {
        format!("secret container {name:?} does not exist; run `thelve deploy prepare` first")
    })?;
    let (plan, stdin) = secret_write_plan(&intent.spec.provider, resource, value.as_str())?;
    process::with_secret_stdin(&plan, stdin.as_bytes())?;
    println!(
        "added a new cloud secret version for {name}; value was not written to argv, state, or logs"
    );
    Ok(())
}

pub fn initialize_internal(config_path: &Path, intent: &CloudDeployment) -> Result<()> {
    let directory = terraform::workspace(config_path, intent)?;
    let resources = terraform::secret_resources(&directory, intent.spec.provider.kind())?;
    let missing_resources = INTERNAL_SECRET_NAMES
        .iter()
        .filter(|name| !resources.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    if !missing_resources.is_empty() {
        bail!(
            "internal secret containers are missing: {}; run `thelve deploy prepare` first",
            missing_resources.join(", ")
        );
    }
    let existing = INTERNAL_SECRET_NAMES
        .iter()
        .filter(|name| {
            resources
                .get(**name)
                .is_some_and(|resource| version_exists(&intent.spec.provider, resource))
        })
        .copied()
        .collect::<Vec<_>>();
    if existing.len() == INTERNAL_SECRET_NAMES.len() {
        println!("all generated internal secret version-1 values already exist; no changes made");
        return Ok(());
    }
    if !existing.is_empty() {
        bail!(
            "refusing mixed-state initialization because correlated internal credentials must be created together; existing version-1 names: {}",
            existing.join(", ")
        );
    }

    let outputs = terraform::outputs(config_path, intent)?;
    let backup_destination = outputs
        .get("backup_destination_url")
        .and_then(|output| output.get("value"))
        .and_then(serde_json::Value::as_str)
        .context("Terraform backup_destination_url output is unavailable")?;
    let values = generated_internal_values(backup_destination)?;
    let mut completed = Vec::new();
    for name in INTERNAL_SECRET_NAMES {
        let resource = resources
            .get(*name)
            .with_context(|| format!("secret container {name:?} is unavailable"))?;
        let value = values
            .get(*name)
            .with_context(|| format!("generated secret {name:?} is unavailable"))?;
        let (plan, stdin) = secret_write_plan(&intent.spec.provider, resource, value.as_str())?;
        if let Err(error) = process::with_secret_stdin(&plan, stdin.as_bytes()) {
            bail!(
                "internal-secret initialization stopped after [{}]; do not rerun against this partial version-1 set: {error}",
                completed.join(", ")
            );
        }
        completed.push(*name);
    }
    println!(
        "initialized {} correlated internal secrets directly in {} secret management; no values entered argv, state, logs, or deployment files",
        completed.len(),
        intent.spec.provider.kind()
    );
    Ok(())
}

fn generated_internal_values(
    backup_destination: &str,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    if !(backup_destination.starts_with("gs://") || backup_destination.starts_with("s3://"))
        || backup_destination.chars().any(char::is_whitespace)
    {
        bail!("backup destination output is invalid");
    }
    let postgres_password = random_token();
    let bridge_database_url = format!(
        "postgres://postgres:{}@postgres:5432/postgres",
        postgres_password.as_str()
    );
    let realtime_database_url = format!(
        "postgres://postgres:{}@127.0.0.1:5432/postgres",
        postgres_password.as_str()
    );
    Ok(BTreeMap::from([
        (
            "database-url".into(),
            Zeroizing::new(bridge_database_url.clone()),
        ),
        (
            "migration-database-url".into(),
            Zeroizing::new(bridge_database_url),
        ),
        (
            "realtime-callback-database-url".into(),
            Zeroizing::new(realtime_database_url),
        ),
        ("realtime-internal-token".into(), random_token()),
        ("control-api-service-token".into(), random_token()),
        ("postgres-password".into(), postgres_password),
        ("redis-password".into(), random_token()),
        ("keycloak-database-password".into(), random_token()),
        (
            "minio-root-user".into(),
            Zeroizing::new("thelveadmin".into()),
        ),
        ("minio-root-password".into(), random_token()),
        ("oidc/client-secret".into(), random_token()),
        ("sip-egress-root".into(), random_token()),
        (
            "backup/destination".into(),
            Zeroizing::new(backup_destination.into()),
        ),
    ]))
}

fn random_token() -> Zeroizing<String> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let value = URL_SAFE_NO_PAD.encode(bytes);
    bytes.fill(0);
    Zeroizing::new(value)
}

fn secret_write_plan(
    provider: &Provider,
    resource: &str,
    value: &str,
) -> Result<(CommandPlan, Zeroizing<String>)> {
    match provider {
        Provider::Gcp { project_id, .. } => Ok((
            CommandPlan::new("gcloud").args([
                "secrets",
                "versions",
                "add",
                resource,
                "--project",
                project_id,
                "--data-file=-",
                "--quiet",
            ]),
            Zeroizing::new(value.to_owned()),
        )),
        Provider::Aws { region, .. } => {
            let body = Zeroizing::new(serde_json::to_string(&AwsSecretWrite {
                secret_id: resource,
                secret_string: value,
            })?);
            Ok((
                CommandPlan::new("aws").args([
                    "secretsmanager",
                    "put-secret-value",
                    "--region",
                    region,
                    "--cli-input-json",
                    "file:///dev/stdin",
                    "--output",
                    "json",
                ]),
                body,
            ))
        }
    }
}

pub fn verify_required_versions(
    intent: &CloudDeployment,
    directory: std::path::PathBuf,
) -> Result<()> {
    let resources = terraform::secret_resources(&directory, intent.spec.provider.kind())?;
    let missing: Vec<_> = intent
        .spec
        .secret_names
        .iter()
        .filter(|name| {
            let Some(resource) = resources.get(*name) else {
                return true;
            };
            !version_exists(&intent.spec.provider, resource)
        })
        .cloned()
        .collect();
    if !missing.is_empty() {
        bail!(
            "required cloud secret versions are missing or disabled: {}; populate them with `thelve secret set`",
            missing.join(", ")
        );
    }
    Ok(())
}

fn version_exists(provider: &Provider, resource: &str) -> bool {
    match provider {
        Provider::Gcp { project_id, .. } => {
            let Some(secret_id) = gcp_secret_id(project_id, resource) else {
                return false;
            };
            process::capture(&CommandPlan::new("gcloud").args([
                "secrets",
                "versions",
                "describe",
                "1",
                "--secret",
                secret_id,
                "--project",
                project_id,
                "--format=value(state)",
            ]))
            .is_ok_and(|state| state.trim() == "ENABLED")
        }
        Provider::Aws { region, .. } => {
            let output = process::capture(&CommandPlan::new("aws").args([
                "secretsmanager",
                "describe-secret",
                "--secret-id",
                resource,
                "--region",
                region,
                "--query",
                "VersionIdsToStages",
                "--output",
                "json",
            ]));
            output
                .ok()
                .and_then(|json| serde_json::from_str::<BTreeMap<String, Vec<String>>>(&json).ok())
                .is_some_and(|versions| {
                    versions
                        .values()
                        .any(|stages| stages.iter().any(|stage| stage == "AWSCURRENT"))
                })
        }
    }
}

fn gcp_secret_id<'a>(project_id: &str, resource: &'a str) -> Option<&'a str> {
    let prefix = format!("projects/{project_id}/secrets/");
    let secret_id = resource.strip_prefix(&prefix)?;
    (!secret_id.is_empty() && !secret_id.contains('/')).then_some(secret_id)
}

#[cfg(test)]
mod tests {
    use crate::config::{CloudProvider, tests::deployable};

    use super::*;

    #[test]
    fn secret_never_appears_in_process_arguments() {
        let sentinel = "telnyx-secret-SENTINEL";
        for provider in [CloudProvider::Gcp, CloudProvider::Aws] {
            let intent = deployable(provider);
            let (plan, stdin) =
                secret_write_plan(&intent.spec.provider, "safe-resource-id", sentinel).unwrap();
            assert!(!plan.display_safe().contains(sentinel));
            assert!(stdin.contains(sentinel));
        }
    }

    #[test]
    fn generated_internal_set_is_complete_correlated_and_excludes_telnyx() {
        let values = generated_internal_values("gs://example-backup/single-node").unwrap();
        assert_eq!(values.len(), INTERNAL_SECRET_NAMES.len());
        assert!(!values.contains_key("telnyx-api-key"));
        assert!(!values.contains_key("telnyx-public-key"));
        let password = values.get("postgres-password").unwrap();
        for name in ["database-url", "migration-database-url"] {
            assert!(values.get(name).unwrap().contains(password.as_str()));
            assert!(values.get(name).unwrap().contains("@postgres:5432/"));
        }
        let realtime = values.get("realtime-callback-database-url").unwrap();
        assert!(realtime.contains(password.as_str()));
        assert!(realtime.contains("@127.0.0.1:5432/"));
        assert!(!realtime.contains("@postgres:5432/"));
    }

    #[test]
    fn gcp_version_lookup_uses_an_exact_project_scoped_secret_id() {
        assert_eq!(
            gcp_secret_id(
                "preview-project",
                "projects/preview-project/secrets/thelve-postgres-password"
            ),
            Some("thelve-postgres-password")
        );
        assert_eq!(
            gcp_secret_id(
                "preview-project",
                "projects/other-project/secrets/thelve-postgres-password"
            ),
            None
        );
        assert_eq!(
            gcp_secret_id(
                "preview-project",
                "projects/preview-project/secrets/nested/secret"
            ),
            None
        );
        assert_eq!(
            gcp_secret_id("preview-project", "projects/preview-project/secrets/"),
            None
        );
    }
}
