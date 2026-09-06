//! `thelve launch`: the single-server appliance from a clean workstation in
//! one command.
//!
//! Nothing here is new machinery. Every step is the runbook's own command,
//! called in the runbook's order with the same approval gate, and recorded in
//! a receipt so a stopped launch resumes at the step that did not complete
//! rather than re-applying what did. The two Telnyx values are still typed at
//! hidden prompts: a launch never takes a secret on the command line.
//!
//! GCP only for activation today, like the runbook; on AWS the launch stops
//! after `up` and says so.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{self, CloudDeployment, CloudProvider, TrustedIssuer};
use crate::{activation, cloud, license, secrets, terraform};

pub const RECEIPT_SCHEMA: &str = "thelve.launch-receipt.v1";
const TELNYX_SECRETS: [&str; 2] = ["telnyx-api-key", "telnyx-public-key"];

/// Everything the runbook has the operator edit into `deployment.yaml` by
/// hand, taken as arguments instead.
#[derive(Clone, Debug)]
pub struct LaunchRequest {
    pub provider: CloudProvider,
    pub name: String,
    pub project: Option<String>,
    pub region: String,
    pub zone: String,
    pub host_image: String,
    pub state_bucket: String,
    pub domains: BTreeMap<String, String>,
    pub tls_contact_email: String,
    pub release_dir: PathBuf,
    pub issuer_url: Option<String>,
    /// Pins the issuer's trust document; see `thelve license trust --expect-sha256`.
    pub issuer_trust_sha256: Option<String>,
    /// The OIDC provider people sign in with.
    pub identity: config::IdentityIntent,
    pub config: PathBuf,
    pub node_config: PathBuf,
    pub activation_receipt: PathBuf,
    pub receipt: PathBuf,
    pub approve: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Doctor,
    Intent,
    BootstrapState,
    Prepare,
    InternalSecrets,
    TelnyxSecrets,
    OidcClientSecret,
    Up,
    RenderNodeConfig,
    Activate,
}

impl Step {
    const ORDER: [Self; 9] = [
        Self::Doctor,
        Self::Intent,
        Self::BootstrapState,
        Self::Prepare,
        Self::InternalSecrets,
        Self::TelnyxSecrets,
        Self::Up,
        Self::RenderNodeConfig,
        Self::Activate,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Doctor => "doctor",
            Self::Intent => "deployment intent",
            Self::BootstrapState => "bootstrap-state",
            Self::Prepare => "prepare",
            Self::InternalSecrets => "secret initialize-internal",
            Self::TelnyxSecrets => "telnyx secrets",
            Self::OidcClientSecret => "oidc client secret",
            Self::Up => "up",
            Self::RenderNodeConfig => "render-node-config",
            Self::Activate => "activate-gcp",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Receipt {
    pub schema_version: String,
    pub deployment: String,
    pub provider: CloudProvider,
    pub completed: BTreeMap<Step, String>,
}

impl Receipt {
    fn load_or_new(path: &Path, request: &LaunchRequest) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                schema_version: RECEIPT_SCHEMA.into(),
                deployment: request.name.clone(),
                provider: request.provider,
                completed: BTreeMap::new(),
            });
        }
        let receipt: Self = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )
        .with_context(|| format!("parse launch receipt {}", path.display()))?;
        if receipt.schema_version != RECEIPT_SCHEMA {
            bail!(
                "launch receipt {} has an unsupported schema",
                path.display()
            );
        }
        if receipt.deployment != request.name || receipt.provider != request.provider {
            bail!(
                "launch receipt {} belongs to {} on {}, not {} on {}",
                path.display(),
                receipt.deployment,
                receipt.provider,
                request.name,
                request.provider
            );
        }
        Ok(receipt)
    }

    fn record(&mut self, path: &Path, step: Step) -> Result<()> {
        self.completed
            .insert(step, Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        let bytes = serde_json::to_vec_pretty(self).context("serialize launch receipt")?;
        fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
    }
}

pub fn launch(request: &LaunchRequest) -> Result<()> {
    if !request.approve {
        bail!(
            "launch creates cloud resources and applies Terraform; rerun with --approve after reading the runbook's safety model"
        );
    }
    if !activation::valid_email(&request.tls_contact_email) {
        bail!("--tls-contact-email must be a real operator address for ACME notices");
    }
    let mut receipt = Receipt::load_or_new(&request.receipt, request)?;
    for step in Step::ORDER {
        if let Some(at) = receipt.completed.get(&step) {
            println!(
                "launch: {} already completed at {at}; skipping",
                step.label()
            );
            continue;
        }
        println!("launch: {}", step.label());
        match step {
            Step::Doctor => cloud::doctor(
                request.provider,
                request.project.clone(),
                Some(request.region.clone()),
            )?,
            Step::Intent => write_intent(request)?,
            Step::BootstrapState => cloud::bootstrap_state(&config::load(&request.config)?)?,
            Step::Prepare => {
                terraform::apply(&request.config, terraform::HostState::Stopped, false)?
            }
            Step::InternalSecrets => {
                secrets::initialize_internal(&request.config, &config::load(&request.config)?)?;
            }
            Step::TelnyxSecrets => {
                let intent = config::load(&request.config)?;
                for name in TELNYX_SECRETS {
                    let value = secrets::read_hidden(&format!("{name}: "))?;
                    secrets::set(&request.config, &intent, name, value)?;
                }
            }
            Step::OidcClientSecret => {
                let intent = config::load(&request.config)?;
                let value = secrets::read_hidden(
                    "oidc/client-secret (the client secret your provider issued for the Thelve desk): ",
                )?;
                secrets::set(&request.config, &intent, "oidc/client-secret", value)?;
            }
            Step::Up => {
                let intent = config::load(&request.config)?;
                secrets::verify_required_versions(
                    &intent,
                    terraform::workspace(&request.config, &intent)?,
                )?;
                terraform::apply(&request.config, terraform::HostState::Running, false)?;
            }
            Step::RenderNodeConfig => activation::render_node_config(
                &request.config,
                &request.release_dir,
                &request.node_config,
                &request.tls_contact_email,
            )?,
            Step::Activate => {
                if request.provider != CloudProvider::Gcp {
                    receipt.record(&request.receipt, Step::RenderNodeConfig)?;
                    bail!(
                        "the appliance is up and its node configuration is rendered at {}; activation is GCP-only today, so finish AWS activation by the runbook",
                        request.node_config.display()
                    );
                }
                activation::activate_gcp(
                    &request.config,
                    &request.release_dir,
                    &request.node_config,
                    &request.activation_receipt,
                )?;
            }
        }
        receipt.record(&request.receipt, step)?;
    }
    terraform::status(&request.config)?;
    print_next_steps(request);
    Ok(())
}

/// The runbook's "edit deployment.yaml" step, done from arguments. An
/// existing intent is kept as written: a resumed launch must not rewrite
/// what an operator may have reviewed.
fn write_intent(request: &LaunchRequest) -> Result<()> {
    if request.config.exists() {
        config::load(&request.config)?;
        println!(
            "launch: keeping existing deployment intent {}",
            request.config.display()
        );
        return Ok(());
    }
    let mut intent = CloudDeployment::template(
        request.provider,
        request.name.clone(),
        request.project.clone(),
        request.region.clone(),
        request.zone.clone(),
    )?;
    intent.spec.host_image = request.host_image.clone();
    intent.spec.state.bucket = request.state_bucket.clone();
    intent.spec.domains = request.domains.clone();
    intent.spec.identity = request.identity.clone();
    if let Some(issuer_url) = &request.issuer_url {
        intent.spec.licensing.trusted_issuers =
            trusted_issuers(issuer_url, request.issuer_trust_sha256.as_deref())?;
    }
    intent.validate()?;
    config::write_new(&request.config, &intent)?;
    println!(
        "launch: wrote non-secret deployment intent to {}",
        request.config.display()
    );
    Ok(())
}

fn trusted_issuers(issuer_url: &str, expect_sha256: Option<&str>) -> Result<Vec<TrustedIssuer>> {
    let document = license::trust(issuer_url, expect_sha256)?;
    let issuers = document
        .pointer("/licensing/trustedIssuers")
        .cloned()
        .context("issuer trust document has no licensing.trustedIssuers")?;
    serde_json::from_value(issuers).context("issuer trust entries")
}

/// The tenant the appliance provisions at boot, derived exactly as the
/// renderer derives it (`thelve_single_node::installation_tenant_id`), so the
/// issuer can be told whom to license before the node exists.
pub fn installation_tenant_id(name: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("thelve:single-node:{name}:tenant").as_bytes(),
    )
}

fn print_next_steps(request: &LaunchRequest) {
    let app = request.domains.get("app").map_or_else(
        || "the app domain".to_owned(),
        |domain| format!("https://{domain}"),
    );
    println!();
    println!("launch complete. Next:");
    println!(
        "  0. This installation's tenant id is {}; the issuer needs it to produce the licence.",
        installation_tenant_id(&request.name)
    );
    println!(
        "  1. Open {app} and complete the setup checklist: first administrator, sign-in, telephony, licence."
    );
    println!(
        "  2. Install the licence the issuer produced: thelve license install --config {} --certificate licence.json \\",
        request.config.display()
    );
    println!(
        "       --release-dir {} --tls-contact-email {} --approve",
        request.release_dir.display(),
        request.tls_contact_email
    );
    println!(
        "     (re-renders and re-activates so the control API installs it at boot), or paste it under Platform admin → Installation."
    );
    println!(
        "  3. Keep {} and {}; a later `thelve launch` with the same arguments resumes from them.",
        request.receipt.display(),
        request.config.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against the renderer's derivation in the Thelve repository
    /// (`crates/thelve-single-node/src/compose.rs`); both sides test this
    /// value so a drift shows up as a failing test rather than an unlicensed
    /// appliance.
    #[test]
    fn installation_tenant_id_matches_the_renderer() {
        assert_eq!(
            installation_tenant_id("thelve-test").to_string(),
            "e37ee2de-10ef-5215-944c-fa2d2393eb0b"
        );
    }

    #[test]
    fn steps_are_recorded_in_runbook_order_and_a_foreign_receipt_is_refused() {
        let directory =
            std::env::temp_dir().join(format!("thelve-launch-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let receipt_path = directory.join("launch-receipt.json");
        let request = LaunchRequest {
            provider: CloudProvider::Gcp,
            name: "thelve-test".into(),
            project: Some("project".into()),
            region: "us-west1".into(),
            zone: "us-west1-b".into(),
            host_image: "image".into(),
            state_bucket: "bucket".into(),
            domains: BTreeMap::new(),
            tls_contact_email: "operator@example.com".into(),
            release_dir: directory.join("release"),
            issuer_url: None,
            issuer_trust_sha256: None,
            identity: config::IdentityIntent::ExternalOidc {
                issuer: "https://login.example.com/realms/acme".into(),
                client_id: "thelve-desk".into(),
            },
            config: directory.join("deployment.yaml"),
            node_config: directory.join("node.yaml"),
            activation_receipt: directory.join("activation-receipt.json"),
            receipt: receipt_path.clone(),
            approve: true,
        };
        let mut receipt = Receipt::load_or_new(&receipt_path, &request).unwrap();
        receipt.record(&receipt_path, Step::Doctor).unwrap();
        receipt.record(&receipt_path, Step::Intent).unwrap();
        let reloaded = Receipt::load_or_new(&receipt_path, &request).unwrap();
        assert_eq!(
            reloaded.completed.keys().copied().collect::<Vec<_>>(),
            [Step::Doctor, Step::Intent]
        );
        assert!(Step::ORDER.windows(2).all(|pair| pair[0] < pair[1]));

        let other = LaunchRequest {
            name: "someone-else".into(),
            ..request
        };
        assert!(Receipt::load_or_new(&receipt_path, &other).is_err());
        fs::remove_dir_all(&directory).unwrap();
    }
}
