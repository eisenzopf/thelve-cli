//! `thelve launch`: the single-server appliance from a clean workstation in
//! one command.
//!
//! Nothing here is new machinery. Every step is the runbook's own command,
//! called in the runbook's order with the same approval gate, and recorded in
//! a receipt so a stopped launch resumes at the step that did not complete
//! rather than re-applying what did. The two Telnyx values are still typed at
//! hidden prompts: a launch never takes a secret on the command line. After
//! the host is up, the launch asks Rudeless for the installation's licence
//! and records it in the intent, so the node is licensed at first boot and
//! nobody visits a licence page.
//!
//! GCP only for activation today, like the runbook; on AWS the launch stops
//! after `up` and says so.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use zeroize::Zeroizing;

use crate::config::{self, CloudDeployment, CloudProvider, TrustedIssuer};
use crate::{activation, cloud, identity, license, secrets, terraform};

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
    /// Who the first person in the bundled sign-in service is; the contact
    /// address when the operator names nobody else.
    pub administrator_email: Option<String>,
    pub release_dir: PathBuf,
    pub issuer_url: Option<String>,
    /// Pins the issuer's trust document; see `thelve license trust --expect-sha256`.
    pub issuer_trust_sha256: Option<String>,
    /// Where the licence is requested; `None` is Rudeless.
    pub license_service_url: Option<String>,
    /// Leave the installation unlicensed and print the manual command instead.
    pub skip_license: bool,
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
    Domains,
    InternalSecrets,
    TelnyxSecrets,
    OidcClientSecret,
    Up,
    License,
    RenderNodeConfig,
    Activate,
    FirstAdministrator,
}

impl Step {
    const ORDER: [Self; 12] = [
        Self::Doctor,
        Self::Intent,
        Self::BootstrapState,
        Self::Prepare,
        Self::Domains,
        Self::InternalSecrets,
        Self::TelnyxSecrets,
        Self::Up,
        Self::License,
        Self::RenderNodeConfig,
        Self::Activate,
        Self::FirstAdministrator,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Doctor => "doctor",
            Self::Intent => "deployment intent",
            Self::BootstrapState => "bootstrap-state",
            Self::Prepare => "prepare",
            Self::Domains => "domain names",
            Self::InternalSecrets => "secret initialize-internal",
            Self::TelnyxSecrets => "telnyx secrets",
            Self::OidcClientSecret => "oidc client secret",
            Self::Up => "up",
            Self::License => "licence",
            Self::RenderNodeConfig => "render-node-config",
            Self::Activate => "activate-gcp",
            Self::FirstAdministrator => "first administrator",
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
    let mut first_administrator = None;
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
            Step::Domains => assign_domains(request)?,
            Step::InternalSecrets => {
                secrets::initialize_internal(&request.config, &config::load(&request.config)?)?;
            }
            Step::TelnyxSecrets => {
                let intent = config::load(&request.config)?;
                let workspace = terraform::workspace(&request.config, &intent)?;
                // Values an operator already provided, by an earlier run or
                // with `thelve secret set`, are left exactly as they are: a
                // launch that can be resumed must not ask twice, and must
                // never overwrite a working credential with a typo.
                if secrets::versions_exist(&intent, &workspace, &TELNYX_SECRETS)? {
                    println!(
                        "launch: the Telnyx values already exist in this project's secret store; keeping them"
                    );
                } else {
                    for name in TELNYX_SECRETS {
                        let value = secrets::read_hidden(&format!("{name}: "))?;
                        secrets::set(&request.config, &intent, name, value)?;
                    }
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
            Step::License => acquire_license(request)?,
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
            Step::FirstAdministrator => {
                first_administrator = create_first_administrator(request)?;
            }
        }
        receipt.record(&request.receipt, step)?;
    }
    terraform::status(&request.config)?;
    print_next_steps(request, first_administrator.as_ref());
    Ok(())
}

/// Give the appliance the names its certificates and sign-in service use.
///
/// An operator who has DNS ready passes `--domain`; the intent then keeps
/// exactly what they wrote. Everyone else gets working names without owning a
/// domain or waiting for a record to propagate: the appliance's own static
/// address, spelled as an `sslip.io` host, which resolves to that address for
/// anybody. Real names are a later change, not a precondition for a first
/// install.
fn assign_domains(request: &LaunchRequest) -> Result<()> {
    let mut intent = config::load(&request.config)?;
    if !intent.spec.domains.is_empty() {
        println!(
            "launch: keeping the domain names in {}",
            request.config.display()
        );
        return Ok(());
    }
    let outputs = terraform::outputs(&request.config, &intent)?;
    let address = outputs
        .get("public_ip")
        .and_then(|output| output.get("value"))
        .and_then(serde_json::Value::as_str)
        .context("the appliance has no static address yet; `prepare` creates it")?;
    intent.spec.domains = default_domains(address)?;
    intent.validate()?;
    config::rewrite(&request.config, &intent)?;
    for (name, host) in &intent.spec.domains {
        println!("launch: {name} is https://{host}");
    }
    println!(
        "launch: these names resolve to this appliance's own address for anyone, so no DNS record is needed. Your own names can replace them later."
    );
    Ok(())
}

/// The four names an appliance answers on, derived from its address.
/// `app-203-0-113-7.sslip.io` resolves to `203.0.113.7`, so a first install
/// has working public certificates with no zone, registrar, or record.
fn default_domains(address: &str) -> Result<BTreeMap<String, String>> {
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 || octets.iter().any(|octet| octet.parse::<u8>().is_err()) {
        bail!("the appliance's address {address:?} is not an IPv4 address");
    }
    let dashed = octets.join("-");
    Ok([
        ("app", "app"),
        ("api", "control"),
        ("media", "realtime"),
        ("sip", "sip"),
    ]
    .into_iter()
    .map(|(key, prefix)| (key.to_owned(), format!("{prefix}-{dashed}.sslip.io")))
    .collect())
}

/// Create the first person in the appliance's own sign-in service, so the
/// operator can open the desk straight away. Only for bundled sign-in: with
/// the customer's own provider, their people already exist.
fn create_first_administrator(
    request: &LaunchRequest,
) -> Result<Option<(identity::FirstAdministrator, Zeroizing<String>)>> {
    let intent = config::load(&request.config)?;
    if intent.spec.identity != config::IdentityIntent::BundledKeycloak {
        println!(
            "launch: sign-in is your own provider, so the people who may open the desk are already yours"
        );
        return Ok(None);
    }
    let app = intent
        .spec
        .domains
        .get("app")
        .context("the intent has no app domain")?
        .clone();
    let email = request
        .administrator_email
        .clone()
        .unwrap_or_else(|| request.tls_contact_email.clone());
    let (outcome, password) =
        identity::create_first_administrator(&request.config, &intent, &app, &email)?;
    Ok(Some((outcome, password)))
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
    intent.metadata.contact_email = Some(request.tls_contact_email.clone());
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

/// Ask Rudeless for this installation's licence and record it, with the
/// issuer's trust anchors, in the deployment intent. Idempotent: an intent
/// that already carries a certificate is left alone, and the service answers
/// a repeated request for the same installation with the same certificate.
fn acquire_license(request: &LaunchRequest) -> Result<()> {
    let mut intent = config::load(&request.config)?;
    if let Some(certificate) = &intent.spec.licensing.certificate {
        println!(
            "launch: the intent already carries certificate {}; keeping it",
            certificate
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
        );
        return Ok(());
    }
    if request.skip_license {
        println!(
            "launch: --skip-license; the appliance boots unlicensed. Install one later with: thelve license install --config {} --certificate licence.json --release-dir {} --tls-contact-email {} --approve",
            request.config.display(),
            request.release_dir.display(),
            request.tls_contact_email
        );
        return Ok(());
    }
    let tenant_id = installation_tenant_id(&request.name);
    let service_url = request
        .license_service_url
        .as_deref()
        .unwrap_or(license::DEFAULT_LICENSE_SERVICE_URL);
    let issued = license::request(
        service_url,
        &request.tls_contact_email,
        tenant_id,
        &request.name,
    )?;
    if intent.spec.licensing.trusted_issuers.is_empty() {
        let issuer_url = request
            .issuer_url
            .as_deref()
            .unwrap_or(license::DEFAULT_ISSUER_URL);
        intent.spec.licensing.trusted_issuers =
            trusted_issuers(issuer_url, request.issuer_trust_sha256.as_deref())?;
    }
    if intent.metadata.contact_email.is_none() {
        intent.metadata.contact_email = Some(request.tls_contact_email.clone());
    }
    intent.spec.licensing.certificate = Some(issued.certificate);
    intent.validate()?;
    config::rewrite(&request.config, &intent)?;
    println!(
        "launch: licence {} for {} from {} ({}) recorded in {}; the node installs it at first boot",
        issued.certificate_id,
        issued.suites.join(", "),
        issued.issuer,
        if issued.reissued {
            "re-delivered"
        } else {
            "issued"
        },
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

fn print_next_steps(
    request: &LaunchRequest,
    first_administrator: Option<&(identity::FirstAdministrator, Zeroizing<String>)>,
) {
    let intent = config::load(&request.config).ok();
    let app = intent
        .as_ref()
        .and_then(|intent| intent.spec.domains.get("app"))
        .map_or_else(
            || "the app domain".to_owned(),
            |domain| format!("https://{domain}"),
        );
    let licensed = intent
        .as_ref()
        .is_some_and(|intent| intent.spec.licensing.certificate.is_some());
    println!();
    println!("launch complete. Next:");
    match first_administrator {
        Some((identity::FirstAdministrator::Created { username }, password)) => {
            println!("  1. Open {app} and sign in:");
            println!("       who:      {username}");
            println!("       password: {}", password.as_str());
            println!(
                "     This password is temporary and shown only here; sign-in asks for a new one straight away. The first person to sign in becomes the first administrator."
            );
        }
        Some((identity::FirstAdministrator::AlreadyExists { username }, _)) => {
            println!(
                "  1. Open {app} and sign in as {username}, who already exists in this installation's sign-in service."
            );
        }
        None => {
            println!(
                "  1. Open {app} and sign in with your own identity provider; the first person to sign in becomes the first administrator."
            );
        }
    }
    if licensed {
        println!("  2. Finish the checklist: telephony. The licence is installed.");
    } else {
        println!("  2. Finish the checklist: telephony, licence.");
        println!(
            "     This installation's tenant id is {}; install its licence with: thelve license install --config {} --certificate licence.json --release-dir {} --tls-contact-email {} --approve",
            installation_tenant_id(&request.name),
            request.config.display(),
            request.release_dir.display(),
            request.tls_contact_email
        );
    }
    println!(
        "  Keep {} and {}; a later `thelve launch` with the same arguments resumes from them.",
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
            administrator_email: None,
            release_dir: directory.join("release"),
            issuer_url: None,
            issuer_trust_sha256: None,
            license_service_url: None,
            skip_license: false,
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

    fn request_in(directory: &Path, license_service_url: Option<String>) -> LaunchRequest {
        LaunchRequest {
            provider: CloudProvider::Gcp,
            name: "thelve-test".into(),
            project: Some("project".into()),
            region: "us-west1".into(),
            zone: "us-west1-b".into(),
            host_image: "projects/project/global/images/thelve-host-0-1-0".into(),
            state_bucket: "thelve-test-state".into(),
            domains: [
                ("app", "desk.example.com"),
                ("api", "api.example.com"),
                ("media", "media.example.com"),
                ("sip", "sip.example.com"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
            tls_contact_email: "operator@example.com".into(),
            administrator_email: None,
            release_dir: directory.join("release"),
            issuer_url: None,
            issuer_trust_sha256: None,
            license_service_url,
            skip_license: false,
            identity: config::IdentityIntent::ExternalOidc {
                issuer: "https://login.example.com/realms/acme".into(),
                client_id: "thelve-desk".into(),
            },
            config: directory.join("deployment.yaml"),
            node_config: directory.join("node.yaml"),
            activation_receipt: directory.join("activation-receipt.json"),
            receipt: directory.join("launch-receipt.json"),
            approve: true,
        }
    }

    #[test]
    fn the_licence_step_records_the_certificate_and_trust_and_is_idempotent() {
        let directory =
            std::env::temp_dir().join(format!("thelve-launch-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let tenant = installation_tenant_id("thelve-test");
        let certificate = serde_json::json!({
            "id": "0f3f6c2a-3c2e-4a7e-9c62-1b4d0f4d6a11",
            "tenant_id": tenant.to_string(),
            "issuer": "https://licenses.rudeless.ai",
            "sequence": 1,
            "signature": "c2lnbmVk",
        });
        let answer = serde_json::json!({
            "tenant_id": tenant,
            "certificate_id": "0f3f6c2a-3c2e-4a7e-9c62-1b4d0f4d6a11",
            "suites": ["core"],
            "issuer": "https://licenses.rudeless.ai",
            "certificate": certificate,
            "reissued": false,
        });
        let trust = serde_json::json!([
            {"issuer": "https://licenses.rudeless.ai", "key_id": "k1", "public_key": "cHVibGlj"}
        ]);
        let base = license::stub::serve(
            vec![
                ("/license", 200, answer.to_string()),
                ("/v1/trust", 200, trust.to_string()),
            ],
            2,
        );
        let mut request = request_in(&directory, Some(format!("{base}/license")));
        request.issuer_url = Some(base.clone());
        write_intent(&request).unwrap();
        let before = config::load(&request.config).unwrap();
        assert_eq!(
            before.metadata.contact_email.as_deref(),
            Some("operator@example.com")
        );
        assert!(before.spec.licensing.certificate.is_none());

        acquire_license(&request).unwrap();
        let after = config::load(&request.config).unwrap();
        let recorded = after
            .spec
            .licensing
            .certificate
            .expect("certificate recorded");
        assert_eq!(recorded["tenant_id"], tenant.to_string());
        assert_eq!(after.spec.licensing.trusted_issuers.len(), 1);
        assert_eq!(after.spec.licensing.trusted_issuers[0].key_id, "k1");

        // The stub is exhausted; a second run must not need the network.
        acquire_license(&request).unwrap();
        let again = config::load(&request.config).unwrap();
        assert_eq!(
            again.spec.licensing.certificate.unwrap()["id"],
            "0f3f6c2a-3c2e-4a7e-9c62-1b4d0f4d6a11"
        );
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn skip_license_leaves_the_intent_unlicensed() {
        let directory =
            std::env::temp_dir().join(format!("thelve-launch-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let mut request = request_in(&directory, None);
        request.skip_license = true;
        write_intent(&request).unwrap();
        acquire_license(&request).unwrap();
        assert!(
            config::load(&request.config)
                .unwrap()
                .spec
                .licensing
                .certificate
                .is_none()
        );
        fs::remove_dir_all(&directory).unwrap();
    }
}
