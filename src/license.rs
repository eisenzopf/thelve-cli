//! Licence installation for a deployed appliance.
//!
//! A licence is a signed entitlement certificate issued for one
//! installation. Installing it is one capability call —
//! `platform.installation.license.install` — which enrols the appliance's
//! tenant with the certificate's issuer and ingests the certificate; the
//! control API declares the capability approval-free for the installation
//! administrator, so it goes through the bound AAuth profile without a plan.
//! The trust anchor the appliance needs first is published by the issuer and
//! copied into the deployment intent's `licensing.trustedIssuers`.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::activation;
use crate::agent::{AgentClient, CapabilityCall, read_json_input};

const INSTALL_CAPABILITY: &str = "platform.installation.license.install";
const MAX_TRUST_BYTES: usize = 64 * 1024;

pub fn install(
    profile: &str,
    certificate_path: &Path,
    idempotency_key: Option<String>,
) -> Result<Value> {
    let certificate = read_json_input(certificate_path)?;
    let certificate_id = certificate
        .get("id")
        .and_then(Value::as_str)
        .context("certificate document has no id")?
        .to_owned();
    if certificate
        .get("signature")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("certificate document is unsigned; obtain the signed certificate from the issuer");
    }
    AgentClient::load(profile)?.invoke(CapabilityCall {
        capability: INSTALL_CAPABILITY.into(),
        resource_type: "entitlement_certificate".into(),
        resource_id: Some(certificate_id.clone()),
        input: certificate,
        approval_id: None,
        idempotency_key: idempotency_key
            .unwrap_or_else(|| format!("license-install-{certificate_id}")),
    })
}

/// Install a licence before any administrator exists: the certificate goes
/// into the deployment intent's `licensing.certificate`, the node
/// configuration is re-rendered, and the node is re-activated so the control
/// API installs it at boot. The certificate is a signed public document, so
/// carrying it in the intent is fine; the intent is rewritten in place after
/// it validates.
pub fn install_via_render(
    config_path: &Path,
    certificate_path: &Path,
    release_dir: &Path,
    tls_contact_email: &str,
    node_config: &Path,
    activation_receipt: &Path,
) -> Result<()> {
    let certificate = read_json_input(certificate_path)?;
    if certificate
        .get("signature")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("certificate document is unsigned; obtain the signed certificate from the issuer");
    }
    let mut intent = crate::config::load(config_path)?;
    let expected_tenant = crate::launch::installation_tenant_id(&intent.metadata.name).to_string();
    if certificate.get("tenant_id").and_then(Value::as_str) != Some(expected_tenant.as_str()) {
        bail!(
            "certificate names another tenant; this installation's tenant id is {expected_tenant}"
        );
    }
    if node_config.exists() {
        bail!(
            "refusing to overwrite existing {}; pass --node-config with a new path",
            node_config.display()
        );
    }
    if activation_receipt.exists() {
        bail!(
            "refusing to overwrite existing {}; pass --activation-receipt with a new path",
            activation_receipt.display()
        );
    }
    intent.spec.licensing.certificate = Some(certificate);
    intent.validate()?;
    let rendered = serde_yaml::to_string(&intent).context("serialize deployment intent")?;
    fs::write(config_path, rendered).with_context(|| format!("write {}", config_path.display()))?;
    println!(
        "licence recorded in {}; re-rendering and re-activating",
        config_path.display()
    );
    activation::render_node_config(config_path, release_dir, node_config, tls_contact_email)?;
    activation::activate_gcp(config_path, release_dir, node_config, activation_receipt)?;
    println!("licence installed at boot; Platform admin → Installation shows the suites it grants");
    Ok(())
}

/// Fetch the issuer's published trust anchors, in the shape the deployment
/// intent's `licensing.trustedIssuers` takes.
///
/// `expect_sha256` pins the document: the digest Rudeless publishes beside
/// the issuer URL, typed from that second channel, so a name that resolves to
/// the wrong host at first fetch yields keys the operator never accepts.
pub fn trust(issuer_url: &str, expect_sha256: Option<&str>) -> Result<Value> {
    let issuer_url = issuer_url.trim_end_matches('/');
    if !issuer_url.starts_with("https://") && !issuer_url.starts_with("http://127.0.0.1") {
        bail!("issuer URL must use https (or loopback http for a local issuer)");
    }
    let response = reqwest::blocking::Client::new()
        .get(format!("{issuer_url}/v1/trust"))
        .send()
        .context("fetch issuer trust")?
        .error_for_status()
        .context("issuer refused the trust request")?;
    let body = response.bytes().context("read issuer trust")?;
    if body.len() > MAX_TRUST_BYTES {
        bail!("issuer trust document is unexpectedly large");
    }
    let trust_sha256 = {
        use sha2::{Digest as _, Sha256};
        format!("sha256:{:x}", Sha256::digest(&body))
    };
    if let Some(expected) = expect_sha256 {
        let expected = expected.trim();
        let expected = if expected.starts_with("sha256:") {
            expected.to_owned()
        } else {
            format!("sha256:{expected}")
        };
        if !expected.eq_ignore_ascii_case(&trust_sha256) {
            bail!(
                "the issuer's trust document does not match the pinned digest: fetched {trust_sha256}; refusing to trust keys the pin does not name"
            );
        }
    }
    let keys: Vec<Value> = serde_json::from_slice(&body).context("parse issuer trust")?;
    let trusted_issuers = keys
        .iter()
        .map(|key| {
            let field = |name: &str| {
                key.get(name)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .with_context(|| format!("issuer trust entry lacks {name}"))
            };
            Ok(serde_json::json!({
                "issuer": field("issuer")?,
                "keyId": field("key_id")?,
                "publicKey": field("public_key")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "licensing": {"trustedIssuers": trusted_issuers},
        "trustSha256": trust_sha256,
    }))
}
