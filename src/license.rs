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

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

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

/// Fetch the issuer's published trust anchors, in the shape the deployment
/// intent's `licensing.trustedIssuers` takes.
pub fn trust(issuer_url: &str) -> Result<Value> {
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
    Ok(serde_json::json!({"licensing": {"trustedIssuers": trusted_issuers}}))
}
