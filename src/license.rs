//! Licences for a deployed appliance.
//!
//! A licence is a signed entitlement certificate issued for one
//! installation. `thelve launch` requests it from Rudeless during the launch,
//! using the installation id it derives from the deployment name and the
//! contact address it already holds for TLS notices, and records it in the
//! deployment intent so the control API installs it at first boot. Nobody
//! visits a licence page. The trust anchor the appliance needs first is
//! published by the issuer and copied into the intent's
//! `licensing.trustedIssuers` in the same step.
//!
//! Installing a certificate later is one capability call —
//! `platform.installation.license.install` — which enrols the appliance's
//! tenant with the certificate's issuer and ingests the certificate.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::activation;
use crate::agent::{AgentClient, CapabilityCall, read_json_input};

const INSTALL_CAPABILITY: &str = "platform.installation.license.install";
const MAX_TRUST_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;

/// Where an appliance's certificates are signed. The launch fetches this
/// issuer's published keys unless `--issuer-url` names another.
pub const DEFAULT_ISSUER_URL: &str = "https://licenses.rudeless.ai";
/// Where the launch asks for the installation's licence. Free, one per
/// installation, without expiry; asking again returns the same certificate.
pub const DEFAULT_LICENSE_SERVICE_URL: &str = "https://rudeless.ai/api/v1/thelve/licenses/trial";

/// What the licence service returned for one installation.
#[derive(Clone, Debug, Deserialize)]
pub struct IssuedLicense {
    pub tenant_id: uuid::Uuid,
    pub certificate_id: uuid::Uuid,
    #[serde(default)]
    pub suites: Vec<String>,
    #[serde(default)]
    pub issuer: String,
    pub certificate: Value,
    #[serde(default)]
    pub reissued: bool,
}

fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
        .user_agent(concat!("thelve-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build licence client")
}

fn require_https_or_loopback(url: &str, what: &str) -> Result<()> {
    if url.starts_with("https://") || url.starts_with("http://127.0.0.1") {
        return Ok(());
    }
    bail!("{what} must use https (or loopback http for a local service)")
}

fn require_signed(certificate: &Value) -> Result<()> {
    if certificate
        .get("signature")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("certificate document is unsigned; obtain the signed certificate from the issuer");
    }
    Ok(())
}

/// Ask the licence service for this installation's certificate.
///
/// The service is idempotent per installation id, so a resumed launch gets
/// the same certificate back. The response is checked before it is trusted:
/// it must be signed and it must name exactly this installation's tenant.
///
/// # Errors
///
/// Returns an error when the service is unreachable, refuses the request
/// (the body's `error` is repeated), or answers with a certificate for
/// another tenant or without a signature.
pub fn request(
    service_url: &str,
    email: &str,
    tenant_id: uuid::Uuid,
    deployment_name: &str,
) -> Result<IssuedLicense> {
    require_https_or_loopback(service_url, "licence service URL")?;
    let response = http_client()?
        .post(service_url)
        .json(&serde_json::json!({
            "email": email,
            "tenant_id": tenant_id,
            "deployment_name": deployment_name,
        }))
        .send()
        .context("reach the licence service")?;
    let status = response.status();
    let body = response
        .bytes()
        .context("read the licence service answer")?;
    if body.len() > MAX_CERTIFICATE_BYTES {
        bail!("the licence service answer is unexpectedly large");
    }
    if !status.is_success() {
        let detail = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .or_else(|| value.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&body).trim().to_owned());
        bail!("the licence service refused the request ({status}): {detail}");
    }
    let issued: IssuedLicense =
        serde_json::from_slice(&body).context("parse the licence service answer")?;
    require_signed(&issued.certificate)?;
    let named = issued
        .certificate
        .get("tenant_id")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<uuid::Uuid>().ok());
    if named != Some(tenant_id) || issued.tenant_id != tenant_id {
        bail!(
            "the licence service answered for another installation; this installation's tenant id is {tenant_id}"
        );
    }
    Ok(issued)
}

/// The fields of an installed certificate an operator wants to see, without
/// the signature and the raw entitlement body.
pub fn summary(certificate: &Value) -> Value {
    let field = |name: &str| certificate.get(name).cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "id": field("id"),
        "tenant_id": field("tenant_id"),
        "issuer": field("issuer"),
        "sequence": field("sequence"),
        "suites": certificate
            .get("suites")
            .or_else(|| certificate.pointer("/entitlements/suites"))
            .cloned()
            .unwrap_or(Value::Null),
        "issued_at": field("issued_at"),
        "expires_at": field("expires_at"),
        "signed": certificate
            .get("signature")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty()),
    })
}

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
    require_signed(&certificate)?;
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
    require_signed(&certificate)?;
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
    crate::config::rewrite(config_path, &intent)?;
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
    require_https_or_loopback(issuer_url, "issuer URL")?;
    let response = http_client()?
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

/// A one-shot HTTP stub for tests: answers each path with a canned status and
/// JSON body, on a loopback port, for as many requests as are queued.
#[cfg(test)]
pub(crate) mod stub {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Serve `responses` (path → (status, body)) for `requests` connections,
    /// then stop. Returns the base URL. Unknown paths answer 404.
    pub fn serve(responses: Vec<(&'static str, u16, String)>, requests: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            for _ in 0..requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buffer = vec![0_u8; 64 * 1024];
                let mut read = 0;
                loop {
                    let n = stream.read(&mut buffer[read..]).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    read += n;
                    let head = String::from_utf8_lossy(&buffer[..read]);
                    if let Some(end) = head.find("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if read >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                let (status, body) = responses
                    .iter()
                    .find(|(candidate, _, _)| *candidate == path)
                    .map_or((404, "{}".to_owned()), |(_, status, body)| {
                        (*status, body.clone())
                    });
                let reason = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    429 => "Too Many Requests",
                    _ => "Not Found",
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.flush();
            }
        });
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_for(tenant: uuid::Uuid) -> Value {
        serde_json::json!({
            "id": "0f3f6c2a-3c2e-4a7e-9c62-1b4d0f4d6a11",
            "tenant_id": tenant.to_string(),
            "issuer": "https://licenses.rudeless.ai",
            "sequence": 1,
            "suites": ["core"],
            "signature": "c2lnbmVk",
        })
    }

    #[test]
    fn request_returns_the_signed_certificate_for_this_installation() {
        let tenant = crate::launch::installation_tenant_id("thelve-test");
        let answer = serde_json::json!({
            "tenant_id": tenant,
            "certificate_id": "0f3f6c2a-3c2e-4a7e-9c62-1b4d0f4d6a11",
            "suites": ["core"],
            "issuer": "https://licenses.rudeless.ai",
            "certificate": certificate_for(tenant),
            "install_command": "",
            "trust_command": "",
            "reissued": false,
        });
        let base = stub::serve(vec![("/license", 200, answer.to_string())], 1);
        let issued = request(
            &format!("{base}/license"),
            "operator@example.com",
            tenant,
            "thelve-test",
        )
        .unwrap();
        assert_eq!(issued.tenant_id, tenant);
        assert_eq!(issued.suites, ["core"]);
        assert!(!issued.reissued);
        assert_eq!(summary(&issued.certificate)["signed"], Value::Bool(true));
        assert_eq!(
            summary(&issued.certificate)["suites"],
            serde_json::json!(["core"])
        );
    }

    #[test]
    fn request_refuses_a_certificate_for_another_installation() {
        let tenant = crate::launch::installation_tenant_id("thelve-test");
        let other = crate::launch::installation_tenant_id("someone-else");
        let answer = serde_json::json!({
            "tenant_id": other,
            "certificate_id": "0f3f6c2a-3c2e-4a7e-9c62-1b4d0f4d6a11",
            "certificate": certificate_for(other),
        });
        let base = stub::serve(vec![("/license", 200, answer.to_string())], 1);
        let error = request(
            &format!("{base}/license"),
            "o@example.com",
            tenant,
            "thelve-test",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("another installation"), "{error}");
    }

    #[test]
    fn request_repeats_the_service_refusal() {
        let tenant = crate::launch::installation_tenant_id("thelve-test");
        let base = stub::serve(
            vec![(
                "/license",
                429,
                serde_json::json!({"error": "too many licence requests from this address"})
                    .to_string(),
            )],
            1,
        );
        let error = request(
            &format!("{base}/license"),
            "o@example.com",
            tenant,
            "thelve-test",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("429"), "{error}");
        assert!(error.contains("too many licence requests"), "{error}");
    }

    #[test]
    fn request_and_trust_refuse_plain_http_off_loopback() {
        let tenant = crate::launch::installation_tenant_id("thelve-test");
        assert!(request("http://example.com/license", "o@example.com", tenant, "x").is_err());
        assert!(trust("http://example.com", None).is_err());
    }

    #[test]
    fn trust_pins_the_document_digest() {
        let document = serde_json::json!([
            {"issuer": "https://licenses.rudeless.ai", "key_id": "k1", "public_key": "cHVibGlj"}
        ])
        .to_string();
        let base = stub::serve(vec![("/v1/trust", 200, document.clone())], 2);
        let trusted = trust(&base, None).unwrap();
        assert_eq!(trusted["licensing"]["trustedIssuers"][0]["keyId"], "k1");
        let digest = trusted["trustSha256"].as_str().unwrap().to_owned();
        assert!(trust(&base, Some("sha256:0000")).is_err());
        let _ = digest;
    }
}
