//! The first person, created by the launch.
//!
//! With bundled sign-in the appliance runs its own identity service. Somebody
//! still has to exist in it before anyone can open the desk, and asking an
//! operator to read a password out of Secret Manager, find an administration
//! console and fill in a form is a poor first five minutes. So the launch
//! creates that person: it reads the bootstrap administrator's password from
//! the cloud secret store the appliance already uses, asks the sign-in service
//! for a short-lived token, creates one user in the Thelve realm with a
//! generated temporary password, and prints that password once.
//!
//! What this deliberately does not do: keep the password. It is generated
//! here, sent to the appliance, printed to the operator's terminal, and
//! dropped. It is temporary, so the sign-in service requires a new one at the
//! first sign-in and the printed value stops working the moment it is used.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore as _, rngs::OsRng};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    config::{CloudDeployment, Provider},
    process::{self, CommandPlan},
    terraform,
};

/// The realm and client the compose renderer creates for bundled sign-in
/// (`crates/thelve-single-node/src/compose.rs`). Kept in step with it by the
/// live launch, which fails loudly here rather than creating a person in a
/// realm the desk does not use.
const REALM: &str = "thelve";
const BOOTSTRAP_USERNAME: &str = "thelve-bootstrap";
const BOOTSTRAP_SECRET: &str = "keycloak-bootstrap-admin-password";
const MAX_SECRET_BYTES: usize = 4096;

/// What the launch did about the first person.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirstAdministrator {
    /// Created now; the temporary password is printed once and then dropped.
    Created { username: String },
    /// Somebody with this name already exists, so nothing was changed.
    AlreadyExists { username: String },
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

fn client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
        .user_agent(concat!("thelve-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build sign-in client")
}

fn temporary_password() -> Zeroizing<String> {
    let mut bytes = [0_u8; 18];
    OsRng.fill_bytes(&mut bytes);
    let value = URL_SAFE_NO_PAD.encode(bytes);
    bytes.fill(0);
    Zeroizing::new(value)
}

/// Read the bootstrap administrator's password from the cloud secret store.
/// The value stays in memory, is used for one token request, and is never
/// written to a file, argv, or a log line.
fn cloud_secret(
    config_path: &Path,
    intent: &CloudDeployment,
    secret: &str,
) -> Result<Zeroizing<String>> {
    let directory = terraform::workspace(config_path, intent)?;
    let resources = terraform::secret_resources(&directory, intent.spec.provider.kind())?;
    let resource = resources.get(secret).with_context(|| {
        format!("secret container {secret:?} does not exist; run `thelve deploy prepare` first")
    })?;
    let plan = match &intent.spec.provider {
        Provider::Gcp { project_id, .. } => {
            // Terraform reports the fully qualified resource; `gcloud` takes
            // the short id beside `--project`.
            let secret_id = crate::secrets::gcp_secret_id(project_id, resource)
                .with_context(|| format!("secret resource {resource:?} is not in this project"))?;
            CommandPlan::new("gcloud").args([
                "secrets",
                "versions",
                "access",
                "latest",
                "--secret",
                secret_id,
                "--project",
                project_id,
                "--quiet",
            ])
        }
        Provider::Aws { region, .. } => CommandPlan::new("aws").args([
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            resource,
            "--region",
            region,
            "--query",
            "SecretString",
            "--output",
            "text",
        ]),
    };
    let value = process::capture_named(&plan, "read the bootstrap administrator password")?;
    let value = Zeroizing::new(value.trim().to_owned());
    if value.is_empty() || value.len() > MAX_SECRET_BYTES {
        bail!("the bootstrap administrator password is empty or implausibly large");
    }
    Ok(value)
}

/// Create the first person in the appliance's own sign-in service.
///
/// Returns the temporary password with the outcome; the caller prints it once
/// and drops it. An existing user of the same name is left exactly as it is,
/// so a resumed launch neither fails nor resets somebody's password.
///
/// # Errors
///
/// Returns an error when the secret cannot be read, the sign-in service
/// refuses the bootstrap credentials, or the user cannot be created.
pub fn create_first_administrator(
    config_path: &Path,
    intent: &CloudDeployment,
    app_domain: &str,
    email: &str,
) -> Result<(FirstAdministrator, Zeroizing<String>)> {
    let base = format!("https://{app_domain}/sso");
    let http = client()?;
    let password = cloud_secret(config_path, intent, BOOTSTRAP_SECRET)?;
    let policy_secret = cloud_secret(config_path, intent, "oidc/client-secret")?;
    create_administrator(&http, &base, email, password, &policy_secret)
}

pub(crate) fn create_administrator(
    http: &reqwest::blocking::Client,
    base: &str,
    email: &str,
    password: Zeroizing<String>,
    policy_secret: &str,
) -> Result<(FirstAdministrator, Zeroizing<String>)> {
    let token: TokenResponse = http
        .post(format!(
            "{base}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", BOOTSTRAP_USERNAME),
            ("password", password.as_str()),
        ])
        .send()
        .context("reach the appliance's sign-in service")?
        .error_for_status()
        .context("the sign-in service refused the bootstrap administrator")?
        .json()
        .context("read the sign-in service's token answer")?;
    drop(password);
    configure_session_client(http, base, &token.access_token, policy_secret)?;
    // Realm imports leave existing realms untouched. Reconcile presentation for
    // appliances upgraded to a node artifact that carries the Thelve theme.
    http.put(format!("{base}/admin/realms/{REALM}"))
        .bearer_auth(&token.access_token)
        .json(&serde_json::json!({"displayName": "Thelve", "loginTheme": "thelve"}))
        .send()
        .context("configure Thelve sign-in presentation")?
        .error_for_status()
        .context("the sign-in service refused Thelve presentation settings")?;
    let temporary = temporary_password();
    let response = http
        .post(format!("{base}/admin/realms/{REALM}/users"))
        .bearer_auth(&token.access_token)
        .json(&serde_json::json!({
            "username": email,
            "email": email,
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": temporary.as_str(),
                "temporary": true,
            }],
        }))
        .send()
        .context("create the first person in the sign-in service")?;
    let status = response.status();
    if status == reqwest::StatusCode::CONFLICT {
        return Ok((
            FirstAdministrator::AlreadyExists {
                username: email.to_owned(),
            },
            Zeroizing::new(String::new()),
        ));
    }
    if !status.is_success() {
        bail!("the sign-in service refused to create the first person: {status}");
    }
    Ok((
        FirstAdministrator::Created {
            username: email.to_owned(),
        },
        temporary,
    ))
}

/// Reconcile a confidential backend client without resetting the realm's policy.
fn configure_session_client(
    http: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    secret: &str,
) -> Result<()> {
    let root = format!("{base}/admin/realms/{REALM}");
    let clients: Vec<serde_json::Value> = http
        .get(format!("{root}/clients"))
        .query(&[("clientId", "thelve-session-policy")])
        .bearer_auth(token)
        .send()?
        .error_for_status()?
        .json()?;
    let spec = serde_json::json!({
        "clientId": "thelve-session-policy", "enabled": true,
        "protocol": "openid-connect", "publicClient": false,
        "secret": secret, "serviceAccountsEnabled": true,
        "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
        "fullScopeAllowed": true
    });
    if let Some(client) = clients.first() {
        let id = client["id"].as_str().context("session client ID missing")?;
        http.put(format!("{root}/clients/{id}"))
            .bearer_auth(token)
            .json(&spec)
            .send()?
            .error_for_status()?;
    } else {
        http.post(format!("{root}/clients"))
            .bearer_auth(token)
            .json(&spec)
            .send()?
            .error_for_status()?;
    }
    let clients: Vec<serde_json::Value> = http
        .get(format!("{root}/clients"))
        .query(&[("clientId", "thelve-session-policy")])
        .bearer_auth(token)
        .send()?
        .error_for_status()?
        .json()?;
    let id = clients
        .first()
        .and_then(|c| c["id"].as_str())
        .context("session client missing")?;
    let account: serde_json::Value = http
        .get(format!("{root}/clients/{id}/service-account-user"))
        .bearer_auth(token)
        .send()?
        .error_for_status()?
        .json()?;
    let user = account["id"]
        .as_str()
        .context("session service account missing")?;
    let managers: Vec<serde_json::Value> = http
        .get(format!("{root}/clients"))
        .query(&[("clientId", "realm-management")])
        .bearer_auth(token)
        .send()?
        .error_for_status()?
        .json()?;
    let manager = managers
        .first()
        .and_then(|c| c["id"].as_str())
        .context("realm management missing")?;
    let mut roles = Vec::new();
    for role in ["view-realm", "manage-realm", "manage-users"] {
        let value: serde_json::Value = http
            .get(format!("{root}/clients/{manager}/roles/{role}"))
            .bearer_auth(token)
            .send()?
            .error_for_status()?
            .json()?;
        roles.push(value);
    }
    http.post(format!(
        "{root}/users/{user}/role-mappings/clients/{manager}"
    ))
    .bearer_auth(token)
    .json(&roles)
    .send()?
    .error_for_status()?;
    Ok(())
}

/// Resolve the issuer's stable subject after the administrator was created.
pub(crate) fn administrator_subject(
    http: &reqwest::blocking::Client,
    base: &str,
    email: &str,
    password: &str,
) -> Result<String> {
    let token: TokenResponse = http
        .post(format!(
            "{base}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", BOOTSTRAP_USERNAME),
            ("password", password),
        ])
        .send()?
        .error_for_status()?
        .json()?;
    let users: Vec<serde_json::Value> = http
        .get(format!("{base}/admin/realms/{REALM}/users"))
        .query(&[("username", email), ("exact", "true")])
        .bearer_auth(&token.access_token)
        .send()?
        .error_for_status()?
        .json()?;
    if users.len() != 1 {
        bail!("initial administrator does not resolve to exactly one identity");
    }
    let subject = users[0]["id"]
        .as_str()
        .context("administrator identity has no subject")?;
    uuid::Uuid::parse_str(subject).context("bundled administrator subject is not a UUID")?;
    Ok(subject.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_temporary_password_is_url_safe_and_long_enough_to_be_typed_once() {
        let value = temporary_password();
        assert_eq!(value.len(), 24, "18 random bytes in url-safe base64");
        assert!(
            value
                .chars()
                .all(|character| character.is_ascii_alphanumeric()
                    || character == '-'
                    || character == '_'),
            "a password an operator retypes must survive a copy through a terminal"
        );
        assert_ne!(
            *value,
            *temporary_password(),
            "each launch generates its own"
        );
    }

    #[test]
    fn the_realm_and_bootstrap_names_match_the_renderer() {
        // Pinned against crates/thelve-single-node/src/compose.rs in the
        // Thelve repository; a drift here creates a person in a realm the
        // desk never signs in to.
        assert_eq!(REALM, "thelve");
        assert_eq!(BOOTSTRAP_USERNAME, "thelve-bootstrap");
        assert_eq!(BOOTSTRAP_SECRET, "keycloak-bootstrap-admin-password");
    }
}
