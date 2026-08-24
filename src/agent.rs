use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::RngCore as _;
use reqwest::Url;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

const PROFILE_SCHEMA: &str = "thelve.agent-profile.v1";
const APPROVAL_POLICY_SCHEMA: &str = "thelve.capability-approval-policy.v1";
const SIGNED_TARGET: &str = "/api/v1/aauth/capabilities/invoke";
const MAX_ERROR_DETAIL: usize = 2_048;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalControl {
    Confirmation,
    FourEyes,
}

impl ApprovalControl {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmation => "confirmation",
            Self::FourEyes => "four_eyes",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfile {
    pub schema_version: String,
    pub name: String,
    pub api_url: String,
    pub tenant_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<Uuid>,
    pub key_id: String,
    pub signing_key_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct CapabilityCall {
    pub capability: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub input: Value,
    pub approval_id: Option<Uuid>,
    pub idempotency_key: String,
}

#[derive(Clone, Debug)]
pub struct PlanRequest {
    pub capability: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub input: Value,
    pub reason: String,
    pub control: ApprovalControl,
    pub expires_in_seconds: u32,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct FrozenCapabilityPolicy {
    schema_version: String,
    capability: String,
    resource_type: String,
    #[serde(default)]
    resource_id: Option<String>,
    input: Value,
    input_sha256: String,
    idempotency_key: String,
}

pub struct AgentClient {
    profile: AgentProfile,
    signer: SigningKey,
    public_jwk: Value,
    http: Client,
}

impl std::fmt::Debug for AgentClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentClient")
            .field("profile", &self.profile.name)
            .field("api_url", &self.profile.api_url)
            .field("tenant_id", &self.profile.tenant_id)
            .field("delegation_id", &self.profile.delegation_id)
            .field("key_id", &self.profile.key_id)
            .finish_non_exhaustive()
    }
}

impl AgentClient {
    pub fn load(profile_name: &str) -> Result<Self> {
        let profile = load_profile(profile_name)?;
        let seed = read_private_seed(&profile.signing_key_file)?;
        let signer = SigningKey::from_bytes(&seed);
        let public_jwk = public_jwk(&signer);
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .user_agent(concat!("thelve-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build Thelve API client")?;
        Ok(Self {
            profile,
            signer,
            public_jwk,
            http,
        })
    }

    pub fn invoke(&self, call: CapabilityCall) -> Result<Value> {
        validate_call(&call)?;
        let delegation_id = self.profile.delegation_id.ok_or_else(|| {
            anyhow!(
                "profile {:?} is not bound to a delegation; run `thelve agent profile bind`",
                self.profile.name
            )
        })?;
        let mut envelope = json!({
            "id": Uuid::new_v4().to_string(),
            "ts": Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true),
            "target": SIGNED_TARGET,
            "tenant_id": self.profile.tenant_id,
            "delegation_id": delegation_id,
            "capability": call.capability,
            "resource_type": call.resource_type,
            "input": call.input,
            "idempotency_key": call.idempotency_key,
            "signature_key": self.public_jwk,
            "signature_agent": self.public_jwk,
            "signature": {
                "keyid": self.profile.key_id,
                "alg": "EdDSA",
                "sig": ""
            }
        });
        if let Some(resource_id) = call.resource_id {
            envelope["resource_id"] = Value::String(resource_id);
        }
        if let Some(approval_id) = call.approval_id {
            envelope["approval_id"] = Value::String(approval_id.to_string());
        }
        let mut unsigned = envelope.clone();
        unsigned
            .as_object_mut()
            .expect("signed envelope is an object")
            .remove("signature");
        let canonical = serde_json::to_vec(&unsigned).context("serialize signed request")?;
        let signature = self.signer.sign(&canonical);
        envelope["signature"]["sig"] = Value::String(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        );

        let endpoint = format!("{}{}", self.profile.api_url, SIGNED_TARGET);
        let response = self
            .http
            .post(endpoint)
            .json(&envelope)
            .send()
            .context("send signed Thelve capability request")?;
        let status = response.status();
        let body = response
            .bytes()
            .context("read Thelve capability response")?;
        let value: Value = serde_json::from_slice(&body).unwrap_or_else(|_| {
            json!({"detail": String::from_utf8_lossy(&body[..body.len().min(MAX_ERROR_DETAIL)])})
        });
        if !status.is_success() {
            let detail = value
                .get("detail")
                .or_else(|| value.get("title"))
                .and_then(Value::as_str)
                .unwrap_or("Thelve rejected the request");
            bail!("Thelve API returned {status}: {}", bounded(detail));
        }
        Ok(value)
    }

    pub fn result(&self, call: CapabilityCall) -> Result<Value> {
        let response = self.invoke(call)?;
        response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("Thelve capability response did not contain a result"))
    }

    pub fn catalog(&self) -> Result<Value> {
        self.result(CapabilityCall {
            capability: "capabilities.list".into(),
            resource_type: "capability_catalog".into(),
            resource_id: None,
            input: json!({}),
            approval_id: None,
            idempotency_key: Uuid::new_v4().to_string(),
        })
    }

    pub fn descriptor(&self, capability: &str) -> Result<Value> {
        let catalog = self.catalog()?;
        catalog
            .get("items")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.get("id").and_then(Value::as_str) == Some(capability))
            })
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "the live governed catalog does not expose capability {capability:?} to this profile"
                )
            })
    }

    pub fn invoke_guarded(&self, call: CapabilityCall) -> Result<Value> {
        let descriptor = self.descriptor(&call.capability)?;
        let risk = descriptor
            .get("risk")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if risk != "read" && call.approval_id.is_none() {
            bail!(
                "{risk} capability {:?} requires an immutable plan; use `thelve agent plan` and `thelve agent apply`",
                call.capability
            );
        }
        self.invoke(call)
    }

    pub fn create_plan(&self, request: PlanRequest) -> Result<Value> {
        if request.reason.trim().is_empty() {
            bail!("a human-readable plan reason is required");
        }
        if !(60..=86_400).contains(&request.expires_in_seconds) {
            bail!("plan expiry must be between 60 seconds and 24 hours");
        }
        let descriptor = self.descriptor(&request.capability)?;
        if descriptor.get("ai_tool").and_then(Value::as_bool) != Some(true) {
            bail!(
                "capability {:?} is not available to AI actors",
                request.capability
            );
        }
        let risk = descriptor
            .get("risk")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let approval = descriptor
            .get("approval")
            .and_then(Value::as_str)
            .unwrap_or("always");
        if request.control == ApprovalControl::Confirmation
            && (risk == "destructive" || approval == "always")
        {
            bail!(
                "{risk} / {approval} capability {:?} requires four-eyes approval",
                request.capability
            );
        }

        let approval_id = Uuid::new_v4();
        let target_idempotency = request
            .idempotency_key
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let policy_snapshot = capability_approval_policy(
            &request.capability,
            &request.resource_type,
            request.resource_id.as_deref(),
            &request.input,
            &target_idempotency,
        )?;
        let expires_at =
            Utc::now() + chrono::Duration::seconds(i64::from(request.expires_in_seconds));
        let approval_spec = json!({
            "id": approval_id,
            "tenant_id": self.profile.tenant_id,
            "action": request.capability,
            "resource_type": request.resource_type,
            "resource_id": request.resource_id,
            "requested_reason": request.reason,
            "policy_snapshot": policy_snapshot,
            "control": request.control.as_str(),
            "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Micros, true),
        });
        self.result(CapabilityCall {
            capability: "approvals.request".into(),
            resource_type: "approval".into(),
            resource_id: Some(approval_id.to_string()),
            input: approval_spec,
            approval_id: None,
            idempotency_key: format!("plan:{approval_id}"),
        })
    }

    pub fn read_plan(&self, approval_id: Uuid) -> Result<Value> {
        self.result(CapabilityCall {
            capability: "approvals.read".into(),
            resource_type: "approval".into(),
            resource_id: Some(approval_id.to_string()),
            input: json!({"id": approval_id}),
            approval_id: None,
            idempotency_key: Uuid::new_v4().to_string(),
        })
    }

    pub fn list_plans(&self, status: Option<&str>, limit: u16) -> Result<Value> {
        let mut input = json!({"limit": limit.clamp(1, 100)});
        if let Some(status) = status {
            input["status"] = Value::String(status.to_owned());
        }
        self.result(CapabilityCall {
            capability: "approvals.list".into(),
            resource_type: "approval".into(),
            resource_id: None,
            input,
            approval_id: None,
            idempotency_key: Uuid::new_v4().to_string(),
        })
    }

    pub fn apply_plan(&self, approval_id: Uuid) -> Result<Value> {
        let record = self.read_plan(approval_id)?;
        if record.get("status").and_then(Value::as_str) != Some("approved") {
            bail!("plan {approval_id} is not approved");
        }
        let spec = record
            .get("spec")
            .ok_or_else(|| anyhow!("approval record is missing spec"))?;
        let profile_tenant = self.profile.tenant_id.to_string();
        if spec.get("tenant_id").and_then(Value::as_str) != Some(profile_tenant.as_str()) {
            bail!("plan {approval_id} belongs to a different tenant");
        }
        let policy: FrozenCapabilityPolicy = serde_json::from_value(
            spec.get("policy_snapshot")
                .cloned()
                .ok_or_else(|| anyhow!("plan has no immutable policy snapshot"))?,
        )
        .context("decode immutable capability plan")?;
        validate_frozen_policy(&policy)?;
        if spec.get("action").and_then(Value::as_str) != Some(policy.capability.as_str())
            || spec.get("resource_type").and_then(Value::as_str)
                != Some(policy.resource_type.as_str())
            || optional_string(spec.get("resource_id")) != policy.resource_id.as_deref()
        {
            bail!("approval scope and immutable capability plan disagree");
        }
        self.invoke(CapabilityCall {
            capability: policy.capability,
            resource_type: policy.resource_type,
            resource_id: policy.resource_id,
            input: policy.input,
            approval_id: Some(approval_id),
            idempotency_key: policy.idempotency_key,
        })
    }
}

pub fn create_profile(
    name: &str,
    api_url: &str,
    tenant_id: Uuid,
    key_id: &str,
    seed_file: Option<&Path>,
) -> Result<Value> {
    validate_profile_name(name)?;
    validate_key_id(key_id)?;
    let api_url = normalize_api_url(api_url)?;
    let root = config_root()?;
    let profiles = root.join("profiles");
    let keys = root.join("keys");
    create_private_directory(&root)?;
    create_private_directory(&profiles)?;
    create_private_directory(&keys)?;
    let profile_path = profiles.join(format!("{name}.yaml"));
    if profile_path.exists() {
        bail!("profile {name:?} already exists");
    }
    let key_path = keys.join(format!("{name}.seed"));
    let seed = if let Some(seed_file) = seed_file {
        read_seed_source(seed_file)?
    } else {
        let mut seed = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        seed
    };
    write_private_new(
        &key_path,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(seed)
            .as_bytes(),
    )?;
    let signer = SigningKey::from_bytes(&seed);
    let profile = AgentProfile {
        schema_version: PROFILE_SCHEMA.into(),
        name: name.into(),
        api_url,
        tenant_id,
        delegation_id: None,
        key_id: key_id.into(),
        signing_key_file: key_path,
    };
    write_profile_new(&profile_path, &profile)?;
    Ok(json!({
        "profile": redacted_profile(&profile),
        "public_jwk": public_jwk(&signer),
        "next": "Register this public JWK, create and approve a bounded AAuth delegation, then bind its id with `thelve agent profile bind`."
    }))
}

pub fn bind_profile(name: &str, delegation_id: Uuid) -> Result<Value> {
    if delegation_id.is_nil() {
        bail!("delegation id cannot be nil");
    }
    let path = profile_path(name)?;
    let mut profile = load_profile(name)?;
    profile.delegation_id = Some(delegation_id);
    write_private_replace(&path, serde_yaml::to_string(&profile)?.as_bytes())?;
    Ok(redacted_profile(&profile))
}

pub fn show_profile(name: &str) -> Result<Value> {
    Ok(redacted_profile(&load_profile(name)?))
}

pub fn show_public_key(name: &str) -> Result<Value> {
    let profile = load_profile(name)?;
    let seed = read_private_seed(&profile.signing_key_file)?;
    Ok(public_jwk(&SigningKey::from_bytes(&seed)))
}

pub fn read_json_input(path: &Path) -> Result<Value> {
    let bytes = if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut bytes)
            .context("read JSON input from stdin")?;
        bytes
    } else {
        fs::read(path).with_context(|| format!("read JSON input {}", path.display()))?
    };
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse JSON input {}", path.display()))?;
    if !value.is_object() {
        bail!("capability input must be a JSON object");
    }
    Ok(value)
}

fn capability_approval_policy(
    capability: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    input: &Value,
    idempotency_key: &str,
) -> Result<Value> {
    let canonical =
        serde_json_canonicalizer::to_vec(input).context("canonicalize capability input")?;
    Ok(json!({
        "schema_version": APPROVAL_POLICY_SCHEMA,
        "capability": capability,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "input": input,
        "input_sha256": format!("sha256:{:x}", Sha256::digest(canonical)),
        "idempotency_key": idempotency_key,
    }))
}

fn validate_frozen_policy(policy: &FrozenCapabilityPolicy) -> Result<()> {
    if policy.schema_version != APPROVAL_POLICY_SCHEMA {
        bail!(
            "unsupported approval policy schema {:?}",
            policy.schema_version
        );
    }
    let expected = capability_approval_policy(
        &policy.capability,
        &policy.resource_type,
        policy.resource_id.as_deref(),
        &policy.input,
        &policy.idempotency_key,
    )?;
    if expected.get("input_sha256").and_then(Value::as_str) != Some(policy.input_sha256.as_str()) {
        bail!("approval plan input digest does not match its frozen input");
    }
    validate_call(&CapabilityCall {
        capability: policy.capability.clone(),
        resource_type: policy.resource_type.clone(),
        resource_id: policy.resource_id.clone(),
        input: policy.input.clone(),
        approval_id: None,
        idempotency_key: policy.idempotency_key.clone(),
    })
}

fn validate_call(call: &CapabilityCall) -> Result<()> {
    if !normalized_identifier(&call.capability, 128)
        || !normalized_identifier(&call.resource_type, 128)
    {
        bail!("capability and resource type must be normalized dotted identifiers");
    }
    if !call.input.is_object() {
        bail!("capability input must be a JSON object");
    }
    if call.idempotency_key.trim() != call.idempotency_key
        || call.idempotency_key.is_empty()
        || call.idempotency_key.len() > 255
    {
        bail!("idempotency key must contain 1-255 trimmed characters");
    }
    if call
        .resource_id
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 512 || value.trim() != value)
    {
        bail!("resource id must contain 1-512 trimmed characters");
    }
    Ok(())
}

fn normalized_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value == value.to_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn load_profile(name: &str) -> Result<AgentProfile> {
    let path = profile_path(name)?;
    let bytes = fs::read(&path).with_context(|| {
        format!(
            "read agent profile {}; create it with `thelve agent profile create`",
            path.display()
        )
    })?;
    let profile: AgentProfile = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("parse agent profile {}", path.display()))?;
    if profile.schema_version != PROFILE_SCHEMA || profile.name != name {
        bail!("agent profile schema or name is invalid");
    }
    validate_profile_name(&profile.name)?;
    validate_key_id(&profile.key_id)?;
    let normalized = normalize_api_url(&profile.api_url)?;
    if normalized != profile.api_url || profile.tenant_id.is_nil() {
        bail!("agent profile contains invalid API or tenant identity");
    }
    Ok(profile)
}

fn profile_path(name: &str) -> Result<PathBuf> {
    validate_profile_name(name)?;
    Ok(config_root()?.join("profiles").join(format!("{name}.yaml")))
}

fn config_root() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("THELVE_CONFIG_DIR") {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            bail!("THELVE_CONFIG_DIR must be an absolute path");
        }
        return Ok(path);
    }
    if let Some(value) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(value).join("thelve"));
    }
    let home =
        std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME or THELVE_CONFIG_DIR is required"))?;
    Ok(PathBuf::from(home).join(".config").join("thelve"))
}

fn normalize_api_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value).context("parse Thelve API URL")?;
    if url.query().is_some()
        || url.fragment().is_some()
        || url.username() != ""
        || url.password().is_some()
    {
        bail!("API URL must not contain credentials, query, or fragment");
    }
    let host = url.host_str().unwrap_or_default();
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("Thelve API must use HTTPS; HTTP is accepted only for loopback development");
    }
    let normalized_path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&normalized_path);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn validate_profile_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        bail!("profile name must use 1-64 lowercase letters, digits, hyphens, or underscores");
    }
    Ok(())
}

fn validate_key_id(value: &str) -> Result<()> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > 255
        || value.chars().any(char::is_control)
    {
        bail!("AAuth key id must contain 1-255 trimmed printable characters");
    }
    Ok(())
}

fn public_jwk(signer: &SigningKey) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signer.verifying_key().as_bytes()),
        "alg": "EdDSA",
        "use": "sig",
    })
}

fn redacted_profile(profile: &AgentProfile) -> Value {
    json!({
        "schema_version": profile.schema_version,
        "name": profile.name,
        "api_url": profile.api_url,
        "tenant_id": profile.tenant_id,
        "delegation_id": profile.delegation_id,
        "key_id": profile.key_id,
        "key_storage": "local_private_file",
    })
}

fn read_seed_source(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("read seed source {}", path.display()))?;
    decode_seed(&bytes)
}

fn read_private_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect signing key {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("signing key must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "signing key {} must not be accessible by group or others",
                path.display()
            );
        }
    }
    Ok(Zeroizing::new(decode_seed(&fs::read(path).with_context(
        || format!("read signing key {}", path.display()),
    )?)?))
}

fn decode_seed(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| anyhow!("AAuth seed must contain exactly 32 bytes"));
    }
    let text = std::str::from_utf8(bytes)
        .context("AAuth seed must be raw bytes or base64url text")?
        .trim();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .context("decode base64url AAuth seed")?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("AAuth seed must decode to exactly 32 bytes"))
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect {}", path.display()))?;
    }
    Ok(())
}

fn write_profile_new(path: &Path, profile: &AgentProfile) -> Result<()> {
    write_private_new(path, serde_yaml::to_string(profile)?.as_bytes())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create private file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write private file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync private file {}", path.display()))?;
    Ok(())
}

fn write_private_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("profile path has no parent"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Uuid::new_v4()
    ));
    write_private_new(&temporary, bytes)?;
    fs::rename(&temporary, path)
        .with_context(|| format!("atomically update {}", path.display()))?;
    Ok(())
}

fn optional_string(value: Option<&Value>) -> Option<&str> {
    value.and_then(|value| {
        if value.is_null() {
            None
        } else {
            value.as_str()
        }
    })
}

fn bounded(value: &str) -> &str {
    let end = value
        .char_indices()
        .nth(MAX_ERROR_DETAIL)
        .map_or(value.len(), |(index, _)| index);
    &value[..end]
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn profile_creation_never_serializes_private_key_material() {
        let root = TempDir::new().expect("temp config");
        unsafe { std::env::set_var("THELVE_CONFIG_DIR", root.path()) };
        let value = create_profile(
            "local",
            "http://127.0.0.1:8080",
            Uuid::new_v4(),
            "local-agent",
            None,
        )
        .expect("profile");
        let rendered = serde_json::to_string(&value).expect("result JSON");
        assert!(!rendered.contains("seed"));
        assert!(!rendered.contains("signing_key_file"));
        let profile = load_profile("local").expect("load profile");
        assert!(profile.signing_key_file.exists());
        unsafe { std::env::remove_var("THELVE_CONFIG_DIR") };
    }

    #[test]
    fn frozen_policy_detects_any_input_change() {
        let policy = capability_approval_policy(
            "queues.configure",
            "queue",
            Some("queue-1"),
            &json!({"priority": 80}),
            "one",
        )
        .expect("policy");
        let mut decoded: FrozenCapabilityPolicy =
            serde_json::from_value(policy).expect("decode policy");
        validate_frozen_policy(&decoded).expect("valid policy");
        decoded.input["priority"] = json!(81);
        assert!(validate_frozen_policy(&decoded).is_err());
    }

    #[test]
    fn remote_plaintext_api_is_refused() {
        assert!(normalize_api_url("http://example.com").is_err());
        assert_eq!(
            normalize_api_url("http://localhost:8080/").expect("loopback"),
            "http://localhost:8080"
        );
    }
}
