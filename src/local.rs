//! Colima hosts the ordinary Linux compose plan; the CLI owns its lifecycle.
use crate::{
    process::{self, CommandPlan},
    secrets,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub struct Request {
    pub name: String,
    pub directory: PathBuf,
    pub release: PathBuf,
    pub email: String,
    pub approve: bool,
    pub issuer_url: Option<String>,
    pub license_service_url: Option<String>,
    pub issuer_trust_sha256: Option<String>,
}
fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
fn ssh(args: &[&str]) -> Result<String> {
    process::capture(
        &CommandPlan::new("colima")
            .args(["ssh", "--"])
            .args(args.iter().copied()),
    )
}
fn ssh_run(args: &[&str]) -> Result<()> {
    process::inherit(
        &CommandPlan::new("colima")
            .args(["ssh", "--"])
            .args(args.iter().copied()),
    )
}
fn protected_write(p: &Path, bytes: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(bytes)?;
    Ok(())
}
fn compose(arguments: &[&str]) -> Result<()> {
    ssh_run(
        &[
            &[
                "sudo",
                "docker",
                "compose",
                "--project-name",
                "thelve",
                "--project-directory",
                "/opt/thelve/current",
                "--env-file",
                "/etc/thelve/runtime.env",
                "-f",
                "/opt/thelve/current/compose.yaml",
            ][..],
            arguments,
        ]
        .concat(),
    )
}

const DEVELOPER_CA_DIRECTORY: &str = "/var/lib/thelve-developer-ca";
const DEVELOPER_CA_ROOT: &str = "/var/lib/thelve-developer-ca/root.crt";
const CADDY_LOCAL_AUTHORITY: &str = "/data/caddy/pki/authorities/local";

fn use_persistent_developer_ca(compose_path: &Path) -> Result<()> {
    let mut document: Value =
        serde_yaml::from_slice(&fs::read(compose_path)?).context("parse rendered compose plan")?;
    let mounts = document
        .pointer_mut("/services/caddy/volumes")
        .and_then(Value::as_array_mut)
        .context("rendered compose plan has no Caddy volumes")?;
    if !mounts.iter().any(|mount| {
        mount
            .as_str()
            .is_some_and(|mount| mount.contains(CADDY_LOCAL_AUTHORITY))
    }) {
        mounts.push(json!(format!(
            "{DEVELOPER_CA_DIRECTORY}:{CADDY_LOCAL_AUTHORITY}:rw"
        )));
    }
    fs::write(compose_path, serde_yaml::to_string(&document)?)?;
    Ok(())
}

fn prepare_persistent_developer_ca() -> Result<()> {
    // Preserve the authority from an appliance created before this directory
    // was split out. New machines leave it empty and Caddy creates the
    // authority on first start.
    ssh_run(&[
        "sudo",
        "sh",
        "-c",
        "mkdir -p /var/lib/thelve-developer-ca; if test ! -f /var/lib/thelve-developer-ca/root.key && test -f /var/lib/thelve/caddy/data/caddy/pki/authorities/local/root.key; then cp -a /var/lib/thelve/caddy/data/caddy/pki/authorities/local/. /var/lib/thelve-developer-ca/; fi; chown -R 1000:1000 /var/lib/thelve-developer-ca; chmod 700 /var/lib/thelve-developer-ca",
    ])
}

// Verify the packaged host executable before running it. The caller selects
// the local package and its trust store, just as they select an installer.
fn verify_host_tool(release: &Path) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest as _, Sha256};
    let document: Value =
        serde_json::from_slice(&fs::read(release.join("bundle/deployment.release.json"))?)?;
    let canonical = serde_json_canonicalizer::to_vec(&document)?;
    let envelope: Value = serde_json::from_slice(&fs::read(
        release.join("bundle/deployment.release.sig.json"),
    )?)?;
    let trust: Value = serde_json::from_slice(&fs::read(release.join("trust.json"))?)?;
    if envelope["algorithm"] != "ed25519" {
        bail!("unsupported release signature");
    }
    let key = trust["keys"]
        .as_array()
        .context("release trust keys missing")?
        .iter()
        .find(|k| k["keyId"] == envelope["keyId"])
        .context("release signing key is not trusted")?;
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key["publicKey"].as_str().context("public key missing")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key"))?;
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD.decode(
            envelope["signature"]
                .as_str()
                .context("signature missing")?,
        )?,
    )?;
    VerifyingKey::from_bytes(&public)?.verify_strict(&canonical, &signature)?;
    let relative = "artifacts/local-thelve-node";
    let artifact = document["spec"]["artifacts"]
        .as_array()
        .context("release artifacts missing")?
        .iter()
        .find(|a| a["path"] == relative)
        .context("prebuilt host tool missing from signed release")?;
    let bytes = fs::read(release.join("bundle").join(relative))?;
    if artifact["sha256"] != format!("sha256:{:x}", Sha256::digest(&bytes))
        || artifact["sizeBytes"].as_u64() != Some(bytes.len() as u64)
    {
        bail!("prebuilt host tool does not match the signed release");
    }
    Ok(())
}

pub fn launch(request: Request) -> Result<()> {
    if !request.approve {
        bail!("local launch creates an appliance inside Colima; rerun with --approve");
    }
    if request.name.is_empty()
        || request.name.len() > 50
        || !request
            .name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        bail!("local name must contain 1–50 lowercase letters, digits, or hyphens");
    }
    if process::capture(&CommandPlan::new("docker").args(["context", "show"]))?.trim() != "colima" {
        bail!("select the default Colima Docker context with `docker context use colima`");
    }
    process::inherit(&CommandPlan::new("colima").arg("status"))?;
    let release = request.release.canonicalize()?;
    for file in [
        "release-ref",
        "trust.json",
        "thelve-node",
        "bundle/artifacts/local-thelve-node",
        "bundle/artifacts/local-node-template.yaml",
        "bundle/deployment.release.json",
    ] {
        if !release.join(file).is_file() {
            bail!("development release is incomplete: missing {file}");
        }
    }
    verify_host_tool(&release)?;
    let verification: Value = serde_json::from_str(&process::capture(
        &CommandPlan::new(path(&release.join("bundle/artifacts/local-thelve-node"))).args([
            "verify",
            "--bundle",
            &path(&release.join("bundle")),
            "--trust-store",
            &path(&release.join("trust.json")),
        ]),
    )?)?;
    if verification["releaseSha256"].as_str()
        != Some(fs::read_to_string(release.join("release-ref"))?.trim())
    {
        bail!("release-ref does not match the verified signed release");
    }
    fs::create_dir_all(&request.directory)?;
    let directory = request.directory.canonicalize()?;
    let marker = ssh(&[
        "sudo",
        "sh",
        "-c",
        "if test -f /etc/thelve/local-owner; then cat /etc/thelve/local-owner; elif test -e /etc/thelve/node.yaml; then echo unmanaged; fi",
    ])?;
    let owner = format!("{}:{}", request.name, path(&directory));
    if !marker.trim().is_empty() && marker.trim() != owner {
        bail!("Colima already contains another appliance; refusing to overwrite it");
    }
    let profiles = process::capture(&CommandPlan::new("colima").args(["list", "--json"]))?;
    let profile = profiles
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|profile| profile["name"] == "default")
        .context("default Colima profile is unavailable")?;
    let address = profile["address"]
        .as_str()
        .filter(|address| !address.is_empty())
        .context("Colima needs a reachable VM address; start it with --network-address")?;
    let domains = crate::launch::default_domains(address)?;
    let node_path = directory.join("node.yaml");
    if !node_path.exists() {
        println!("==> generating correlated local secrets and bundled identity configuration");
        let mut config: Value = serde_yaml::from_slice(&fs::read(
            release.join("bundle/artifacts/local-node-template.yaml"),
        )?)?;
        config["metadata"]["name"] = json!(request.name);
        let spec = &mut config["spec"];
        spec["releaseRef"] = json!(fs::read_to_string(release.join("release-ref"))?.trim());
        spec["hosting"] = json!("metal");
        spec["localDevelopment"] = json!(true);
        spec["domains"] = json!(domains);
        spec["networking"]["advertisedIpv4"] = json!(address);
        spec["identity"] = json!({"mode":"bundled_keycloak"});
        spec["data"]["objects"] = json!({"mode":"bundled"});
        spec["tls"]["contactEmail"] = json!(request.email);
        let secret_dir = directory.join("secrets");
        initialize_secret_directory(&secret_dir)?;
        let mut bindings = Vec::new();
        for name in
            secrets::generated_internal_values("s3://thelve-local-backups/appliance")?.keys()
        {
            let filename = name.replace('/', "--");
            bindings.push(json!({"id":name,"source":{"provider":"local_file","path":format!("/etc/thelve/secrets/{filename}")}}));
        }
        spec["secretBindings"] = json!(bindings);
        spec["licensing"] = {
            let trust = crate::license::trust(
                request
                    .issuer_url
                    .as_deref()
                    .unwrap_or(crate::license::DEFAULT_ISSUER_URL),
                request.issuer_trust_sha256.as_deref(),
            )?;
            let issued = crate::license::request(
                request
                    .license_service_url
                    .as_deref()
                    .unwrap_or(crate::license::DEFAULT_LICENSE_SERVICE_URL),
                &request.email,
                crate::launch::installation_tenant_id(&request.name),
                &request.name,
            )?;
            json!({"trustedIssuers":trust["licensing"]["trustedIssuers"],"certificate":issued.certificate})
        };
        protected_write(&node_path, serde_yaml::to_string(&config)?.as_bytes())?;
    }
    let mut config: Value = serde_yaml::from_slice(&fs::read(&node_path)?)?;
    if config["spec"]["releaseRef"].as_str()
        != Some(fs::read_to_string(release.join("release-ref"))?.trim())
    {
        config["spec"]["releaseRef"] =
            json!(fs::read_to_string(release.join("release-ref"))?.trim());
        fs::write(&node_path, serde_yaml::to_string(&config)?)?;
    }
    let render_stage = tempfile::tempdir_in(&directory)?;
    let render = render_stage.path().join("render");
    if !render.exists() {
        process::inherit(
            &CommandPlan::new(path(&release.join("bundle/artifacts/local-thelve-node"))).args([
                "render",
                "--config",
                &path(&node_path),
                "--bundle",
                &path(&release.join("bundle")),
                "--trust-store",
                &path(&release.join("trust.json")),
                "--output",
                &path(&render),
            ]),
        )?;
        for file in [
            "redis.conf",
            "redis-entrypoint.sh",
            "keycloak-entrypoint.sh",
            "postgres-entrypoint.sh",
        ] {
            fs::copy(
                release
                    .join("bundle/artifacts")
                    .join(format!("local-{file}")),
                render.join(file),
            )?;
        }
        // The development release signs this template with Caddy's internal issuer.
        fs::copy(
            release.join("bundle/artifacts/Caddyfile.tmpl"),
            render.join("Caddyfile"),
        )?;
        use_persistent_developer_ca(&render.join("compose.yaml"))?;
    }
    println!("==> staging the verified appliance in Colima");
    ssh_run(&[
        "sudo",
        "mkdir",
        "-p",
        "/etc/thelve/secrets",
        "/opt/thelve/current",
        "/opt/thelve/bin",
        "/var/lib/thelve",
    ])?;
    prepare_persistent_developer_ca()?;
    ssh_run(&[
        "sudo",
        "cp",
        "-R",
        &format!("{}/.", path(&render)),
        "/opt/thelve/current/",
    ])?;
    ssh_run(&[
        "sudo",
        "cp",
        &path(&render.join("runtime.env")),
        "/etc/thelve/runtime.env",
    ])?;
    ssh_run(&["sudo", "cp", &path(&node_path), "/etc/thelve/node.yaml"])?;
    ssh_run(&[
        "sudo",
        "cp",
        "-R",
        &format!("{}/secrets/.", path(&directory)),
        "/etc/thelve/secrets/",
    ])?;
    ssh_run(&["sudo", "chown", "-R", "root:root", "/etc/thelve/secrets"])?;
    ssh_run(&["sudo", "chmod", "700", "/etc/thelve/secrets"])?;
    ssh_run(&[
        "sudo",
        "cp",
        &path(&release.join("bundle/artifacts/thelve-node")),
        "/opt/thelve/bin/thelve-node",
    ])?;
    ssh_run(&[
        "sudo",
        "chmod",
        "755",
        "/opt/thelve/bin/thelve-node",
        "/opt/thelve/current/redis-entrypoint.sh",
        "/opt/thelve/current/postgres-entrypoint.sh",
        "/opt/thelve/current/keycloak-entrypoint.sh",
    ])?;
    let owner_path = directory.join("owner");
    fs::write(&owner_path, format!("{owner}\n"))?;
    ssh_run(&["sudo", "cp", &path(&owner_path), "/etc/thelve/local-owner"])?;
    ssh_run(&[
        "sudo",
        "sh",
        "-c",
        "mkdir -p /run/thelve; chmod 711 /run/thelve; mkdir -p /var/lib/thelve/postgres /var/lib/thelve/redis /var/lib/thelve/minio /var/lib/thelve/caddy/data/caddy/pki/authorities /var/lib/thelve/caddy/config; chown 999:999 /var/lib/thelve/postgres /var/lib/thelve/redis; chown 1000:1000 /var/lib/thelve/minio; chown -R 1000:1000 /var/lib/thelve/caddy",
    ])?;
    ssh_run(&[
        "sudo",
        "/opt/thelve/bin/thelve-node",
        "activate-secrets",
        "--config",
        "/etc/thelve/node.yaml",
    ])?;
    println!("==> starting the appliance and waiting for health checks");
    let receipt_path = directory.join("launch-receipt.json");
    let release_changed = if receipt_path.exists() {
        let previous: Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        previous["release_ref"] != config["spec"]["releaseRef"]
    } else {
        false
    };
    let mut up = vec![
        "up",
        "--detach",
        "--pull",
        "never",
        "--no-build",
        "--wait",
        "--wait-timeout",
        "600",
    ];
    // Mounted presentation artifacts are cached by the identity service.
    // A release change must refresh those caches as well as service images.
    if release_changed {
        up.push("--force-recreate");
    }
    compose(&up)?;
    let domain = config["spec"]["domains"]["app"]
        .as_str()
        .context("app domain missing")?;
    finish_administrator(&directory, domain, &request.email)?;
    fs::write(
        directory.join("launch-receipt.json"),
        serde_json::to_vec_pretty(
            &json!({"schema_version":"thelve.local-launch-receipt.v1","name":request.name,"provider":"colima","release_ref":config["spec"]["releaseRef"],"app_url":format!("https://{domain}"),"ready":true,"secret_values_recorded":false}),
        )?,
    )?;
    println!("Thelve is ready at https://{domain}");
    Ok(())
}

fn finish_administrator(directory: &Path, domain: &str, email: &str) -> Result<()> {
    let ca = read_developer_ca()?;
    let ca_path = directory.join("local-ca.crt");
    fs::write(&ca_path, &ca)?;
    trust_developer_ca(&ca_path)?;
    let http = reqwest::blocking::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes())?)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    wait_for_local_https(&http, domain)?;
    let password = zeroize::Zeroizing::new(fs::read_to_string(
        directory.join("secrets/keycloak-bootstrap-admin-password"),
    )?);
    let (result, temporary) = crate::identity::create_administrator(
        &http,
        &format!("https://{domain}/sso"),
        email,
        password,
        &zeroize::Zeroizing::new(fs::read_to_string(
            directory.join("secrets/oidc--client-secret"),
        )?),
    )?;
    match result {
        crate::identity::FirstAdministrator::Created { username } => {
            // This protected handoff file lets a developer recover the first password
            // if their terminal disconnects. It is never put in a receipt or log.
            protected_write(
                &directory.join("initial-admin-password"),
                temporary.as_bytes(),
            )?;
            println!(
                "Administrator: {username}\nTemporary password: {}\nYou must change this password at first sign-in.",
                temporary.as_str()
            );
        }
        crate::identity::FirstAdministrator::AlreadyExists { username } => {
            println!("Administrator {username} already exists; password unchanged.")
        }
    }
    let bootstrap = zeroize::Zeroizing::new(fs::read_to_string(
        directory.join("secrets/keycloak-bootstrap-admin-password"),
    )?);
    let subject = crate::identity::administrator_subject(
        &http,
        &format!("https://{domain}/sso"),
        email,
        &bootstrap,
    )?;
    let identity = json!({"issuer":format!("https://{domain}/sso/realms/thelve"),"subject":subject,"user_name":email,"email":email});
    process::with_secret_stdin(
        &CommandPlan::new("colima").args([
            "ssh",
            "--",
            "sudo",
            "docker",
            "exec",
            "-i",
            "thelve-control-api-1",
            "thelve-control-api",
            "bootstrap-administrator",
        ]),
        &serde_json::to_vec(&identity)?,
    )
    .context("could not bind the administrator to the installation tenant")?;
    println!("Administrator linked to the installation tenant.");
    Ok(())
}

fn read_developer_ca() -> Result<String> {
    let mut last_error = None;
    for _ in 0..30 {
        match ssh(&["sudo", "cat", DEVELOPER_CA_ROOT]) {
            Ok(ca) if !ca.trim().is_empty() => return Ok(ca),
            Ok(_) => last_error = Some(anyhow::anyhow!("developer CA root is empty")),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("developer CA root was not created")))
        .context("wait for Caddy to create the machine-level developer CA")
}

fn wait_for_local_https(http: &reqwest::blocking::Client, domain: &str) -> Result<()> {
    let url = format!("https://{domain}/sso/realms/master/.well-known/openid-configuration");
    let mut last_error = None;
    for _ in 0..30 {
        match http.get(&url).send() {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                last_error = Some(anyhow::anyhow!(
                    "sign-in readiness returned HTTP {}",
                    response.status()
                ));
            }
            Err(error) => last_error = Some(error.into()),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("sign-in service did not become ready")))
        .context("wait for the appliance's HTTPS certificate and sign-in service")
}

#[cfg(target_os = "macos")]
fn trust_developer_ca(ca_path: &Path) -> Result<()> {
    let verified = std::process::Command::new("security")
        .args(["verify-cert", "-c"])
        .arg(ca_path)
        .args(["-p", "ssl"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("check the macOS developer CA trust")?
        .success();
    if verified {
        println!("The machine-level Thelve developer CA is already trusted.");
        return Ok(());
    }
    let home = std::env::var_os("HOME").context("HOME is unavailable")?;
    let keychain = PathBuf::from(home).join("Library/Keychains/login.keychain-db");
    println!("==> trusting the machine-level Thelve developer CA (macOS may ask for approval)");
    process::inherit(
        &CommandPlan::new("security")
            .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
            .arg(path(&keychain))
            .arg(path(ca_path)),
    )
}

#[cfg(not(target_os = "macos"))]
fn trust_developer_ca(ca_path: &Path) -> Result<()> {
    println!(
        "Install this machine-level Thelve developer CA in your operating system trust store: {}",
        path(ca_path)
    );
    Ok(())
}

pub fn operate(directory: &Path, action: &str, approve: bool) -> Result<()> {
    if action != "status" && !approve {
        bail!("{action} changes the local appliance; rerun with --approve");
    }
    if process::capture(&CommandPlan::new("docker").args(["context", "show"]))?.trim() != "colima" {
        bail!("select the default Colima Docker context first");
    }
    let directory = directory.canonicalize()?;
    let expected = fs::read_to_string(directory.join("owner"))?;
    let actual = ssh(&["sudo", "cat", "/etc/thelve/local-owner"])?;
    if expected.trim() != actual.trim()
        || !expected.trim().ends_with(&format!(":{}", path(&directory)))
    {
        bail!("local appliance owner does not match this directory");
    }
    if action == "status" {
        return compose(&["ps"]);
    }
    let running = ssh(&[
        "sudo",
        "docker",
        "ps",
        "--filter",
        "label=com.docker.compose.project=thelve",
        "--format",
        "{{.Names}}",
    ])?;
    if !running.trim().is_empty()
        && ssh(&[
            "sudo",
            "/opt/thelve/bin/thelve-node",
            "drain",
            "--config",
            "/etc/thelve/node.yaml",
        ])
        .is_err()
    {
        eprintln!("local gateway did not acknowledge drain; stopping the development containers");
    }
    compose(&["down", "--timeout", "120", "--remove-orphans"])?;
    if action == "destroy" {
        ssh_run(&[
            "sudo",
            "rm",
            "-rf",
            "/etc/thelve",
            "/opt/thelve",
            "/var/lib/thelve",
            "/run/thelve",
        ])?;
        fs::remove_dir_all(&directory)?;
        println!("Removed the local appliance, data, and credentials.");
    } else {
        println!("Local appliance stopped; data and credentials retained.");
    }
    Ok(())
}

fn initialize_secret_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let values = secrets::generated_internal_values("s3://thelve-local-backups/appliance")?;
    if directory.exists() {
        if values
            .keys()
            .any(|name| !directory.join(name.replace('/', "--")).is_file())
        {
            bail!(
                "local secrets are incomplete; refusing to regenerate correlated credentials separately"
            );
        }
        return Ok(());
    }
    let stage = tempfile::tempdir_in(
        directory
            .parent()
            .context("secret directory has no parent")?,
    )?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700))?;
    for (name, value) in values {
        protected_write(
            &stage.path().join(name.replace('/', "--")),
            value.as_bytes(),
        )?;
    }
    fs::rename(stage.path(), directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packaged_host_tool_is_verified_before_execution() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::{Signer as _, SigningKey};
        use sha2::{Digest as _, Sha256};
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("bundle/artifacts")).unwrap();
        let tool = b"prebuilt host executable";
        let document = json!({"spec":{"artifacts":[{"path":"artifacts/local-thelve-node","sha256":format!("sha256:{:x}", Sha256::digest(tool)),"sizeBytes":tool.len()}]}});
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(&serde_json_canonicalizer::to_vec(&document).unwrap());
        fs::write(
            root.path().join("bundle/deployment.release.json"),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        fs::write(root.path().join("bundle/deployment.release.sig.json"), serde_json::to_vec(&json!({"algorithm":"ed25519","keyId":"test","signature":URL_SAFE_NO_PAD.encode(signature.to_bytes())})).unwrap()).unwrap();
        fs::write(root.path().join("trust.json"), serde_json::to_vec(&json!({"keys":[{"keyId":"test","publicKey":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())}]})).unwrap()).unwrap();
        fs::write(root.path().join("bundle/artifacts/local-thelve-node"), tool).unwrap();
        verify_host_tool(root.path()).unwrap();
        fs::write(
            root.path().join("bundle/artifacts/local-thelve-node"),
            b"tampered",
        )
        .unwrap();
        assert!(verify_host_tool(root.path()).is_err());
    }

    #[test]
    fn secret_initialization_is_correlated_repeatable_and_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("secrets");
        initialize_secret_directory(&directory).unwrap();
        let password = fs::read_to_string(directory.join("postgres-password")).unwrap();
        let url = fs::read_to_string(directory.join("database-url")).unwrap();
        assert!(url.contains(&password));
        initialize_secret_directory(&directory).unwrap();
        assert_eq!(
            fs::read_to_string(directory.join("postgres-password")).unwrap(),
            password
        );
        assert_eq!(
            fs::metadata(directory.join("postgres-password"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_file(directory.join("database-url")).unwrap();
        assert!(initialize_secret_directory(&directory).is_err());
    }

    #[test]
    fn local_compose_reuses_a_machine_level_developer_ca() {
        let root = tempfile::tempdir().unwrap();
        let compose_path = root.path().join("compose.yaml");
        fs::write(
            &compose_path,
            "services:\n  caddy:\n    volumes:\n      - /var/lib/thelve/caddy/data:/data:rw\n",
        )
        .unwrap();
        use_persistent_developer_ca(&compose_path).unwrap();
        use_persistent_developer_ca(&compose_path).unwrap();
        let document: Value = serde_yaml::from_slice(&fs::read(compose_path).unwrap()).unwrap();
        let mounts = document
            .pointer("/services/caddy/volumes")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            mounts
                .iter()
                .filter(|mount| mount.as_str().unwrap().contains(CADDY_LOCAL_AUTHORITY))
                .count(),
            1
        );
    }
}
