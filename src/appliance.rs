//! Linux host installation. Image admission precedes any execution from that image.
use crate::process::{self, CommandPlan};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

const SIGNING_IDENTITY: &str = "https://github.com/eisenzopf/Thelve/.github/workflows/portable-appliance-candidate.yml@refs/heads/main";

#[derive(Debug, Args)]
pub struct CompleteSetupArgs {
    #[arg(long, default_value = "/etc/thelve")]
    configuration: PathBuf,
    #[arg(long)]
    admin_email: String,
    #[arg(long)]
    approve: bool,
}

pub fn complete_setup(args: CompleteSetupArgs) -> Result<()> {
    ensure!(args.approve, "administrator setup requires --approve");
    ensure!(
        std::env::consts::OS == "linux",
        "run setup on the Linux appliance host"
    );
    ensure!(
        process::capture(&CommandPlan::new("id").arg("-u"))?.trim() == "0",
        "run setup as root"
    );
    validate_administrator_email(&args.admin_email)?;
    let context = process::capture(&CommandPlan::new("docker").args([
        "context",
        "inspect",
        "--format",
        "{{.Endpoints.docker.Host}}",
    ]))?;
    ensure!(
        context.trim().starts_with("unix://") && std::env::var_os("DOCKER_HOST").is_none(),
        "setup requires the local Docker Engine"
    );
    let configuration = args.configuration.canonicalize()?;
    let inspected = process::capture(&CommandPlan::new("docker").args(["inspect", "thelve"]))?;
    let inspected: serde_json::Value = serde_json::from_str(&inspected)?;
    let container = &inspected[0];
    ensure!(
        container["State"]["Running"] == true,
        "appliance is not running"
    );
    let mounts = container["Mounts"]
        .as_array()
        .context("appliance mounts unavailable")?;
    ensure!(
        mounts.iter().any(|mount| {
            mount["Destination"] == "/etc/thelve"
                && mount["Source"].as_str() == configuration.to_str()
                && mount["RW"] == false
        }),
        "configuration is not the running appliance's read-only configuration"
    );
    let node: serde_json::Value =
        serde_json::from_slice(&fs::read(configuration.join("node.json"))?)?;
    let hostname = node["spec"]["domains"]["app"]
        .as_str()
        .context("installation hostname missing")?;
    finish_administrator(&configuration, hostname, &args.admin_email)
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Exact signed appliance image, including its sha256 manifest digest.
    #[arg(long)]
    image: String,
    /// Prepared appliance configuration, signed release documents, and secret files.
    #[arg(long, default_value = "/etc/thelve")]
    configuration: PathBuf,
    /// Generate fresh configuration using the template in the verified image.
    #[arg(long, requires_all = ["contact_email", "public_ip", "release_directory"])]
    hostname: Option<String>,
    #[arg(long, requires = "hostname")]
    contact_email: Option<String>,
    /// Create and link the first administrator (separate from licensing contact).
    #[arg(long, requires = "hostname")]
    admin_email: Option<String>,
    #[arg(long, requires = "hostname")]
    public_ip: Option<std::net::Ipv4Addr>,
    #[arg(long, requires = "hostname")]
    release_directory: Option<PathBuf>,
    /// Durable appliance data. Existing nonempty directories are never adopted implicitly.
    #[arg(long, default_value = "/var/lib/thelve")]
    data: PathBuf,
    #[arg(long)]
    approve: bool,
}

fn validate_image(image: &str) -> Result<&str> {
    let (repository, digest) = image
        .rsplit_once("@sha256:")
        .context("image must be pinned by sha256 digest")?;
    ensure!(
        !repository.is_empty()
            && !repository.starts_with('-')
            && repository.contains('/')
            && repository
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"./_-".contains(&b))
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid digest-pinned image identity"
    );
    Ok(digest)
}

fn run_plan(image: &str, configuration: &str, data: &str) -> Result<CommandPlan> {
    let digest = validate_image(image)?;
    ensure!(
        !configuration.contains(',') && !data.contains(','),
        "mount paths cannot contain commas"
    );
    Ok(CommandPlan::new("docker").args([
        "run",
        "--detach",
        "--name",
        "thelve",
        "--restart",
        "unless-stopped",
        "--network",
        "host",
        "--read-only",
        "--tmpfs",
        "/run:rw,nosuid,nodev,noexec,mode=0755",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--env-file",
        &format!("{configuration}/appliance.env"),
        "--env",
        &format!("THELVE_APPLIANCE_IMAGE_DIGEST=sha256:{digest}"),
        "--mount",
        &format!("type=bind,src={configuration},dst=/etc/thelve,readonly"),
        "--mount",
        &format!("type=bind,src={data},dst=/var/lib/thelve"),
        image,
    ]))
}

pub fn install(args: InstallArgs) -> Result<()> {
    ensure!(
        args.approve,
        "installation starts a persistent appliance; rerun with --approve"
    );
    ensure!(
        std::env::consts::OS == "linux",
        "run the installer on the target Linux host"
    );
    validate_image(&args.image)?;
    if let Some(email) = &args.admin_email {
        validate_administrator_email(email)?;
    }
    ensure!(
        process::capture(&CommandPlan::new("id").arg("-u"))?.trim() == "0",
        "run the installer as root"
    );
    let context = process::capture(&CommandPlan::new("docker").args([
        "context",
        "inspect",
        "--format",
        "{{.Endpoints.docker.Host}}",
    ]))?;
    ensure!(
        context.trim().starts_with("unix://") && std::env::var_os("DOCKER_HOST").is_none(),
        "installation requires a local Docker Engine, not a remote Docker context"
    );
    let containers = process::capture(&CommandPlan::new("docker").args([
        "ps",
        "--all",
        "--filter",
        "name=^/thelve$",
        "--format",
        "{{.ID}}",
    ]))?;
    ensure!(
        containers.trim().is_empty(),
        "an appliance already exists; use the lifecycle upgrade/recovery path"
    );
    if args.data.exists() {
        ensure!(
            !fs::symlink_metadata(&args.data)?.file_type().is_symlink()
                && fs::read_dir(&args.data)?.next().is_none(),
            "data directory must be empty; refusing to overwrite or adopt existing data"
        );
    }
    process::inherit(&CommandPlan::new("cosign").args([
        "verify",
        "--certificate-identity",
        SIGNING_IDENTITY,
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        &args.image,
    ]))?;
    process::inherit(&CommandPlan::new("docker").args(["pull", &args.image]))?;
    let digests = process::capture(&CommandPlan::new("docker").args([
        "image",
        "inspect",
        "--format",
        "{{json .RepoDigests}}",
        &args.image,
    ]))?;
    let digests: Vec<String> = serde_json::from_str(&digests)?;
    ensure!(
        digests.contains(&args.image),
        "pulled image identity differs from the verified digest"
    );
    if args.hostname.is_some() {
        prepare_configuration(&args)?;
    }
    let configuration = args
        .configuration
        .canonicalize()
        .context("configuration directory unavailable")?;
    for file in [
        "appliance.env",
        "Caddyfile",
        "release/portable-appliance-release.json",
        "release/portable-appliance-release.signature.json",
    ] {
        let metadata = fs::symlink_metadata(configuration.join(file))
            .with_context(|| format!("configuration lacks {file}"))?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "configuration {file} must be a regular file"
        );
    }
    let environment = fs::read_to_string(configuration.join("appliance.env"))?;
    for line in environment.lines().filter(|line| !line.starts_with('#')) {
        let key = line.split('=').next().unwrap_or_default();
        ensure!(
            !matches!(
                key,
                "THELVE_APPLIANCE_ALLOW_UNSIGNED_DEVELOPMENT"
                    | "THELVE_ALLOW_UNVERIFIED_PRODUCT_RELEASE"
                    | "GOOGLE_APPLICATION_CREDENTIALS"
            ),
            "release installation refuses unsafe environment setting {key}"
        );
        ensure!(
            line != "AUTO_SEED_DEMO=true" && line != "ALLOW_DEMO_AUTH=true",
            "release installation refuses demo data and demo authentication"
        );
    }
    initialize_secrets(&configuration.join("secrets"))?;
    fs::create_dir_all(&args.data)?;
    let data = args.data.canonicalize()?;
    let plan = run_plan(
        &args.image,
        configuration
            .to_str()
            .context("configuration path is not UTF-8")?,
        data.to_str().context("data path is not UTF-8")?,
    )?;
    process::inherit(&plan)?;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(600) {
        let state = process::capture(&CommandPlan::new("docker").args([
            "inspect",
            "--format",
            "{{json .State}}",
            "thelve",
        ]))?;
        let state: serde_json::Value = serde_json::from_str(&state)?;
        ensure!(
            state["Running"] == true,
            "appliance stopped before readiness; inspect docker logs thelve (configuration and data retained)"
        );
        if state["Health"]["Status"] == "healthy" {
            if let Some(email) = &args.admin_email {
                finish_administrator(
                    &configuration,
                    args.hostname.as_deref().context("hostname required")?,
                    email,
                )?;
            }
            println!(
                "Thelve appliance is healthy. Complete administrator setup at your configured HTTPS hostname."
            );
            return Ok(());
        }
        thread::sleep(Duration::from_secs(5));
    }
    anyhow::bail!(
        "appliance has not become healthy within 10 minutes; container and data retained for diagnosis"
    )
}

fn installation_name(hostname: &str) -> String {
    use sha2::{Digest as _, Sha256};
    format!("thelve-{:x}", Sha256::digest(hostname.as_bytes()))[..39].to_owned()
}

fn validate_administrator_email(email: &str) -> Result<()> {
    let (local, domain) = email
        .split_once('@')
        .context("valid administrator email required")?;
    ensure!(
        !local.is_empty()
            && domain.contains('.')
            && !domain.contains('@')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && email.len() <= 254
            && !email.chars().any(char::is_whitespace),
        "valid administrator email required"
    );
    Ok(())
}

fn finish_administrator(
    configuration: &std::path::Path,
    hostname: &str,
    email: &str,
) -> Result<()> {
    use std::io::IsTerminal;
    validate_administrator_email(email)?;
    let http = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(45))
        .build()?;
    let base = format!("https://{hostname}/sso");
    let bootstrap = crate::secrets::read_private_file(
        &configuration.join("secrets/keycloak-bootstrap-admin-password"),
    )?;
    let policy =
        crate::secrets::read_private_file(&configuration.join("secrets/oidc--client-secret"))?;
    let handoff = configuration.join("initial-admin-password");
    let temporary = prepare_administrator_password(&handoff)?;
    let (result, temporary) = crate::identity::create_administrator_with_password(
        &http,
        &base,
        email,
        bootstrap.clone(),
        &policy,
        temporary,
    )?;
    if matches!(result, crate::identity::FirstAdministrator::Created { .. }) {
        write_interactive_password(
            &mut std::io::stdout().lock(),
            std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
            &temporary,
        )?;
        println!(
            "Temporary administrator password saved to {} (owner-only); change it at first sign-in.",
            handoff.display()
        );
    }
    let subject = crate::identity::administrator_subject(&http, &base, email, &bootstrap)?;
    let identity = serde_json::json!({
        "issuer": format!("{base}/realms/thelve"), "subject": subject,
        "user_name": email, "email": email,
    });
    process::with_secret_stdin(
        &CommandPlan::new("docker").args([
            "exec",
            "-i",
            "thelve",
            "thelve-control-api",
            "bootstrap-administrator",
        ]),
        &serde_json::to_vec(&identity)?,
    )
    .context("could not link administrator to the installation tenant")?;
    println!("Administrator linked to the installation tenant.");
    Ok(())
}

fn prepare_administrator_password(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>> {
    use std::io::Write;
    if fs::symlink_metadata(path).is_ok() {
        return crate::secrets::read_private_file(path);
    }
    let parent = path.parent().context("password handoff parent required")?;
    let password = crate::identity::temporary_password();
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(password.as_bytes())?;
    staged.as_file().sync_all()?;
    staged
        .persist_noclobber(path)
        .context("save protected administrator password before account creation")?;
    fs::File::open(parent)?.sync_all()?;
    Ok(password)
}

fn write_interactive_password(
    output: &mut impl std::io::Write,
    interactive: bool,
    password: &str,
) -> Result<()> {
    if interactive {
        writeln!(output, "Temporary administrator password: {password}")?;
        output.flush()?;
    }
    Ok(())
}

fn prepare_configuration(args: &InstallArgs) -> Result<()> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        !args.configuration.exists(),
        "configuration already exists; refusing to overwrite it"
    );
    let hostname = args.hostname.as_deref().context("hostname required")?;
    let email = args
        .contact_email
        .as_deref()
        .context("contact email required")?;
    ensure!(
        hostname.len() <= 200
            && hostname.contains('.')
            && hostname.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }),
        "hostname must be a lowercase fully qualified DNS name"
    );
    ensure!(
        email.contains('@') && !email.chars().any(char::is_whitespace),
        "valid contact email required"
    );
    let releases = args
        .release_directory
        .as_ref()
        .context("release directory required")?
        .canonicalize()?;
    let parent = args
        .configuration
        .parent()
        .context("configuration parent required")?;
    fs::create_dir_all(parent)?;
    let stage = tempfile::tempdir_in(parent)?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700))?;
    let release_stage = stage.path().join("release");
    fs::create_dir(&release_stage)?;
    for name in [
        "product-release.json",
        "product-release.signature.json",
        "portable-appliance-release.json",
        "portable-appliance-release.signature.json",
        "catalog-trust-root.json",
        "catalog-trust-root.sha256",
        "deployment-release.json",
        "deployment-release.signature.json",
        "deployment-trust-store.json",
        "deployment-release.sha256",
        "deployment-trust-store.sha256",
    ] {
        let source = releases.join(name);
        let metadata = fs::symlink_metadata(&source)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "release input {name} must be a regular file"
        );
        fs::copy(source, release_stage.join(name))?;
    }
    let template = process::capture(&CommandPlan::new("docker").args([
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--entrypoint",
        "cat",
        &args.image,
        "/etc/thelve-image/node.template.json",
    ]))?;
    let mut node: serde_json::Value = serde_json::from_str(&template)?;
    // A stable name is used on every retry; no tenant or administrator is seeded here.
    node["metadata"]["name"] = serde_json::json!(installation_name(hostname));
    node["spec"]["domains"] = serde_json::json!({
        "app": hostname, "api": format!("api.{hostname}"),
        "media": format!("media.{hostname}"), "sip": hostname,
    });
    node["spec"]["networking"]["advertisedIpv4"] =
        serde_json::json!(args.public_ip.context("public IP required")?.to_string());
    node["spec"]["tls"]["contactEmail"] = serde_json::json!(email);
    node["spec"]["releaseRef"] = serde_json::json!(format!(
        "sha256:{:x}",
        Sha256::digest(fs::read(release_stage.join("deployment-release.json"))?)
    ));
    fs::write(
        stage.path().join("node.json"),
        serde_json::to_vec_pretty(&node)?,
    )?;
    let mount = format!("type=bind,src={},dst=/work", stage.path().display());
    ensure!(
        !stage.path().to_string_lossy().contains(','),
        "configuration path cannot contain commas"
    );
    process::inherit(&CommandPlan::new("docker").args([
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        &mount,
        "--entrypoint",
        "render_portable_appliance",
        &args.image,
        "/work/node.json",
        "/work/release/deployment-release.json",
        &args.image,
        "/work/rendered",
    ]))?;
    for name in [
        "appliance.env",
        "Caddyfile",
        "keycloak-realm.json",
        "appliance-plan.json",
    ] {
        fs::rename(
            stage.path().join("rendered").join(name),
            stage.path().join(name),
        )?;
    }
    fs::remove_dir(stage.path().join("rendered"))?;
    initialize_secrets(&stage.path().join("secrets"))?;
    fs::rename(stage.path(), &args.configuration)?;
    println!(
        "Configuration generated. DNS must point {hostname}, api.{hostname}, and media.{hostname} to the server."
    );
    Ok(())
}

fn initialize_secrets(directory: &std::path::Path) -> Result<()> {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    if directory.exists() {
        ensure!(
            !fs::symlink_metadata(directory)?.file_type().is_symlink(),
            "secret directory must not be a symlink"
        );
        // Existing credentials are never regenerated; runtime preflight checks
        // completeness against the rendered secret references.
        return Ok(());
    }
    let parent = directory
        .parent()
        .context("secret directory needs a parent")?;
    let stage = tempfile::tempdir_in(parent)?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700))?;
    for (name, value) in crate::secrets::generated_portable_values()? {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(stage.path().join(name.replace('/', "--")))?;
        file.write_all(value.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(stage.path(), directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administrator_password_handoff_survives_retry_without_rotation() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("password");
        let initial = prepare_administrator_password(&path).unwrap();
        assert_eq!(
            prepare_administrator_password(&path).unwrap().as_str(),
            initial.as_str()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    #[test]
    fn temporary_password_is_not_printed_by_noninteractive_installs() {
        let sentinel = "synthetic-temporary-password";
        let mut output = Vec::new();
        write_interactive_password(&mut output, false, sentinel).unwrap();
        assert!(output.is_empty());
        write_interactive_password(&mut output, true, sentinel).unwrap();
        assert!(String::from_utf8(output).unwrap().contains(sentinel));
    }
    #[test]
    fn administrator_identity_is_validated_before_installation() {
        assert!(validate_administrator_email("admin@example.com").is_ok());
        for invalid in [
            "",
            "@example.com",
            "a@@example.com",
            "a@",
            "a@.com",
            "a@example.com\n",
        ] {
            assert!(validate_administrator_email(invalid).is_err());
        }
    }
    #[test]
    fn installation_names_are_stable_and_bounded_for_long_hostnames() {
        let hostname = format!("{}.{}.example.com", "a".repeat(63), "b".repeat(63));
        let name = installation_name(&hostname);
        assert!(name.len() <= 50);
        assert_eq!(name, installation_name(&hostname));
        assert_ne!(name, installation_name("another.example.com"));
    }
    #[test]
    fn internal_secrets_are_correlated_private_and_preserved_on_retry() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("secrets");
        initialize_secrets(&directory).unwrap();
        let password = fs::read_to_string(directory.join("postgres-password")).unwrap();
        let database = fs::read_to_string(directory.join("database-url")).unwrap();
        assert!(database.contains(&format!(":{password}@127.0.0.1:5432/")));
        assert_eq!(
            fs::read_to_string(directory.join("keycloak-database-password")).unwrap(),
            password
        );
        assert_eq!(
            fs::metadata(directory.join("database-url"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!directory.join("telnyx-api-key").exists());
        assert!(!directory.join("vapi-api-key").exists());
        initialize_secrets(&directory).unwrap();
        assert_eq!(
            fs::read_to_string(directory.join("postgres-password")).unwrap(),
            password
        );
    }
    #[test]
    fn mutable_or_option_like_images_are_refused() {
        for image in [
            "example.com/thelve:latest",
            "--privileged",
            "example.com/t@sha256:abc",
        ] {
            assert!(validate_image(image).is_err());
        }
    }
    #[test]
    fn launch_is_one_container_with_durable_data_and_no_provider_credentials() {
        let image = format!("example.com/thelve@sha256:{}", "a".repeat(64));
        let plan = run_plan(&image, "/etc/thelve", "/var/lib/thelve").unwrap();
        assert!(plan.args.contains(&"host".to_string()));
        assert!(
            plan.args
                .contains(&"type=bind,src=/etc/thelve,dst=/etc/thelve,readonly".to_string())
        );
        assert!(
            plan.args
                .contains(&"type=bind,src=/var/lib/thelve,dst=/var/lib/thelve".to_string())
        );
        assert!(
            !plan
                .display_safe()
                .contains("GOOGLE_APPLICATION_CREDENTIALS")
        );
        assert!(!plan.display_safe().contains("API_KEY"));
        assert!(run_plan(&image, "/etc/thelve,readonly=false", "/var/lib/thelve").is_err());
    }
}
