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
pub struct InstallArgs {
    /// Exact signed appliance image, including its sha256 manifest digest.
    #[arg(long)]
    image: String,
    /// Prepared appliance configuration, signed release documents, and secret files.
    #[arg(long)]
    configuration: PathBuf,
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
    ensure!(
        process::capture(&CommandPlan::new("id").arg("-u"))?.trim() == "0",
        "run the installer as root"
    );
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
