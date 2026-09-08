use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::{
    activation, agent, catalog, cloud, config, launch, license, lifecycle, mcp, preview, recovery,
    secrets, skills, terraform,
};

#[derive(Debug, Parser)]
#[command(
    name = "thelve",
    version,
    about = "Thelve installation and administration CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Administer a local appliance.
    #[command(hide = true)]
    Dev(crate::dev::DevArgs),
    /// Check cloud identity, permissions, and local deployment prerequisites.
    Doctor(DoctorArgs),
    /// Verify signed release, channel, and machine-image catalogs.
    #[command(alias = "catalog")]
    Release(CatalogArgs),
    /// Create and operate a cloud single-node deployment.
    Deploy(DeployArgs),
    /// Create, verify, and restore encrypted single-node recovery points.
    Backup(BackupArgs),
    /// Populate cloud secret-manager values without Terraform state or argv exposure.
    Secret(SecretArgs),
    /// Configure and use a bounded AAuth client for a deployed Thelve system.
    Agent(AgentArgs),
    /// Serve the safe local Model Context Protocol bridge over stdio.
    Mcp(McpArgs),
    /// Install the portable Thelve skills for Codex and Claude.
    Skill(SkillArgs),
    /// Obtain issuer trust and install a signed licence on a deployed appliance.
    License(LicenseArgs),
    /// Bring up a single-server appliance from a clean workstation in one resumable command.
    Launch(Box<LaunchArgs>),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LaunchProvider {
    Gcp,
    Aws,
    Local,
}

#[derive(Debug, Args)]
struct LaunchArgs {
    #[arg(long, value_enum)]
    provider: LaunchProvider,
    /// Persistent local appliance directory.
    #[arg(long)]
    local_dir: Option<PathBuf>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long)]
    zone: Option<String>,
    /// Exact host image from a verified machine-image catalog.
    #[arg(long)]
    host_image: Option<String>,
    /// Globally unique remote-state bucket.
    #[arg(long)]
    state_bucket: Option<String>,
    /// Domain assignments as key=host, e.g. app=desk.example.com; repeat for app, api, media, sip.
    /// Optional: without them the appliance uses sslip.io names for its own address, so no DNS is required.
    #[arg(long = "domain", value_parser = parse_domain)]
    domains: Vec<(String, String)>,
    /// Real operator address for ACME notices.
    #[arg(long)]
    tls_contact_email: Option<String>,
    /// Who the first person in the bundled sign-in service is; the contact address by default.
    #[arg(long)]
    admin_email: Option<String>,
    /// Verified release directory from `thelve release fetch-gcp-preview`.
    #[arg(long)]
    release_dir: PathBuf,
    /// Entitlement issuer whose published trust the appliance accepts; defaults to Rudeless.
    #[arg(long)]
    issuer_url: Option<String>,
    /// Where the launch requests the installation's licence; defaults to Rudeless.
    #[arg(long)]
    license_service_url: Option<String>,
    /// Leave the installation unlicensed (air-gapped work); the manual command is printed.
    #[arg(long)]
    skip_license: bool,
    /// SHA-256 of the issuer's trust document, published beside the issuer URL; pins what --issuer-url fetches.
    #[arg(long)]
    issuer_trust_sha256: Option<String>,
    /// Use your own OIDC provider instead of the bundled sign-in service: its HTTPS issuer URL.
    /// The provider must issue proof-bound (DPoP) JWT access tokens carrying a tenant claim.
    #[arg(long, requires = "oidc_client_id")]
    oidc_issuer: Option<String>,
    /// The client your provider registered for the Thelve desk (its secret is typed at a hidden prompt).
    #[arg(long, requires = "oidc_issuer")]
    oidc_client_id: Option<String>,
    #[arg(long, default_value = "deployment.yaml")]
    config: PathBuf,
    #[arg(long, default_value = "node.yaml")]
    node_config: PathBuf,
    #[arg(long, default_value = "activation-receipt.json")]
    activation_receipt: PathBuf,
    #[arg(long, default_value = "launch-receipt.json")]
    receipt: PathBuf,
    #[arg(long)]
    approve: bool,
}

fn launch_identity(args: &LaunchArgs) -> config::IdentityIntent {
    match (&args.oidc_issuer, &args.oidc_client_id) {
        (Some(issuer), Some(client_id)) => config::IdentityIntent::ExternalOidc {
            issuer: issuer.clone(),
            client_id: client_id.clone(),
        },
        _ => config::IdentityIntent::BundledKeycloak,
    }
}

fn parse_domain(value: &str) -> Result<(String, String), String> {
    let (key, host) = value
        .split_once('=')
        .ok_or_else(|| format!("expected key=host, got {value:?}"))?;
    if !matches!(key, "app" | "api" | "media" | "sip") || host.is_empty() {
        return Err(format!(
            "domain key must be app, api, media, or sip with a host, got {value:?}"
        ));
    }
    Ok((key.into(), host.into()))
}

#[derive(Debug, Args)]
struct LicenseArgs {
    #[command(subcommand)]
    command: LicenseCommand,
}

#[derive(Debug, Subcommand)]
enum LicenseCommand {
    /// Show the certificate recorded in a deployment intent, without its signature.
    Status {
        #[arg(long, default_value = "deployment.yaml")]
        config: PathBuf,
    },
    /// Print an issuer's published trust anchors as a `licensing` block for the deployment intent.
    Trust {
        #[arg(long, default_value = license::DEFAULT_ISSUER_URL)]
        issuer_url: String,
        /// The trust document's SHA-256 as published beside the issuer URL; refuses anything else.
        #[arg(long)]
        expect_sha256: Option<String>,
    },
    /// Install a signed entitlement certificate: through a bound AAuth profile, or before any
    /// administrator exists by recording it in the deployment intent and re-activating the node.
    Install {
        /// Bound AAuth profile to invoke the install capability with.
        #[arg(long, conflicts_with = "config")]
        profile: Option<String>,
        /// Signed certificate JSON file, or - for stdin.
        #[arg(long, default_value = "-")]
        certificate: PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Deployment intent; with this the certificate is installed at the next boot.
        #[arg(long, requires_all = ["release_dir", "tls_contact_email"])]
        config: Option<PathBuf>,
        #[arg(long)]
        release_dir: Option<PathBuf>,
        #[arg(long)]
        tls_contact_email: Option<String>,
        #[arg(long, default_value = "node.yaml")]
        node_config: PathBuf,
        #[arg(long, default_value = "activation-receipt.json")]
        activation_receipt: PathBuf,
        #[arg(long)]
        approve: bool,
    },
}

#[derive(Debug, Args)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Create, bind, and inspect local AAuth profiles.
    Profile(AgentProfileArgs),
    /// Print the profile's public JWK; private key material is never printed.
    PublicKey {
        #[arg(long)]
        profile: String,
    },
    /// Discover the live governed capability catalog through signed AAuth.
    Capabilities {
        #[arg(long)]
        profile: String,
    },
    /// Invoke a read or an exact approval-bound capability.
    Invoke(AgentInvokeArgs),
    /// Propose an immutable capability plan for human review.
    Plan(AgentPlanArgs),
    /// Read a pending or decided immutable plan.
    PlanRead {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        approval_id: Uuid,
    },
    /// List immutable plans visible to the delegated actor.
    PlanList {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u16,
    },
    /// Execute only the exact payload frozen in an approved plan.
    Apply {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        approval_id: Uuid,
    },
}

#[derive(Debug, Args)]
struct AgentProfileArgs {
    #[command(subcommand)]
    command: AgentProfileCommand,
}

#[derive(Debug, Subcommand)]
enum AgentProfileCommand {
    /// Generate a protected Ed25519 key and write an unbound profile.
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        api_url: String,
        #[arg(long)]
        tenant_id: Uuid,
        #[arg(long)]
        key_id: String,
        /// Import a raw or base64url 32-byte seed instead of generating one.
        #[arg(long)]
        seed_file: Option<PathBuf>,
    },
    /// Bind a profile to an already approved bounded delegation.
    Bind {
        #[arg(long)]
        name: String,
        #[arg(long)]
        delegation_id: Uuid,
    },
    /// Print non-secret profile metadata.
    Show {
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PlanControl {
    Confirmation,
    FourEyes,
}

impl From<PlanControl> for agent::ApprovalControl {
    fn from(value: PlanControl) -> Self {
        match value {
            PlanControl::Confirmation => Self::Confirmation,
            PlanControl::FourEyes => Self::FourEyes,
        }
    }
}

#[derive(Debug, Args)]
struct AgentInvokeArgs {
    #[arg(long)]
    profile: String,
    #[arg(long)]
    capability: String,
    #[arg(long, default_value = "unspecified")]
    resource_type: String,
    #[arg(long)]
    resource_id: Option<String>,
    /// JSON object file, or - for stdin.
    #[arg(long, default_value = "-")]
    input: PathBuf,
    #[arg(long)]
    approval_id: Option<Uuid>,
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct AgentPlanArgs {
    #[arg(long)]
    profile: String,
    #[arg(long)]
    capability: String,
    #[arg(long, default_value = "unspecified")]
    resource_type: String,
    #[arg(long)]
    resource_id: Option<String>,
    /// JSON object file, or - for stdin.
    #[arg(long, default_value = "-")]
    input: PathBuf,
    #[arg(long)]
    reason: String,
    #[arg(long, value_enum, default_value = "confirmation")]
    control: PlanControl,
    #[arg(long, default_value_t = 600)]
    expires_in_seconds: u32,
    /// Stable target-operation key. Generated when omitted.
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Run the local newline-delimited JSON-RPC MCP server on stdin/stdout.
    Serve {
        #[arg(long)]
        profile: String,
    },
}

#[derive(Debug, Args)]
struct SkillArgs {
    #[command(subcommand)]
    command: SkillCommand,
}

#[derive(Debug, Subcommand)]
enum SkillCommand {
    /// Install the packaged skills and optionally register the local MCP server.
    Install {
        #[arg(long, value_enum, default_value = "all")]
        target: skills::SkillTarget,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        configure_mcp: bool,
    },
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long, value_enum)]
    provider: config::CloudProvider,
    /// GCP project ID. Required for provider=gcp.
    #[arg(long)]
    project: Option<String>,
    /// AWS region. Required for provider=aws.
    #[arg(long)]
    region: Option<String>,
}

#[derive(Debug, Args)]
struct CatalogArgs {
    #[command(subcommand)]
    command: CatalogCommand,
}

#[derive(Debug, Subcommand)]
enum CatalogCommand {
    /// Verify a raw JSON document against its detached signature and trust root.
    Verify {
        #[arg(long)]
        document: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
        /// Independently pinned sha256:<64 lowercase hex> digest of the trust-root bytes.
        #[arg(long)]
        trust_root_sha256: String,
        #[arg(long, value_enum)]
        kind: catalog::CatalogKind,
    },
    /// Fetch all private GCP preview bytes after exact signature and trust-pin verification.
    FetchGcpPreview {
        #[arg(long)]
        descriptor: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
        /// Independently pinned sha256:<64 lowercase hex> digest of the trust-root bytes.
        #[arg(long)]
        trust_root_sha256: String,
        #[arg(long)]
        output: PathBuf,
        /// Acknowledge that this release is explicitly not production-qualified.
        #[arg(long)]
        admit_preview: bool,
    },
}

#[derive(Debug, Args)]
struct DeployArgs {
    #[command(subcommand)]
    command: DeployCommand,
}

#[derive(Debug, Subcommand)]
enum DeployCommand {
    /// Create an isolated GCP project, link billing, set a budget, and enable deployment APIs.
    BootstrapProject {
        #[arg(long)]
        project: String,
        #[arg(long)]
        organization: String,
        #[arg(long)]
        billing_account: String,
        #[arg(long, default_value = "us-west1")]
        region: String,
        #[arg(long, default_value_t = 50)]
        monthly_budget_usd: u32,
        #[arg(long)]
        approve: bool,
    },
    /// Write a strict non-secret deployment intent file.
    Init {
        #[arg(long, value_enum)]
        provider: config::CloudProvider,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "deployment.yaml")]
        output: PathBuf,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        region: String,
        #[arg(long)]
        zone: String,
    },
    /// Create and harden the remote state bucket. This mutates cloud resources.
    BootstrapState {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Render a redacted plan without applying it.
    Plan {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create networking, secret containers, and a stopped host.
    Prepare {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Start or update the appliance after required secret versions exist.
    Up {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Stop compute while preserving address, disk, secrets, and backups.
    Pause {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Resume a previously paused host.
    Resume {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Destroy infrastructure. Requires an exact deployment-name confirmation.
    Destroy {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
        #[arg(long)]
        confirm: String,
    },
    /// Print provider outputs without secret values.
    Status {
        #[arg(long)]
        config: PathBuf,
    },
    /// Render a value-free node configuration from applied cloud outputs and a verified release.
    RenderNodeConfig {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        tls_contact_email: String,
        #[arg(long, default_value = "node.yaml")]
        output: PathBuf,
    },
    /// Roll a running GCP node back onto a release it already installed; upgrades are `activate-gcp` with the newer release.
    Rollback {
        #[arg(long)]
        config: PathBuf,
        /// Installed release id as listed in the support bundle.
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "rollback-receipt.json")]
        receipt: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Fetch the node manager's value-free support bundle.
    SupportBundle {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "support-bundle.json")]
        output: PathBuf,
    },
    /// Transport and activate a verified preview release through GCP IAP/OS Login.
    ActivateGcp {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        node_config: PathBuf,
        #[arg(long, default_value = "activation-receipt.json")]
        receipt: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Replace only the GCP VM and boot disk, activate a signed release, and restore a verified backup.
    ReplaceNode {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        backup_id: Uuid,
        #[arg(long, default_value = "replacement-receipt.json")]
        receipt: PathBuf,
        #[arg(long)]
        approve: bool,
        #[arg(long)]
        confirm: String,
    },
}

#[derive(Debug, Args)]
struct BackupArgs {
    #[command(subcommand)]
    command: BackupCommand,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Drain writers and create a checksummed, immutable, encrypted recovery point.
    Create {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long, default_value = "backup-receipt.json")]
        output: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    /// Download and independently verify a recovery point without exposing backup contents.
    Verify {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        backup_id: Uuid,
    },
    /// Restore a verified recovery point onto the already activated node.
    Restore {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long)]
        backup_id: Uuid,
        #[arg(long, default_value = "restore-receipt.json")]
        output: PathBuf,
        #[arg(long)]
        approve: bool,
    },
}

#[derive(Debug, Args)]
struct SecretArgs {
    #[command(subcommand)]
    command: SecretCommand,
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    /// Read a value from a hidden prompt or stdin and add a provider secret version.
    Set {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        name: String,
        /// Read the secret from stdin instead of a hidden terminal prompt.
        #[arg(long)]
        stdin: bool,
    },
    /// Generate one correlated version-1 set for all non-Telnyx runtime secrets.
    InitializeInternal {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
    },
}

pub fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Dev(args) => crate::dev::execute(args),
        Command::Doctor(args) => cloud::doctor(args.provider, args.project, args.region),
        Command::Release(args) => match args.command {
            CatalogCommand::Verify {
                document,
                signature,
                trust_root,
                trust_root_sha256,
                kind,
            } => {
                let receipt =
                    catalog::verify(&document, &signature, &trust_root, &trust_root_sha256, kind)?;
                println!(
                    "catalog verified: {} ({}, trust root {})",
                    receipt.schema_version, receipt.digest, receipt.trust_root_digest
                );
                Ok(())
            }
            CatalogCommand::FetchGcpPreview {
                descriptor,
                signature,
                trust_root,
                trust_root_sha256,
                output,
                admit_preview,
            } => {
                let receipt = preview::fetch(
                    &descriptor,
                    &signature,
                    &trust_root,
                    &trust_root_sha256,
                    &output,
                    admit_preview,
                )?;
                print_json(&serde_json::to_value(receipt)?)
            }
        },
        Command::Deploy(args) => match args.command {
            DeployCommand::BootstrapProject {
                project,
                organization,
                billing_account,
                region,
                monthly_budget_usd,
                approve,
            } => {
                require_approval(approve, "bootstrap-project")?;
                cloud::bootstrap_gcp_project(
                    &project,
                    &organization,
                    &billing_account,
                    &region,
                    monthly_budget_usd,
                )
            }
            DeployCommand::Init {
                provider,
                name,
                output,
                project,
                region,
                zone,
            } => {
                let intent =
                    config::CloudDeployment::template(provider, name, project, region, zone)?;
                config::write_new(&output, &intent)?;
                println!("wrote non-secret deployment intent to {}", output.display());
                println!(
                    "edit the host image, state bucket, and domains; review the dated Telnyx network profile before planning"
                );
                Ok(())
            }
            DeployCommand::BootstrapState { config, approve } => {
                require_approval(approve, "bootstrap-state")?;
                let intent = config::load(&config)?;
                cloud::bootstrap_state(&intent)
            }
            DeployCommand::Plan { config } => {
                terraform::plan(&config, terraform::HostState::Running)
            }
            DeployCommand::Prepare { config, approve } => {
                require_approval(approve, "prepare")?;
                terraform::apply(&config, terraform::HostState::Stopped, false)
            }
            DeployCommand::Up { config, approve } | DeployCommand::Resume { config, approve } => {
                require_approval(approve, "up/resume")?;
                let intent = config::load(&config)?;
                secrets::verify_required_versions(
                    &intent,
                    terraform::workspace(&config, &intent)?,
                )?;
                terraform::apply(&config, terraform::HostState::Running, false)
            }
            DeployCommand::Pause { config, approve } => {
                require_approval(approve, "pause")?;
                terraform::apply(&config, terraform::HostState::Stopped, false)
            }
            DeployCommand::Destroy {
                config,
                approve,
                confirm,
            } => {
                require_approval(approve, "destroy")?;
                let intent = config::load(&config)?;
                if confirm != intent.metadata.name {
                    bail!(
                        "--confirm must exactly match deployment name {:?}",
                        intent.metadata.name
                    );
                }
                terraform::apply(&config, terraform::HostState::Stopped, true)
            }
            DeployCommand::Status { config } => terraform::status(&config),
            DeployCommand::RenderNodeConfig {
                config,
                release_dir,
                tls_contact_email,
                output,
            } => activation::render_node_config(&config, &release_dir, &output, &tls_contact_email),
            DeployCommand::Rollback {
                config,
                to,
                receipt,
                approve,
            } => {
                require_approval(approve, "rollback")?;
                lifecycle::rollback(&config, &to, &receipt)
            }
            DeployCommand::SupportBundle { config, output } => {
                lifecycle::support_bundle(&config, &output)
            }
            DeployCommand::ActivateGcp {
                config,
                release_dir,
                node_config,
                receipt,
                approve,
            } => {
                require_approval(approve, "activate-gcp")?;
                activation::activate_gcp(&config, &release_dir, &node_config, &receipt)
            }
            DeployCommand::ReplaceNode {
                config,
                release_dir,
                backup_id,
                receipt,
                approve,
                confirm,
            } => {
                require_approval(approve, "replace-node")?;
                let intent = config::load(&config)?;
                if confirm != intent.metadata.name {
                    bail!(
                        "--confirm must exactly match deployment name {:?}",
                        intent.metadata.name
                    );
                }
                recovery::replace_gcp_node(&config, &release_dir, backup_id, &receipt)
            }
        },
        Command::Backup(args) => match args.command {
            BackupCommand::Create {
                config,
                release_dir,
                output,
                approve,
            } => {
                require_approval(approve, "backup create")?;
                recovery::create_backup(&config, &release_dir, &output)
            }
            BackupCommand::Verify { config, backup_id } => {
                let value = recovery::verify_backup(&config, backup_id)?;
                print_json(&value)
            }
            BackupCommand::Restore {
                config,
                release_dir,
                backup_id,
                output,
                approve,
            } => {
                require_approval(approve, "backup restore")?;
                recovery::restore_backup(&config, &release_dir, backup_id, &output)
            }
        },
        Command::Secret(args) => match args.command {
            SecretCommand::Set {
                config,
                name,
                stdin,
            } => {
                let intent = config::load(&config)?;
                if !intent
                    .spec
                    .secret_names
                    .iter()
                    .any(|candidate| candidate == &name)
                {
                    bail!("secret {name:?} is not declared in spec.secretNames");
                }
                let value = if stdin {
                    secrets::read_stdin().context("read secret from stdin")?
                } else {
                    secrets::read_hidden(&format!("Value for {name}: "))?
                };
                secrets::set(&config, &intent, &name, value)
            }
            SecretCommand::InitializeInternal { config, approve } => {
                require_approval(approve, "secret initialize-internal")?;
                let intent = config::load(&config)?;
                secrets::initialize_internal(&config, &intent)
            }
        },
        Command::Agent(args) => execute_agent(args),
        Command::Launch(args) => {
            if matches!(args.provider, LaunchProvider::Local) {
                return crate::local::launch(crate::local::Request {
                    name: args.name,
                    directory: args
                        .local_dir
                        .unwrap_or_else(|| PathBuf::from(".thelve-local")),
                    release: args.release_dir,
                    email: args
                        .admin_email
                        .or(args.tls_contact_email)
                        .context("--admin-email is required for a local launch")?,
                    issuer_url: args.issuer_url,
                    license_service_url: args.license_service_url,
                    issuer_trust_sha256: args.issuer_trust_sha256,
                    approve: args.approve,
                });
            }
            launch::launch(&launch::LaunchRequest {
                identity: launch_identity(&args),
                provider: match args.provider {
                    LaunchProvider::Gcp => config::CloudProvider::Gcp,
                    LaunchProvider::Aws => config::CloudProvider::Aws,
                    LaunchProvider::Local => unreachable!(),
                },
                name: args.name,
                project: args.project,
                region: args
                    .region
                    .context("--region is required for a cloud launch")?,
                zone: args.zone.context("--zone is required for a cloud launch")?,
                host_image: args
                    .host_image
                    .context("--host-image is required for a cloud launch")?,
                state_bucket: args
                    .state_bucket
                    .context("--state-bucket is required for a cloud launch")?,
                domains: args.domains.into_iter().collect(),
                tls_contact_email: args
                    .tls_contact_email
                    .context("--tls-contact-email is required for a cloud launch")?,
                administrator_email: args.admin_email,
                release_dir: args.release_dir,
                issuer_url: args.issuer_url,
                issuer_trust_sha256: args.issuer_trust_sha256,
                license_service_url: args.license_service_url,
                skip_license: args.skip_license,
                config: args.config,
                node_config: args.node_config,
                activation_receipt: args.activation_receipt,
                receipt: args.receipt,
                approve: args.approve,
            })
        }
        Command::License(args) => match args.command {
            LicenseCommand::Status { config } => {
                let intent = config::load(&config)?;
                match &intent.spec.licensing.certificate {
                    Some(certificate) => print_json(&license::summary(certificate)),
                    None => {
                        println!(
                            "no certificate recorded in {}; this installation's tenant id is {}",
                            config.display(),
                            launch::installation_tenant_id(&intent.metadata.name)
                        );
                        Ok(())
                    }
                }
            }
            LicenseCommand::Trust {
                issuer_url,
                expect_sha256,
            } => print_json(&license::trust(&issuer_url, expect_sha256.as_deref())?),
            LicenseCommand::Install {
                profile,
                certificate,
                idempotency_key,
                config,
                release_dir,
                tls_contact_email,
                node_config,
                activation_receipt,
                approve,
            } => match (profile, config) {
                (Some(profile), None) => {
                    print_json(&license::install(&profile, &certificate, idempotency_key)?)
                }
                (None, Some(config)) => {
                    require_approval(approve, "license install --config")?;
                    license::install_via_render(
                        &config,
                        &certificate,
                        &release_dir.expect("clap requires release_dir with config"),
                        &tls_contact_email.expect("clap requires tls_contact_email with config"),
                        &node_config,
                        &activation_receipt,
                    )
                }
                _ => bail!(
                    "pass either --profile (installed through the API) or --config (installed at boot)"
                ),
            },
        },
        Command::Mcp(args) => match args.command {
            McpCommand::Serve { profile } => mcp::serve(&profile),
        },
        Command::Skill(args) => match args.command {
            SkillCommand::Install {
                target,
                profile,
                configure_mcp,
            } => skills::install(target, &profile, configure_mcp),
        },
    }
}

fn execute_agent(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Profile(args) => match args.command {
            AgentProfileCommand::Create {
                name,
                api_url,
                tenant_id,
                key_id,
                seed_file,
            } => print_json(&agent::create_profile(
                &name,
                &api_url,
                tenant_id,
                &key_id,
                seed_file.as_deref(),
            )?),
            AgentProfileCommand::Bind {
                name,
                delegation_id,
            } => print_json(&agent::bind_profile(&name, delegation_id)?),
            AgentProfileCommand::Show { name } => print_json(&agent::show_profile(&name)?),
        },
        AgentCommand::PublicKey { profile } => print_json(&agent::show_public_key(&profile)?),
        AgentCommand::Capabilities { profile } => {
            print_json(&agent::AgentClient::load(&profile)?.catalog()?)
        }
        AgentCommand::Invoke(args) => {
            let input = agent::read_json_input(&args.input)?;
            let result =
                agent::AgentClient::load(&args.profile)?.invoke_guarded(agent::CapabilityCall {
                    capability: args.capability,
                    resource_type: args.resource_type,
                    resource_id: args.resource_id,
                    input,
                    approval_id: args.approval_id,
                    idempotency_key: args
                        .idempotency_key
                        .unwrap_or_else(|| Uuid::new_v4().to_string()),
                })?;
            print_json(&result)
        }
        AgentCommand::Plan(args) => {
            let input = agent::read_json_input(&args.input)?;
            let result =
                agent::AgentClient::load(&args.profile)?.create_plan(agent::PlanRequest {
                    capability: args.capability,
                    resource_type: args.resource_type,
                    resource_id: args.resource_id,
                    input,
                    reason: args.reason,
                    control: args.control.into(),
                    expires_in_seconds: args.expires_in_seconds,
                    idempotency_key: args.idempotency_key,
                })?;
            print_json(&result)
        }
        AgentCommand::PlanRead {
            profile,
            approval_id,
        } => print_json(&agent::AgentClient::load(&profile)?.read_plan(approval_id)?),
        AgentCommand::PlanList {
            profile,
            status,
            limit,
        } => print_json(&agent::AgentClient::load(&profile)?.list_plans(status.as_deref(), limit)?),
        AgentCommand::Apply {
            profile,
            approval_id,
        } => print_json(&agent::AgentClient::load(&profile)?.apply_plan(approval_id)?),
    }
}

fn print_json(value: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn require_approval(approved: bool, operation: &str) -> Result<()> {
    if !approved {
        bail!("{operation} changes cloud resources; rerun with --approve after reviewing the plan");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn local_launch_does_not_require_cloud_infrastructure_flags() {
        let cli = Cli::try_parse_from([
            "thelve",
            "launch",
            "--provider",
            "local",
            "--name",
            "local-test",
            "--release-dir",
            "/release",
            "--admin-email",
            "operator@example.com",
            "--approve",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Command::Launch(args) if matches!(args.provider, LaunchProvider::Local))
        );
    }

    #[test]
    fn local_lifecycle_is_available_but_building_is_not() {
        for action in ["status", "stop", "destroy"] {
            assert!(
                Cli::try_parse_from(["thelve", "dev", action, "--local-dir", "/appliance"]).is_ok()
            );
        }
        assert!(
            Cli::try_parse_from([
                "thelve",
                "dev",
                "release",
                "build",
                "--source",
                "/source",
                "--reference-release",
                "/reference",
                "--output",
                "/release"
            ])
            .is_err()
        );
    }

    #[test]
    fn local_install_has_no_source_or_issuer_build_options() {
        for option in ["--source", "--local-license"] {
            assert!(
                Cli::try_parse_from([
                    "thelve",
                    "launch",
                    "--provider",
                    "local",
                    "--name",
                    "local-test",
                    "--release-dir",
                    "/release",
                    option,
                    "/source"
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn destructive_operations_require_explicit_approval() {
        assert!(require_approval(false, "destroy").is_err());
        assert!(require_approval(true, "destroy").is_ok());
    }

    #[test]
    fn release_verification_requires_an_independent_trust_root_pin() {
        assert!(
            Cli::try_parse_from([
                "thelve",
                "release",
                "verify",
                "--document",
                "release.json",
                "--signature",
                "release.signature.json",
                "--trust-root",
                "trust.json",
                "--kind",
                "release",
            ])
            .is_err()
        );
    }
}
