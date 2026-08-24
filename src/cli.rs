use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::{activation, agent, catalog, cloud, config, mcp, preview, secrets, skills, terraform};

#[derive(Debug, Parser)]
#[command(name = "thelve", version, about = "Cloud-only Thelve deployment CLI")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check cloud identity, permissions, and local deployment prerequisites.
    Doctor(DoctorArgs),
    /// Verify signed release, channel, and machine-image catalogs.
    #[command(alias = "catalog")]
    Release(CatalogArgs),
    /// Create and operate a cloud single-node deployment.
    Deploy(DeployArgs),
    /// Populate cloud secret-manager values without Terraform state or argv exposure.
    Secret(SecretArgs),
    /// Configure and use a bounded AAuth client for a deployed Thelve system.
    Agent(AgentArgs),
    /// Serve the safe local Model Context Protocol bridge over stdio.
    Mcp(McpArgs),
    /// Install the portable Thelve skills for Codex and Claude.
    Skill(SkillArgs),
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
