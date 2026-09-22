//! Root-local provider configuration. Keys travel only over protected stdin.
use crate::{
    process::{self, CommandPlan},
    secrets,
};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Args)]
pub struct ProviderArgs {
    #[command(subcommand)]
    command: ProviderCommand,
}
#[derive(Debug, Subcommand)]
enum ProviderCommand {
    Configure(ConfigureArgs),
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Provider {
    Telnyx,
    Vapi,
}
#[derive(Debug, Args)]
struct ConfigureArgs {
    #[arg(value_enum)]
    provider: Provider,
    /// Read the key from this environment variable, never a literal argument.
    #[arg(long, conflicts_with = "key_file")]
    key_env: Option<String>,
    /// Read an owner-only, non-symlink key file. Otherwise use a hidden prompt.
    #[arg(long)]
    key_file: Option<std::path::PathBuf>,
}

pub fn run(args: ProviderArgs) -> Result<()> {
    let ProviderCommand::Configure(args) = args.command;
    ensure!(
        std::env::consts::OS == "linux",
        "run provider configuration on the Linux appliance host"
    );
    ensure!(
        process::capture(&CommandPlan::new("id").arg("-u"))?.trim() == "0",
        "run provider configuration as root"
    );
    ensure!(
        std::env::var_os("DOCKER_HOST").is_none(),
        "provider configuration requires local Docker"
    );
    let context = process::capture(&CommandPlan::new("docker").args([
        "context",
        "inspect",
        "--format",
        "{{.Endpoints.docker.Host}}",
    ]))?;
    ensure!(
        context.trim().starts_with("unix://"),
        "provider configuration requires local Docker"
    );
    let key = if let Some(name) = args.key_env {
        secrets::read_environment(&name)?
    } else if let Some(path) = args.key_file {
        secrets::read_private_file(&path)?
    } else {
        secrets::read_hidden("Provider API key (hidden): ")?
    };
    let provider = match args.provider {
        Provider::Telnyx => "telnyx",
        Provider::Vapi => "vapi",
    };
    #[derive(serde::Serialize)]
    struct Input<'a> {
        provider: &'a str,
        api_key: &'a str,
    }
    let payload = zeroize::Zeroizing::new(serde_json::to_vec(&Input {
        provider,
        api_key: &key,
    })?);
    process::with_secret_stdin(
        &CommandPlan::new("docker").args([
            "exec",
            "--user",
            "root",
            "-i",
            "thelve",
            "thelve-appliance",
            "configure-provider",
        ]),
        &payload,
    )?;
    println!("{provider} configured. Continue resource setup in the Thelve settings page.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: ProviderArgs,
    }
    #[test]
    fn keys_are_never_literal_cli_arguments() {
        assert!(TestCli::try_parse_from(["test", "configure", "vapi"]).is_ok());
        assert!(
            TestCli::try_parse_from(["test", "configure", "telnyx", "--key-env", "TELNYX_API_KEY"])
                .is_ok()
        );
        assert!(
            TestCli::try_parse_from(["test", "configure", "vapi", "--api-key", "secret"]).is_err()
        );
        assert!(TestCli::try_parse_from(["test", "configure", "other"]).is_err());
        assert!(
            TestCli::try_parse_from([
                "test",
                "configure",
                "vapi",
                "--key-env",
                "VAPI_API_KEY",
                "--key-file",
                "/tmp/key"
            ])
            .is_err()
        );
    }
}
