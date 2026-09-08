//! Local appliance administration; release builds belong to private tooling.
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct DevArgs {
    #[command(subcommand)]
    command: DevCommand,
}

#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Show the local appliance containers.
    Status(LocalArgs),
    /// Drain and stop the local appliance, preserving its data.
    Stop(LocalArgs),
    /// Remove the local appliance, its data, and its local credentials.
    Destroy(LocalArgs),
}

#[derive(Debug, Args)]
struct LocalArgs {
    #[arg(long, default_value = ".thelve-local")]
    local_dir: PathBuf,
    #[arg(long)]
    approve: bool,
}

pub fn execute(args: DevArgs) -> Result<()> {
    match args.command {
        DevCommand::Status(args) => crate::local::operate(&args.local_dir, "status", args.approve),
        DevCommand::Stop(args) => crate::local::operate(&args.local_dir, "stop", args.approve),
        DevCommand::Destroy(args) => {
            crate::local::operate(&args.local_dir, "destroy", args.approve)
        }
    }
}
