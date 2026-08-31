mod activation;
mod agent;
mod catalog;
mod cli;
mod cloud;
mod config;
mod mcp;
mod preview;
mod process;
mod recovery;
mod secrets;
mod skills;
mod terraform;

use anyhow::Result;
use clap::Parser;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let command = cli::Cli::parse();
    cli::execute(command)
}
