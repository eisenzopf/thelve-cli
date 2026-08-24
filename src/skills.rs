use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use include_dir::{Dir, DirEntry, include_dir};

static PLUGIN: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/distribution/plugins/thelve-agent");
const MANAGED_MARKER: &str = ".thelve-managed";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SkillTarget {
    Codex,
    Claude,
    All,
}

pub fn install(target: SkillTarget, profile: &str, configure_mcp: bool) -> Result<()> {
    validate_profile_name(profile)?;
    let home = install_home()?;
    let mut installed = Vec::new();
    if matches!(target, SkillTarget::Codex | SkillTarget::All) {
        let root = home.join(".agents").join("skills");
        install_skills(&root)?;
        installed.push(format!("Codex skills: {}", root.display()));
        if configure_mcp {
            register_mcp(
                "codex",
                &[
                    "mcp",
                    "add",
                    "thelve",
                    "--",
                    "thelve",
                    "mcp",
                    "serve",
                    "--profile",
                    profile,
                ],
            )?;
        }
    }
    if matches!(target, SkillTarget::Claude | SkillTarget::All) {
        let root = home.join(".claude").join("skills");
        install_skills(&root)?;
        installed.push(format!("Claude skills: {}", root.display()));
        if configure_mcp {
            register_mcp(
                "claude",
                &[
                    "mcp",
                    "add",
                    "--transport",
                    "stdio",
                    "--scope",
                    "user",
                    "thelve",
                    "--",
                    "thelve",
                    "mcp",
                    "serve",
                    "--profile",
                    profile,
                ],
            )?;
        }
    }
    for item in installed {
        println!("{item}");
    }
    if !configure_mcp {
        println!(
            "skills installed; rerun with --configure-mcp after profile {profile:?} is bound and `thelve` is on PATH"
        );
    }
    Ok(())
}

fn install_skills(destination_root: &Path) -> Result<()> {
    fs::create_dir_all(destination_root)
        .with_context(|| format!("create skill root {}", destination_root.display()))?;
    let source_root = PLUGIN
        .get_dir("skills")
        .ok_or_else(|| anyhow!("packaged Thelve skills are missing"))?;
    for name in ["thelve-admin", "thelve-cloud"] {
        let source = source_root
            .get_dir(name)
            .ok_or_else(|| anyhow!("packaged skill {name} is missing"))?;
        let destination = destination_root.join(name);
        if destination.exists() && !destination.join(MANAGED_MARKER).is_file() {
            bail!(
                "refusing to overwrite unmanaged skill {}; move it aside or install the Thelve plugin manually",
                destination.display()
            );
        }
        fs::create_dir_all(&destination)
            .with_context(|| format!("create skill {}", destination.display()))?;
        materialize(source, Path::new(""), &destination)?;
        fs::write(
            destination.join(MANAGED_MARKER),
            format!("thelve-cli {}\n", env!("CARGO_PKG_VERSION")),
        )
        .with_context(|| format!("mark managed skill {}", destination.display()))?;
    }
    Ok(())
}

fn materialize(source: &Dir<'_>, relative: &Path, destination: &Path) -> Result<()> {
    for entry in source.entries() {
        match entry {
            DirEntry::Dir(directory) => {
                let name = directory
                    .path()
                    .file_name()
                    .ok_or_else(|| anyhow!("packaged skill directory has no name"))?;
                let next_relative = relative.join(name);
                let next_destination = destination.join(name);
                fs::create_dir_all(&next_destination).with_context(|| {
                    format!("create skill directory {}", next_destination.display())
                })?;
                materialize(directory, &next_relative, &next_destination)?;
            }
            DirEntry::File(file) => {
                let name = file
                    .path()
                    .file_name()
                    .ok_or_else(|| anyhow!("packaged skill file has no name"))?;
                let path = destination.join(name);
                fs::write(&path, file.contents())
                    .with_context(|| format!("install skill file {}", path.display()))?;
            }
        }
    }
    Ok(())
}

fn register_mcp(program: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .with_context(|| {
            format!(
                "launch {program}; install it or register `thelve mcp serve --profile PROFILE` manually"
            )
        })?;
    if !status.success() {
        bail!(
            "{program} refused MCP registration (status {status}); inspect its existing `thelve` server before changing it"
        );
    }
    Ok(())
}

fn install_home() -> Result<PathBuf> {
    if let Some(root) = std::env::var_os("THELVE_SKILL_INSTALL_HOME") {
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            bail!("THELVE_SKILL_INSTALL_HOME must be absolute");
        }
        return Ok(root);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME or THELVE_SKILL_INSTALL_HOME is required"))
}

fn validate_profile_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        bail!("profile name must be a normalized local identifier");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distribution_contains_both_valid_skill_entrypoints() {
        for name in ["thelve-admin", "thelve-cloud"] {
            let skill = PLUGIN
                .get_file(format!("skills/{name}/SKILL.md"))
                .expect("packaged skill");
            let text = skill.contents_utf8().expect("UTF-8 skill");
            assert!(text.starts_with("---\nname: "));
            assert!(!text.contains("[TODO"));
        }
    }
}
