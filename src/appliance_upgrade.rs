//! Explicit signed-candidate upgrade. Never reseeds or replaces installation secrets.
use crate::{
    appliance,
    process::{self, CommandPlan},
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug, Args)]
pub struct UpgradeArgs {
    /// Exact new image manifest; signature verification is mandatory.
    #[arg(long)]
    image: String,
    #[arg(long, value_enum, default_value = "release-key")]
    image_signer: appliance::ImageSigner,
    /// Explicitly admit a test candidate, not production qualification.
    #[arg(long)]
    signed_test_candidate: bool,
    #[arg(long)]
    approve: bool,
}

fn docker(args: &[&str]) -> CommandPlan {
    CommandPlan::new("docker").args(args.iter().copied())
}

struct UpgradeLock;
impl Drop for UpgradeLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir("/run/thelve-upgrade.lock");
    }
}

fn mounted_paths(container: &Value) -> Result<(PathBuf, PathBuf)> {
    ensure!(
        container["State"]["Running"] == true,
        "appliance must be running before upgrade"
    );
    ensure!(
        container["HostConfig"]["NetworkMode"] == "host"
            && container["HostConfig"]["ReadonlyRootfs"] == true,
        "existing container does not match the portable appliance topology"
    );
    ensure!(
        container["Config"]["Labels"]["io.thelve.installation.status"] == "signed-test-candidate",
        "this upgrade path is only for an existing signed test candidate"
    );
    let mounts = container["Mounts"]
        .as_array()
        .context("appliance mounts unavailable")?;
    let resolve = |destination: &str, writable: bool| -> Result<PathBuf> {
        let matching: Vec<_> = mounts
            .iter()
            .filter(|m| m["Destination"] == destination)
            .collect();
        ensure!(
            matching.len() == 1,
            "appliance mount is missing or ambiguous"
        );
        let mount = matching[0];
        ensure!(
            mount["Type"] == "bind" && mount["RW"] == writable,
            "unexpected appliance mount type or permissions"
        );
        let source = mount["Source"]
            .as_str()
            .context("mount source unavailable")?;
        let path = PathBuf::from(source);
        ensure!(
            path.is_absolute()
                && path.components().count() >= 3
                && !source.contains([',', '\n', '\r']),
            "unsafe appliance mount source"
        );
        Ok(path)
    };
    let configuration = resolve("/etc/thelve", false)?;
    let data = resolve("/var/lib/thelve", true)?;
    ensure!(
        !configuration.starts_with(&data) && !data.starts_with(&configuration),
        "configuration and data mounts overlap"
    );
    Ok((configuration, data))
}

fn environment_bytes(container: &Value) -> Result<Vec<u8>> {
    let entries = container["Config"]["Env"]
        .as_array()
        .context("container environment unavailable")?;
    let mut output = String::new();
    for entry in entries {
        let value = entry.as_str().context("invalid container environment")?;
        let (name, _) = value
            .split_once('=')
            .context("environment entry has no value separator")?;
        ensure!(
            !name.is_empty()
                && !name.as_bytes()[0].is_ascii_digit()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                && !value.contains(['\n', '\r', '\0']),
            "environment cannot be losslessly represented in an env file"
        );
        output.push_str(value);
        output.push('\n');
    }
    Ok(output.into_bytes())
}

fn candidate_environment(container: &Value) -> Result<Vec<u8>> {
    let mut bytes = environment_bytes(container)?;
    let text = std::str::from_utf8(&bytes)?;
    let value = |name: &str| {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(key, _)| *key == name)
            .map(|(_, value)| value)
            .next_back()
    };
    // Bring an existing portable installation in line with the current render
    // defaults. Both consumers retain separate protected object namespaces.
    if value("THELVE_APPLIANCE_MODE") == Some("portable_oci")
        && value("GOVERNED_RUNTIME_OBJECT_STORE_URL").is_none_or(str::is_empty)
    {
        let destination = value("ATTACHMENT_OBJECT_STORE_URL")
            .filter(|url| !url.is_empty())
            .context("portable appliance object store is missing")?;
        let addition = format!("GOVERNED_RUNTIME_OBJECT_STORE_URL={destination}\n");
        bytes.extend_from_slice(addition.as_bytes());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(_path: &Path, _bytes: &[u8]) -> Result<()> {
    anyhow::bail!("upgrade requires a Linux host")
}

pub fn upgrade(args: UpgradeArgs) -> Result<()> {
    ensure!(
        args.approve && args.signed_test_candidate,
        "upgrade requires --approve and --signed-test-candidate"
    );
    ensure!(
        std::env::consts::OS == "linux",
        "run upgrade on the Linux appliance host"
    );
    appliance::validate_image(&args.image)?;
    ensure!(
        std::env::var_os("DOCKER_HOST").is_none(),
        "upgrade requires local Docker"
    );
    ensure!(
        process::capture(&CommandPlan::new("id").arg("-u"))?.trim() == "0",
        "run upgrade as root"
    );
    fs::create_dir("/run/thelve-upgrade.lock").context(
        "upgrade lock exists; verify no upgrade is running before recovering a stale lock",
    )?;
    let _upgrade_lock = UpgradeLock;
    let endpoint = process::capture(&docker(&[
        "context",
        "inspect",
        "--format",
        "{{.Endpoints.docker.Host}}",
    ]))?;
    ensure!(
        endpoint.trim().starts_with("unix://"),
        "upgrade requires local Docker"
    );
    let inspection =
        process::capture_named(&docker(&["inspect", "thelve"]), "inspect current appliance")?;
    let parsed: Value = serde_json::from_str(&inspection)?;
    let container = parsed.get(0).context("current appliance unavailable")?;
    let (configuration, data) = mounted_paths(container)?;
    ensure!(
        configuration.canonicalize()? == configuration && data.canonicalize()? == data,
        "appliance paths must be canonical"
    );
    let environment = environment_bytes(container)?;
    let new_environment = candidate_environment(container)?;
    ensure!(
        container["Config"]["Env"]
            .as_array()
            .is_some_and(|values| values
                .iter()
                .any(|value| value == "PGDATA=/var/lib/thelve/postgres")),
        "PostgreSQL must reside in the backed-up appliance data mount"
    );
    appliance::verify_image(&args.image, args.image_signer)?;
    process::inherit(&docker(&["pull", &args.image]))?;
    let host_arch = std::env::consts::ARCH;
    let expected_arch = match host_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => anyhow::bail!("unsupported host architecture"),
    };
    let arch = process::capture(&docker(&[
        "image",
        "inspect",
        "--format",
        "{{.Architecture}}",
        &args.image,
    ]))?;
    ensure!(
        arch.trim() == expected_arch,
        "candidate architecture differs from host"
    );

    let backup_root = Path::new("/var/backups/thelve");
    fs::create_dir_all(backup_root)?;
    ensure!(
        backup_root.canonicalize()? == backup_root,
        "backup root must not be a symlink"
    );
    let backup = tempfile::Builder::new()
        .prefix("upgrade-")
        .tempdir_in(backup_root)?
        .keep();
    let suffix = backup
        .file_name()
        .and_then(|s| s.to_str())
        .context("backup path invalid")?;
    let previous = format!("thelve-before-{suffix}");
    write_private(
        &backup.join("container-inspect.json"),
        inspection.as_bytes(),
    )?;
    write_private(&backup.join("appliance.env"), &environment)?;
    write_private(&backup.join("candidate.env"), &new_environment)?;
    let archive = backup.join("configuration-and-data.tar.gz");
    let archive = archive.to_str().context("archive path invalid")?;
    let configuration_text = configuration
        .to_str()
        .context("configuration path invalid")?;
    let data_text = data.to_str().context("data path invalid")?;
    // Validate the complete replacement command before causing any downtime.
    let mut plan = appliance::run_plan(&args.image, configuration_text, data_text)?;
    let env_index = plan
        .args
        .iter()
        .position(|value| value == "--env-file")
        .context("upgrade environment option missing")?;
    plan.args[env_index + 1] = backup.join("candidate.env").to_string_lossy().into_owned();
    appliance::configure_test_candidate(&mut plan)?;
    // Stop before snapshotting PostgreSQL. If snapshot fails, restart the unchanged container.
    process::inherit(&docker(&["stop", "--time", "120", "thelve"]))?;
    let snapshot = process::inherit(&CommandPlan::new("tar").args([
        "--numeric-owner",
        "--xattrs",
        "-czf",
        archive,
        "-C",
        "/",
        "--",
        configuration_text.trim_start_matches('/'),
        data_text.trim_start_matches('/'),
    ]))
    .and_then(|()| {
        let checksum = process::capture(&CommandPlan::new("sha256sum").arg(archive))?;
        write_private(&backup.join("SHA256SUMS"), checksum.as_bytes())
    });
    if let Err(error) = snapshot {
        let _ = process::inherit(&docker(&["start", "thelve"]));
        return Err(error.context("snapshot failed; attempted restart of unchanged appliance"));
    }
    if let Err(error) = process::inherit(&docker(&["rename", "thelve", &previous])) {
        let _ = process::inherit(&docker(&["start", "thelve"]));
        return Err(error.context("rename failed; attempted restart of unchanged appliance"));
    }
    // No automatic rollback after starting a new image: database migrations may have run.
    process::inherit(&plan).with_context(|| {
        format!(
            "candidate failed to start; recovery snapshot: {}; previous container: {previous}",
            backup.display()
        )
    })?;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(600) {
        let state = process::capture(&docker(&[
            "inspect",
            "--format",
            "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
            "thelve",
        ]))?;
        if state.trim() == "running healthy" {
            println!(
                "Upgrade healthy. Recovery snapshot: {}; previous container: {previous}",
                backup.display()
            );
            return Ok(());
        }
        if !state.starts_with("running") {
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    anyhow::bail!(
        "candidate did not become healthy; snapshot: {}; previous container: {previous}; no recovery data was deleted",
        backup.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn container() -> Value {
        json!({"State":{"Running":true}, "HostConfig":{"NetworkMode":"host","ReadonlyRootfs":true},
            "Config":{"Labels":{"io.thelve.installation.status":"signed-test-candidate"},"Env":["KEY=private","EMPTY="]},
            "Mounts":[{"Type":"bind","Source":"/etc/thelve-test","Destination":"/etc/thelve","RW":false},
                {"Type":"bind","Source":"/var/lib/thelve-test","Destination":"/var/lib/thelve","RW":true}]})
    }
    #[test]
    fn only_exact_portable_candidate_mounts_are_adopted() {
        assert!(mounted_paths(&container()).is_ok());
        for path in ["/", "/etc", "relative/path", "/etc/bad,path"] {
            let mut value = container();
            value["Mounts"][0]["Source"] = json!(path);
            assert!(mounted_paths(&value).is_err());
        }
        let mut value = container();
        value["Mounts"][0]["RW"] = json!(true);
        assert!(mounted_paths(&value).is_err());
        let mut value = container();
        value["Config"]["Labels"] = json!({});
        assert!(mounted_paths(&value).is_err());
    }
    #[test]
    fn environment_preserves_values_and_rejects_lossy_multiline_encoding() {
        assert_eq!(
            environment_bytes(&container()).unwrap(),
            b"KEY=private\nEMPTY=\n"
        );
        for value in [
            "KEY=one\ntwo",
            "KEY=one\rtwo",
            "BAD",
            "KEY=\0",
            "#KEY=lost",
            "=missing",
            "1KEY=bad",
        ] {
            let mut input = container();
            input["Config"]["Env"] = json!([value]);
            assert!(environment_bytes(&input).is_err());
        }
    }

    #[test]
    fn upgrade_adds_portable_store_default_without_overwriting_explicit_settings() {
        let mut input = container();
        input["Config"]["Env"] = json!([
            "THELVE_APPLIANCE_MODE=portable_oci",
            "ATTACHMENT_OBJECT_STORE_URL=s3://local-objects",
            "VAPI_API_KEY_FILE=/private/key"
        ]);
        let expected = candidate_environment(&input).unwrap();
        let text = std::str::from_utf8(&expected).unwrap();
        assert!(text.contains("GOVERNED_RUNTIME_OBJECT_STORE_URL=s3://local-objects\n"));
        assert!(text.contains("VAPI_API_KEY_FILE=/private/key\n"));
        input["Config"]["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("GOVERNED_RUNTIME_OBJECT_STORE_URL=s3://dedicated"));
        assert_eq!(
            candidate_environment(&input).unwrap(),
            environment_bytes(&input).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn recovery_environment_is_private_and_cannot_be_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("environment");
        write_private(&path, b"KEY=test-only\n").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_private(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"KEY=test-only\n");
    }
}
