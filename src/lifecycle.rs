//! Release lifecycle on a running GCP node: roll back to an installed
//! release, and collect a value-free support bundle.
//!
//! Upgrading is `deploy activate-gcp` with the newer verified release — the
//! node manager's install is convergent and the activation transport already
//! records the receipt — so no separate upgrade verb exists here. Both
//! commands below run the node manager over the same IAP/OS Login session
//! activation uses and capture only what it prints, which is redacted by
//! construction.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use uuid::Uuid;

use crate::activation;

const NODE_MANAGER: &str = "/opt/thelve/bin/thelve-node";
const NODE_CONFIG: &str = "/etc/thelve/node.yaml";

fn sudo_node(arguments: &str) -> String {
    format!("sudo sh -c 'ulimit -n 65536; exec \"$@\"' thelve-node {NODE_MANAGER} {arguments}")
}

fn valid_installed_release_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

/// Roll the node back onto `installed_release_id` and write the node
/// manager's receipt locally.
pub fn rollback(config_path: &Path, installed_release_id: &str, receipt: &Path) -> Result<()> {
    if !valid_installed_release_id(installed_release_id) {
        bail!("--to must be an installed release id (release id plus intent suffix)");
    }
    if receipt.exists() {
        bail!("refusing to overwrite existing {}", receipt.display());
    }
    let operation_id = Uuid::new_v4();
    let output = activation::capture_gcp_remote(
        config_path,
        sudo_node(&format!(
            "rollback --config {NODE_CONFIG} --to {installed_release_id} --operation-id {operation_id}"
        )),
        "rollback",
    )?;
    let document = first_json_document(&output).context("rollback receipt")?;
    if document.get("action").and_then(Value::as_str) != Some("rollback") {
        bail!("node manager did not return a rollback receipt");
    }
    fs::write(receipt, serde_json::to_vec_pretty(&document)?)
        .with_context(|| format!("write {}", receipt.display()))?;
    println!(
        "rolled back to {installed_release_id}; receipt written to {}",
        receipt.display()
    );
    Ok(())
}

/// Fetch the node manager's support bundle to a local file.
pub fn support_bundle(config_path: &Path, output: &Path) -> Result<()> {
    if output.exists() {
        bail!("refusing to overwrite existing {}", output.display());
    }
    let captured = activation::capture_gcp_remote(
        config_path,
        sudo_node(&format!("support-bundle --config {NODE_CONFIG}")),
        "support-bundle",
    )?;
    let document = first_json_document(&captured).context("support bundle")?;
    if document.get("secretValuesRecorded") != Some(&Value::Bool(false)) {
        bail!("support bundle did not attest that no secret values were recorded");
    }
    fs::write(output, serde_json::to_vec_pretty(&document)?)
        .with_context(|| format!("write {}", output.display()))?;
    println!("support bundle written to {}", output.display());
    Ok(())
}

/// The node manager prints one pretty JSON document; the SSH transport may
/// wrap it in banner lines.
fn first_json_document(captured: &str) -> Result<Value> {
    let start = captured
        .find('{')
        .context("no JSON document in the node manager output")?;
    serde_json::from_str(&captured[start..]).context("node manager output is not a JSON document")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_commands_are_bounded_and_documents_are_extracted() {
        assert!(valid_installed_release_id(
            "018f6f4e-6ac8-7e33-9e70-1f63c7f41a01-0123456789ab"
        ));
        assert!(!valid_installed_release_id("../etc"));
        assert!(!valid_installed_release_id("a b"));
        let command = sudo_node("support-bundle --config /etc/thelve/node.yaml");
        assert!(command.ends_with(
            "thelve-node /opt/thelve/bin/thelve-node support-bundle --config /etc/thelve/node.yaml"
        ));
        let document =
            first_json_document("Warning: banner\n{\n  \"action\": \"rollback\"\n}\n").unwrap();
        assert_eq!(document["action"], "rollback");
        assert!(first_json_document("no document here").is_err());
    }
}
