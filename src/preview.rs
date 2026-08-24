use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::Builder;
use uuid::Uuid;

use crate::{
    catalog::{self, CatalogKind},
    process::{self, CommandPlan},
};

const FETCH_RECEIPT_SCHEMA: &str = "thelve.preview-release-fetch-receipt/v1";
const MAX_NODE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TRUST_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreviewRelease {
    pub schema_version: String,
    pub metadata: PreviewMetadata,
    pub spec: PreviewSpec,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreviewMetadata {
    pub release: String,
    pub release_id: String,
    pub created_at: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub cloud_build_id: String,
    pub preview_only: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreviewSpec {
    pub project_id: String,
    pub region: String,
    pub registry_prefix: String,
    pub deployment_release_sha256: String,
    pub deployment_bundle: RemoteObject,
    pub node_manager: RemoteObject,
    pub offline_trust_store: RemoteObject,
    pub catalog_trust_root: RemoteObject,
    pub images: Vec<ImageRecord>,
    pub qualification: PreviewQualification,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RemoteObject {
    pub gcs_uri: String,
    pub https_uri: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ImageRecord {
    pub component_id: String,
    pub repository: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreviewQualification {
    pub production_qualified: bool,
    pub requires_explicit_preview_admission: bool,
    pub open_gates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchReceipt {
    pub schema_version: String,
    pub release: String,
    pub release_id: String,
    pub project_id: String,
    pub region: String,
    pub descriptor_sha256: String,
    pub trust_root_sha256: String,
    pub deployment_release_sha256: String,
    pub artifacts: BTreeMap<String, ArtifactReceipt>,
    pub preview_only: bool,
    pub production_qualified: bool,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub secret_values_recorded: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactReceipt {
    pub sha256: String,
    pub size_bytes: u64,
}

pub fn fetch(
    descriptor_path: &Path,
    signature_path: &Path,
    trust_root_path: &Path,
    trust_root_sha256: &str,
    output: &Path,
    admit_preview: bool,
) -> Result<FetchReceipt> {
    if !admit_preview {
        bail!("private preview retrieval requires --admit-preview");
    }
    if output.exists() {
        bail!("refusing to overwrite existing {}", output.display());
    }
    catalog::verify(
        descriptor_path,
        signature_path,
        trust_root_path,
        trust_root_sha256,
        CatalogKind::PreviewRelease,
    )?;
    let descriptor_bytes = read_bounded(descriptor_path, 4 * 1024 * 1024, "preview descriptor")?;
    let descriptor: PreviewRelease =
        serde_json::from_slice(&descriptor_bytes).context("parse verified preview descriptor")?;
    validate_preview(&descriptor, trust_root_path, trust_root_sha256)?;

    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create preview release parent {}", parent.display()))?;
    let staging = Builder::new()
        .prefix(".thelve-preview-fetch-")
        .tempdir_in(parent)
        .context("create preview release staging directory")?;
    #[cfg(unix)]
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;

    copy_control(
        descriptor_path,
        &staging.path().join("preview-release.json"),
    )?;
    copy_control(
        signature_path,
        &staging.path().join("preview-release.signature.json"),
    )?;
    copy_control(trust_root_path, &staging.path().join("trust-root.json"))?;
    download_object(
        &descriptor.spec.deployment_bundle,
        &staging.path().join("thelve-deployment-bundle.tar.gz"),
        MAX_BUNDLE_BYTES,
    )?;
    download_object(
        &descriptor.spec.node_manager,
        &staging.path().join("thelve-node"),
        MAX_NODE_BYTES,
    )?;
    download_object(
        &descriptor.spec.offline_trust_store,
        &staging.path().join("offline-trust.json"),
        MAX_TRUST_BYTES,
    )?;
    #[cfg(unix)]
    fs::set_permissions(
        staging.path().join("thelve-node"),
        fs::Permissions::from_mode(0o700),
    )?;

    let artifacts = BTreeMap::from([
        (
            "deploymentBundle".into(),
            artifact_receipt(&staging.path().join("thelve-deployment-bundle.tar.gz"))?,
        ),
        (
            "nodeManager".into(),
            artifact_receipt(&staging.path().join("thelve-node"))?,
        ),
        (
            "offlineTrustStore".into(),
            artifact_receipt(&staging.path().join("offline-trust.json"))?,
        ),
    ]);
    let receipt = FetchReceipt {
        schema_version: FETCH_RECEIPT_SCHEMA.into(),
        release: descriptor.metadata.release.clone(),
        release_id: descriptor.metadata.release_id.clone(),
        project_id: descriptor.spec.project_id.clone(),
        region: descriptor.spec.region.clone(),
        descriptor_sha256: sha256_bytes(&descriptor_bytes),
        trust_root_sha256: trust_root_sha256.into(),
        deployment_release_sha256: descriptor.spec.deployment_release_sha256.clone(),
        artifacts,
        preview_only: true,
        production_qualified: false,
        fetched_at: chrono::Utc::now(),
        secret_values_recorded: false,
    };
    create_private_json(&staging.path().join("fetch-receipt.json"), &receipt)?;

    let staging_path = staging.keep();
    fs::rename(&staging_path, output).with_context(|| {
        format!(
            "promote verified preview release {} to {}",
            staging_path.display(),
            output.display()
        )
    })?;
    Ok(receipt)
}

pub fn verify_fetched(root: &Path) -> Result<(FetchReceipt, PreviewRelease)> {
    let receipt_bytes = read_bounded(
        &root.join("fetch-receipt.json"),
        1024 * 1024,
        "fetch receipt",
    )?;
    let receipt: FetchReceipt =
        serde_json::from_slice(&receipt_bytes).context("parse fetch receipt")?;
    if receipt.schema_version != FETCH_RECEIPT_SCHEMA
        || !receipt.preview_only
        || receipt.production_qualified
        || receipt.secret_values_recorded
    {
        bail!("preview fetch receipt is not admissible");
    }
    catalog::verify(
        &root.join("preview-release.json"),
        &root.join("preview-release.signature.json"),
        &root.join("trust-root.json"),
        &receipt.trust_root_sha256,
        CatalogKind::PreviewRelease,
    )?;
    let descriptor_bytes = read_bounded(
        &root.join("preview-release.json"),
        4 * 1024 * 1024,
        "preview descriptor",
    )?;
    if sha256_bytes(&descriptor_bytes) != receipt.descriptor_sha256 {
        bail!("preview descriptor changed after retrieval");
    }
    let descriptor: PreviewRelease =
        serde_json::from_slice(&descriptor_bytes).context("parse verified preview descriptor")?;
    validate_preview(
        &descriptor,
        &root.join("trust-root.json"),
        &receipt.trust_root_sha256,
    )?;
    for (name, file) in [
        ("deploymentBundle", "thelve-deployment-bundle.tar.gz"),
        ("nodeManager", "thelve-node"),
        ("offlineTrustStore", "offline-trust.json"),
    ] {
        let expected = receipt
            .artifacts
            .get(name)
            .with_context(|| format!("fetch receipt is missing {name}"))?;
        let actual = artifact_receipt(&root.join(file))?;
        if actual.sha256 != expected.sha256 || actual.size_bytes != expected.size_bytes {
            bail!("fetched preview artifact {name} changed after retrieval");
        }
    }
    Ok((receipt, descriptor))
}

fn validate_preview(
    descriptor: &PreviewRelease,
    trust_root_path: &Path,
    trust_root_sha256: &str,
) -> Result<()> {
    if descriptor.schema_version != "thelve.gcp-preview-release/v1"
        || !descriptor.metadata.preview_only
        || descriptor.spec.qualification.production_qualified
        || !descriptor
            .spec
            .qualification
            .requires_explicit_preview_admission
        || descriptor.spec.images.len() != 15
        || descriptor.spec.qualification.open_gates.is_empty()
    {
        bail!("preview descriptor has an inadmissible qualification posture");
    }
    chrono::DateTime::parse_from_rfc3339(&descriptor.metadata.created_at)
        .context("preview release creation time is invalid")?;
    Uuid::parse_str(&descriptor.metadata.release_id).context("preview release ID is invalid")?;
    Uuid::parse_str(&descriptor.metadata.cloud_build_id)
        .context("preview Cloud Build ID is invalid")?;
    if descriptor.metadata.source_commit.len() != 40
        || digest_hex(&descriptor.metadata.source_tree_sha256).is_err()
        || digest_hex(&descriptor.spec.deployment_release_sha256).is_err()
        || !descriptor.spec.registry_prefix.starts_with(&format!(
            "{}-docker.pkg.dev/{}/",
            descriptor.spec.region, descriptor.spec.project_id
        ))
    {
        bail!("preview descriptor source or registry identity is invalid");
    }
    let image_ids = descriptor
        .spec
        .images
        .iter()
        .map(|image| image.component_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if image_ids.len() != descriptor.spec.images.len()
        || descriptor.spec.images.iter().any(|image| {
            !image
                .repository
                .starts_with(&format!("{}/", descriptor.spec.registry_prefix))
                || digest_hex(&image.digest).is_err()
        })
    {
        bail!("preview image inventory is duplicated or outside the signed registry");
    }
    let trust = artifact_receipt(trust_root_path)?;
    if trust.sha256 != descriptor.spec.catalog_trust_root.sha256
        || trust.size_bytes != descriptor.spec.catalog_trust_root.size_bytes
        || trust.sha256 != trust_root_sha256
    {
        bail!("independently pinned trust root does not match the signed descriptor");
    }
    let object_parent = gcs_parent(&descriptor.spec.deployment_bundle.gcs_uri)?;
    for (object, maximum) in [
        (&descriptor.spec.deployment_bundle, MAX_BUNDLE_BYTES),
        (&descriptor.spec.node_manager, MAX_NODE_BYTES),
        (&descriptor.spec.offline_trust_store, MAX_TRUST_BYTES),
        (&descriptor.spec.catalog_trust_root, MAX_TRUST_BYTES),
    ] {
        if object.size_bytes == 0
            || object.size_bytes > maximum
            || gcs_parent(&object.gcs_uri)? != object_parent
            || object.https_uri
                != object
                    .gcs_uri
                    .strip_prefix("gs://")
                    .map(|suffix| format!("https://storage.googleapis.com/{suffix}"))
                    .unwrap_or_default()
            || digest_hex(&object.sha256).is_err()
        {
            bail!("preview release objects do not share one bounded immutable prefix");
        }
    }
    Ok(())
}

fn digest_hex(value: &str) -> Result<&str> {
    let digest = value
        .strip_prefix("sha256:")
        .context("value is not a SHA-256 digest")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("value is not a lowercase SHA-256 digest");
    }
    Ok(digest)
}

fn download_object(object: &RemoteObject, destination: &Path, maximum: u64) -> Result<()> {
    if object.size_bytes == 0 || object.size_bytes > maximum || destination.exists() {
        bail!("preview object destination or declared size is invalid");
    }
    process::inherit(&CommandPlan::new("gcloud").args([
        "--quiet".into(),
        "storage".into(),
        "cp".into(),
        object.gcs_uri.clone(),
        destination.display().to_string(),
    ]))?;
    let actual = artifact_receipt(destination)?;
    if actual.sha256 != object.sha256 || actual.size_bytes != object.size_bytes {
        bail!("downloaded preview object failed its signed size or digest");
    }
    #[cfg(unix)]
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn gcs_parent(uri: &str) -> Result<&str> {
    if !uri.starts_with("gs://")
        || uri
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
        || uri.split('/').any(|part| part == "..")
    {
        bail!("preview object has an unsafe GCS URI");
    }
    uri.rsplit_once('/')
        .map(|(parent, _)| parent)
        .context("preview object GCS URI has no object name")
}

fn artifact_receipt(path: &Path) -> Result<ArtifactReceipt> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect preview artifact {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("preview artifact must be a non-empty regular file");
    }
    Ok(ArtifactReceipt {
        sha256: format!("sha256:{:x}", Sha256::digest(fs::read(path)?)),
        size_bytes: metadata.len(),
    })
}

fn copy_control(source: &Path, destination: &Path) -> Result<()> {
    let bytes = read_bounded(source, 4 * 1024 * 1024, "preview control document")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(destination)
        .with_context(|| format!("create {}", destination.display()))?
        .write_all(&bytes)?;
    Ok(())
}

fn create_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?
        .write_all(&bytes)?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("{label} must be a bounded non-empty regular file");
    }
    fs::read(path).with_context(|| format!("read {label}"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn required_file(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect fetched preview file {name}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("fetched preview file {name} is not a regular file");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcs_parent_rejects_traversal_and_accepts_one_immutable_prefix() {
        assert_eq!(
            gcs_parent("gs://thelve-release/releases/0.1.0/abc/bundle.tgz").unwrap(),
            "gs://thelve-release/releases/0.1.0/abc"
        );
        assert!(gcs_parent("gs://thelve-release/releases/../secret").is_err());
        assert!(gcs_parent("https://storage.googleapis.com/bucket/object").is_err());
    }
}
