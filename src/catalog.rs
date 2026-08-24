use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::ValueEnum;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_CATALOG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 1024 * 1024;
const MAX_TRUST_ROOT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CatalogKind {
    Release,
    MachineImage,
    Channel,
    PreviewRelease,
}

#[derive(Debug)]
pub struct VerificationReceipt {
    pub schema_version: String,
    pub digest: String,
    pub trust_root_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignatureEnvelope {
    schema_version: String,
    algorithm: String,
    key_id: String,
    document_sha256: String,
    signature_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustRoot {
    schema_version: String,
    keys: Vec<TrustedKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedKey {
    key_id: String,
    algorithm: String,
    public_key_base64: String,
    status: KeyStatus,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum KeyStatus {
    Active,
    Revoked,
}

pub fn verify(
    document_path: &Path,
    signature_path: &Path,
    trust_root_path: &Path,
    expected_trust_root_sha256: &str,
    kind: CatalogKind,
) -> Result<VerificationReceipt> {
    let document = read_regular_bounded(document_path, MAX_CATALOG_BYTES, "catalog")?;
    let envelope_bytes =
        read_regular_bounded(signature_path, MAX_SIGNATURE_BYTES, "signature envelope")?;
    let envelope_value: serde_json::Value =
        serde_json::from_slice(&envelope_bytes).context("parse detached signature envelope")?;
    validate_against(
        &envelope_value,
        include_bytes!("../contracts/thelve-detached-signature-v1.schema.json"),
        "detached signature",
    )?;
    let envelope: SignatureEnvelope = serde_json::from_value(envelope_value)?;

    let trust_bytes = read_regular_bounded(trust_root_path, MAX_TRUST_ROOT_BYTES, "trust root")?;
    let trust_root_digest = format!("sha256:{:x}", Sha256::digest(&trust_bytes));
    if expected_trust_root_sha256 != trust_root_digest {
        bail!(
            "trust-root digest mismatch: expected {expected_trust_root_sha256}, calculated {trust_root_digest}"
        );
    }
    let trust_value: serde_json::Value =
        serde_json::from_slice(&trust_bytes).context("parse trust root")?;
    validate_against(
        &trust_value,
        include_bytes!("../contracts/thelve-trust-root-v1.schema.json"),
        "trust root",
    )?;
    let trust: TrustRoot = serde_json::from_value(trust_value)?;

    if envelope.schema_version != "thelve.detached-signature/v1"
        || trust.schema_version != "thelve.trust-root/v1"
        || envelope.algorithm != "ed25519"
    {
        bail!("unsupported trust or signature contract");
    }

    let digest = format!("sha256:{:x}", Sha256::digest(&document));
    if digest != envelope.document_sha256 {
        bail!(
            "catalog digest mismatch: expected {}, calculated {digest}",
            envelope.document_sha256
        );
    }

    let key = trust
        .keys
        .iter()
        .find(|key| key.key_id == envelope.key_id)
        .context("signature key is not present in the trust root")?;
    if key.status != KeyStatus::Active || key.algorithm != "ed25519" {
        bail!("signature key is revoked or uses an unsupported algorithm");
    }
    let public_key: [u8; 32] = STANDARD
        .decode(&key.public_key_base64)
        .context("decode trusted public key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
    let signature_bytes: [u8; 64] = STANDARD
        .decode(&envelope.signature_base64)
        .context("decode detached signature")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must be 64 bytes"))?;
    VerifyingKey::from_bytes(&public_key)
        .context("parse Ed25519 public key")?
        .verify(&document, &Signature::from_bytes(&signature_bytes))
        .context("verify catalog signature")?;

    let value: serde_json::Value =
        serde_json::from_slice(&document).context("catalog is not JSON")?;
    let schema_version = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        .context("catalog is missing schemaVersion")?;
    let admitted = match kind {
        CatalogKind::Release => schema_version.starts_with("thelve.product-release/"),
        CatalogKind::MachineImage => schema_version.starts_with("thelve.machine-image-catalog/"),
        CatalogKind::Channel => schema_version.starts_with("thelve.release-channel/"),
        CatalogKind::PreviewRelease => schema_version == "thelve.gcp-preview-release/v1",
    };
    if !admitted {
        bail!("catalog schemaVersion {schema_version:?} does not match requested kind");
    }
    validate_schema(&value, kind)?;
    Ok(VerificationReceipt {
        schema_version: schema_version.into(),
        digest,
        trust_root_digest,
    })
}

fn read_regular_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("{label} must be a bounded non-empty regular file");
    }
    fs::read(path).with_context(|| format!("read {label} {}", path.display()))
}

fn validate_schema(document: &serde_json::Value, kind: CatalogKind) -> Result<()> {
    let schema_bytes = match kind {
        CatalogKind::Release => {
            include_bytes!("../contracts/thelve-product-release-v1.schema.json").as_slice()
        }
        CatalogKind::MachineImage => {
            include_bytes!("../contracts/thelve-machine-image-catalog-v1.schema.json").as_slice()
        }
        CatalogKind::Channel => {
            include_bytes!("../contracts/thelve-release-channel-v1.schema.json").as_slice()
        }
        CatalogKind::PreviewRelease => {
            include_bytes!("../contracts/thelve-gcp-preview-release-v1.schema.json").as_slice()
        }
    };
    validate_against(document, schema_bytes, "signed catalog")
}

pub(crate) fn validate_against(
    document: &serde_json::Value,
    schema_bytes: &[u8],
    label: &str,
) -> Result<()> {
    let schema: serde_json::Value = serde_json::from_slice(schema_bytes)
        .with_context(|| format!("embedded {label} schema is invalid"))?;
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .with_context(|| format!("compile embedded {label} schema"))?;
    if !validator.is_valid(document) {
        bail!("{label} does not satisfy its embedded schema");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn verifies_exact_signed_bytes_and_rejects_tampering() {
        let directory = tempdir().unwrap();
        let document = include_bytes!("../contracts/product-release.example.json");
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let signature = signing.sign(document);
        let digest = format!("sha256:{:x}", Sha256::digest(document));
        let envelope = serde_json::json!({
            "schemaVersion": "thelve.detached-signature/v1",
            "algorithm": "ed25519",
            "keyId": "test-release-key",
            "documentSha256": digest,
            "signatureBase64": STANDARD.encode(signature.to_bytes())
        });
        let root = serde_json::json!({
            "schemaVersion": "thelve.trust-root/v1",
            "keys": [{
                "keyId": "test-release-key",
                "algorithm": "ed25519",
                "publicKeyBase64": STANDARD.encode(signing.verifying_key().to_bytes()),
                "status": "active"
            }]
        });
        let document_path = directory.path().join("release.json");
        let signature_path = directory.path().join("release.sig.json");
        let root_path = directory.path().join("trust.json");
        fs::write(&document_path, document).unwrap();
        fs::write(&signature_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let root_bytes = serde_json::to_vec(&root).unwrap();
        let root_digest = format!("sha256:{:x}", Sha256::digest(&root_bytes));
        fs::write(&root_path, &root_bytes).unwrap();

        verify(
            &document_path,
            &signature_path,
            &root_path,
            &root_digest,
            CatalogKind::Release,
        )
        .unwrap();
        assert!(
            verify(
                &document_path,
                &signature_path,
                &root_path,
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                CatalogKind::Release
            )
            .is_err()
        );
        fs::write(&document_path, b"{}").unwrap();
        assert!(
            verify(
                &document_path,
                &signature_path,
                &root_path,
                &root_digest,
                CatalogKind::Release
            )
            .is_err()
        );
    }

    #[test]
    fn compatibility_manifest_hashes_every_embedded_contract() {
        let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../contracts/cloud-delivery-compatibility-v1.json"
        ))
        .unwrap();
        let contracts = manifest.get("contracts").unwrap();
        for (name, bytes) in [
            (
                "singleNodeComputeProfiles",
                include_bytes!("../contracts/single-node-compute-profiles-v1.json").as_slice(),
            ),
            (
                "productRelease",
                include_bytes!("../contracts/thelve-product-release-v1.schema.json").as_slice(),
            ),
            (
                "machineImageCatalog",
                include_bytes!("../contracts/thelve-machine-image-catalog-v1.schema.json")
                    .as_slice(),
            ),
            (
                "detachedSignature",
                include_bytes!("../contracts/thelve-detached-signature-v1.schema.json").as_slice(),
            ),
            (
                "trustRoot",
                include_bytes!("../contracts/thelve-trust-root-v1.schema.json").as_slice(),
            ),
            (
                "releaseChannel",
                include_bytes!("../contracts/thelve-release-channel-v1.schema.json").as_slice(),
            ),
        ] {
            let expected = contracts[name]["sha256"].as_str().unwrap();
            assert_eq!(expected, format!("sha256:{:x}", Sha256::digest(bytes)));
        }

        let declared_secrets: Vec<&str> = manifest["compatibility"]["requiredRuntimeSecrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(declared_secrets, crate::config::REQUIRED_SECRET_NAMES);
    }
}
