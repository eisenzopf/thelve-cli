use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv4Addr,
    path::Path,
};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub const API_VERSION: &str = "thelve.io/v1alpha1";
pub const KIND: &str = "CloudSingleNode";

// Retrieved from Telnyx's machine-readable SIP signaling and media profile at
// https://sip.telnyx.com/voice.json on 2026-08-24. Keeping the retrieval date
// and revision in deployment intent makes the firewall input auditable and
// lets operators reject an old CLI profile.
const TELNYX_NETWORK_PROFILE_VERSION: &str = "telnyx-sip-network-2026-08-24-r2";
const TELNYX_US_SIGNALING_CIDRS: &[&str] = &["192.76.120.10/32", "64.16.250.10/32"];
const TELNYX_MEDIA_CIDRS: &[&str] = &[
    "36.255.198.128/25",
    "50.114.136.128/25",
    "50.114.144.0/21",
    "64.16.226.0/24",
    "64.16.227.0/24",
    "64.16.228.0/24",
    "64.16.229.0/24",
    "64.16.230.0/24",
    "64.16.248.0/24",
    "64.16.249.0/24",
    "103.115.244.128/25",
    "103.115.247.0/24",
    "185.246.41.128/25",
    "185.246.42.128/28",
];

pub const REQUIRED_SECRET_NAMES: &[&str] = &[
    "database-url",
    "migration-database-url",
    "realtime-callback-database-url",
    "realtime-internal-token",
    "control-api-service-token",
    "postgres-password",
    "redis-password",
    "keycloak-database-password",
    "minio-root-user",
    "minio-root-password",
    "oidc/client-secret",
    "backup/destination",
    "telnyx-api-key",
    "telnyx-public-key",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Gcp,
    Aws,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Gcp => "gcp",
            Self::Aws => "aws",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloudDeployment {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Spec,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Metadata {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Spec {
    pub provider: Provider,
    pub environment: Environment,
    pub compute_profile: String,
    pub host_image: String,
    pub state: State,
    pub networking: Networking,
    #[serde(default)]
    pub domains: BTreeMap<String, String>,
    pub max_concurrent_inbound_calls: u16,
    pub secret_names: Vec<String>,
    #[serde(default)]
    pub deletion_protection: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Test,
    Staging,
    Production,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Test => "test",
            Self::Staging => "staging",
            Self::Production => "production",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum Provider {
    #[serde(rename = "gcp")]
    Gcp {
        project_id: String,
        region: String,
        zone: String,
        #[serde(default)]
        admin_principals: Vec<String>,
        #[serde(default)]
        dns_managed_zone: String,
        #[serde(default)]
        ops_agent_package: Option<PinnedPackage>,
    },
    #[serde(rename = "aws")]
    Aws {
        region: String,
        availability_zone: String,
        #[serde(default)]
        route53_zone_id: String,
        #[serde(default)]
        cloudwatch_agent_package: Option<PinnedPackage>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PinnedPackage {
    pub url: String,
    pub sha256: String,
}

impl Provider {
    pub fn kind(&self) -> CloudProvider {
        match self {
            Self::Gcp { .. } => CloudProvider::Gcp,
            Self::Aws { .. } => CloudProvider::Aws,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct State {
    pub bucket: String,
    pub prefix: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Networking {
    pub telnyx_cidr_source_version: String,
    pub telnyx_signaling_cidrs: Vec<String>,
    pub telnyx_media_cidrs: Vec<String>,
    #[serde(default = "default_https_sources")]
    pub https_source_cidrs: Vec<String>,
    #[serde(default = "default_sip_port")]
    pub sip_port: u16,
    #[serde(default = "default_rtp_start")]
    pub rtp_port_start: u16,
    #[serde(default = "default_rtp_end")]
    pub rtp_port_end: u16,
    #[serde(default = "default_webrtc_start")]
    pub webrtc_port_start: u16,
    #[serde(default = "default_webrtc_end")]
    pub webrtc_port_end: u16,
    #[serde(default = "default_webrtc_media_cidrs")]
    pub webrtc_media_cidrs: Vec<String>,
}

impl CloudDeployment {
    pub fn template(
        provider: CloudProvider,
        name: String,
        project: Option<String>,
        region: String,
        zone: String,
    ) -> Result<Self> {
        let telnyx_profile = telnyx_network_profile(provider, &region);
        let provider = match provider {
            CloudProvider::Gcp => Provider::Gcp {
                project_id: project.context("--project is required for provider=gcp")?,
                region,
                zone,
                admin_principals: Vec::new(),
                dns_managed_zone: String::new(),
                ops_agent_package: None,
            },
            CloudProvider::Aws => Provider::Aws {
                region,
                availability_zone: zone,
                route53_zone_id: String::new(),
                cloudwatch_agent_package: None,
            },
        };
        Ok(Self {
            api_version: API_VERSION.into(),
            kind: KIND.into(),
            metadata: Metadata { name: name.clone() },
            spec: Spec {
                provider,
                environment: Environment::Test,
                compute_profile: "recommended_test".into(),
                host_image: "REPLACE_WITH_SIGNED_CATALOG_IMAGE".into(),
                state: State {
                    bucket: format!("REPLACE-{name}-state-bucket"),
                    prefix: format!("thelve/{name}/test"),
                },
                networking: Networking {
                    telnyx_cidr_source_version: telnyx_profile.as_ref().map_or_else(
                        || "REPLACE_WITH_CURRENT_SIGNED_NETWORK_PROFILE".into(),
                        |profile| profile.version.into(),
                    ),
                    telnyx_signaling_cidrs: telnyx_profile.as_ref().map_or_else(
                        || vec!["REPLACE_WITH_CURRENT_TELNYX_SIGNALING_CIDR".into()],
                        |profile| strings(profile.signaling_cidrs),
                    ),
                    telnyx_media_cidrs: telnyx_profile.map_or_else(
                        || vec!["REPLACE_WITH_CURRENT_TELNYX_MEDIA_CIDR".into()],
                        |profile| strings(profile.media_cidrs),
                    ),
                    https_source_cidrs: default_https_sources(),
                    sip_port: default_sip_port(),
                    rtp_port_start: default_rtp_start(),
                    rtp_port_end: default_rtp_end(),
                    webrtc_port_start: default_webrtc_start(),
                    webrtc_port_end: default_webrtc_end(),
                    webrtc_media_cidrs: default_webrtc_media_cidrs(),
                },
                domains: BTreeMap::new(),
                max_concurrent_inbound_calls: 2,
                secret_names: REQUIRED_SECRET_NAMES
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                deletion_protection: false,
            },
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.api_version != API_VERSION || self.kind != KIND {
            bail!(
                "unsupported deployment contract {}/{}",
                self.api_version,
                self.kind
            );
        }
        if !valid_name(&self.metadata.name) {
            bail!(
                "metadata.name must be 3-30 lowercase letters, digits, or hyphens and start with a letter"
            );
        }
        if self.spec.state.bucket.starts_with("REPLACE") || self.spec.state.bucket.len() < 3 {
            bail!("spec.state.bucket must name an existing or bootstrappable remote state bucket");
        }
        if self.spec.state.prefix.contains("..") || self.spec.state.prefix.starts_with('/') {
            bail!("spec.state.prefix must be a safe relative state prefix");
        }
        if !matches!(
            self.spec.compute_profile.as_str(),
            "budget_smoke" | "recommended_test" | "production_baseline" | "production_growth"
        ) {
            bail!("unknown computeProfile {:?}", self.spec.compute_profile);
        }
        let production_profile = matches!(
            self.spec.compute_profile.as_str(),
            "production_baseline" | "production_growth"
        );
        if self.spec.environment == Environment::Production && !production_profile {
            bail!("production requires production_baseline or production_growth");
        }
        if self.spec.max_concurrent_inbound_calls == 0
            || self.spec.max_concurrent_inbound_calls > 500
        {
            bail!("maxConcurrentInboundCalls must be between 1 and 500");
        }
        if self.spec.host_image.starts_with("REPLACE") {
            bail!("spec.hostImage must resolve from a verified machine-image catalog");
        }
        match &self.spec.provider {
            Provider::Gcp {
                project_id,
                zone,
                region,
                dns_managed_zone,
                ops_agent_package,
                ..
            } => {
                if project_id.is_empty()
                    || region.is_empty()
                    || !zone.starts_with(&format!("{region}-"))
                {
                    bail!("GCP projectId, region, and a zone within that region are required");
                }
                if !self.spec.host_image.starts_with("projects/")
                    || !self.spec.host_image.contains("/global/images/")
                    || self.spec.host_image.contains("/families/")
                {
                    bail!(
                        "GCP hostImage must be an exact projects/.../global/images/... identifier"
                    );
                }
                validate_dns(dns_managed_zone, &self.spec.domains, "dnsManagedZone")?;
                validate_pinned_package(ops_agent_package.as_ref(), "opsAgentPackage")?;
            }
            Provider::Aws {
                region,
                availability_zone,
                route53_zone_id,
                cloudwatch_agent_package,
            } => {
                if region.is_empty() || !valid_aws_zone(region, availability_zone) {
                    bail!("AWS region and an availabilityZone within that region are required");
                }
                let ami = self.spec.host_image.as_bytes();
                if !self.spec.host_image.starts_with("ami-")
                    || !(12..=21).contains(&ami.len())
                    || !ami[4..].iter().all(u8::is_ascii_hexdigit)
                {
                    bail!("AWS hostImage must be an exact AMI ID");
                }
                validate_dns(route53_zone_id, &self.spec.domains, "route53ZoneId")?;
                validate_pinned_package(
                    cloudwatch_agent_package.as_ref(),
                    "cloudwatchAgentPackage",
                )?;
            }
        }
        validate_networking(&self.spec.networking)?;
        for required in REQUIRED_SECRET_NAMES {
            if !self
                .spec
                .secret_names
                .iter()
                .any(|candidate| candidate == required)
            {
                bail!("spec.secretNames is missing required logical secret {required:?}");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TelnyxNetworkProfile {
    version: &'static str,
    signaling_cidrs: &'static [&'static str],
    media_cidrs: &'static [&'static str],
}

fn telnyx_network_profile(provider: CloudProvider, region: &str) -> Option<TelnyxNetworkProfile> {
    let is_us_region = match provider {
        CloudProvider::Gcp => region.starts_with("us-"),
        CloudProvider::Aws => region.starts_with("us-"),
    };
    is_us_region.then_some(TelnyxNetworkProfile {
        version: TELNYX_NETWORK_PROFILE_VERSION,
        signaling_cidrs: TELNYX_US_SIGNALING_CIDRS,
        media_cidrs: TELNYX_MEDIA_CIDRS,
    })
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn validate_dns(zone: &str, domains: &BTreeMap<String, String>, field: &str) -> Result<()> {
    if zone.is_empty() {
        return Ok(());
    }
    for required in ["app", "api", "media", "sip"] {
        if domains.get(required).is_none_or(String::is_empty) {
            bail!("spec.provider.{field} requires a non-empty spec.domains.{required}");
        }
    }
    Ok(())
}

fn valid_aws_zone(region: &str, zone: &str) -> bool {
    let Some(suffix) = zone.strip_prefix(region) else {
        return false;
    };
    (suffix.len() == 1 && suffix.as_bytes()[0].is_ascii_lowercase())
        || (suffix.starts_with('-')
            && suffix.len() > 1
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
}

fn validate_pinned_package(package: Option<&PinnedPackage>, field: &str) -> Result<()> {
    let Some(package) = package else {
        return Ok(());
    };
    if !package.url.starts_with("https://")
        || package.url.contains([' ', '\n', '\r'])
        || package.sha256.len() != 64
        || !package
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("spec.provider.{field} requires an HTTPS URL and lowercase SHA-256");
    }
    Ok(())
}

fn validate_networking(networking: &Networking) -> Result<()> {
    if networking.telnyx_cidr_source_version.starts_with("REPLACE")
        || networking.telnyx_cidr_source_version.len() < 8
    {
        bail!("a current, auditable Telnyx CIDR source version is required");
    }
    for (label, cidrs) in [
        ("signaling", &networking.telnyx_signaling_cidrs),
        ("media", &networking.telnyx_media_cidrs),
    ] {
        if cidrs.is_empty()
            || cidrs
                .iter()
                .any(|cidr| cidr.starts_with("REPLACE") || cidr == "0.0.0.0/0")
        {
            bail!("Telnyx {label} CIDRs must be explicit, current, and may not include 0.0.0.0/0");
        }
    }
    if networking.rtp_port_start != 16384 || networking.rtp_port_end != 32768 {
        bail!("the managed Telnyx SIP profile requires RTP 16384-32768");
    }
    let webrtc_width = u32::from(networking.webrtc_port_end)
        .checked_sub(u32::from(networking.webrtc_port_start))
        .map(|width| width + 1);
    if networking.webrtc_port_start <= networking.rtp_port_end
        || !webrtc_width.is_some_and(|width| (16..=16_384).contains(&width))
    {
        bail!("browser media requires a separate bounded WebRTC UDP range");
    }
    let unique_webrtc_cidrs = networking
        .webrtc_media_cidrs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if networking.webrtc_media_cidrs.is_empty()
        || unique_webrtc_cidrs.len() != networking.webrtc_media_cidrs.len()
        || networking
            .webrtc_media_cidrs
            .iter()
            .any(|cidr| !valid_ipv4_cidr(cidr))
    {
        bail!("WebRTC media CIDRs must be canonical IPv4 networks");
    }
    Ok(())
}

fn valid_ipv4_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    u32::from(address) & mask == u32::from(address)
}

fn valid_name(name: &str) -> bool {
    (3..=30).contains(&name.len())
        && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && name
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !name.ends_with('-')
}

fn default_https_sources() -> Vec<String> {
    vec!["0.0.0.0/0".into()]
}
const fn default_sip_port() -> u16 {
    5060
}
const fn default_rtp_start() -> u16 {
    16384
}
const fn default_rtp_end() -> u16 {
    32768
}
const fn default_webrtc_start() -> u16 {
    49152
}
const fn default_webrtc_end() -> u16 {
    50175
}
fn default_webrtc_media_cidrs() -> Vec<String> {
    vec!["0.0.0.0/0".into()]
}

pub fn load(path: &Path) -> Result<CloudDeployment> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let intent: CloudDeployment = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("parse strict deployment intent {}", path.display()))?;
    intent.validate()?;
    Ok(intent)
}

pub fn write_new(path: &Path, intent: &CloudDeployment) -> Result<()> {
    if path.exists() {
        bail!("refusing to overwrite existing {}", path.display());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let bytes = serde_yaml::to_string(intent).context("serialize deployment intent")?;
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn template_is_intentionally_not_deployable_until_reviewed() {
        let template = CloudDeployment::template(
            CloudProvider::Gcp,
            "thelve-test".into(),
            Some("example-project".into()),
            "us-west1".into(),
            "us-west1-b".into(),
        )
        .unwrap();
        assert!(
            template
                .validate()
                .unwrap_err()
                .to_string()
                .contains("state.bucket")
        );
    }

    #[test]
    fn us_template_embeds_the_auditable_telnyx_network_profile() {
        let template = CloudDeployment::template(
            CloudProvider::Gcp,
            "thelve-test".into(),
            Some("example-project".into()),
            "us-west1".into(),
            "us-west1-b".into(),
        )
        .unwrap();
        assert_eq!(
            template.spec.networking.telnyx_cidr_source_version,
            TELNYX_NETWORK_PROFILE_VERSION
        );
        assert_eq!(
            template.spec.networking.telnyx_signaling_cidrs,
            strings(TELNYX_US_SIGNALING_CIDRS)
        );
        assert_eq!(
            template.spec.networking.telnyx_media_cidrs,
            strings(TELNYX_MEDIA_CIDRS)
        );
        assert_eq!(template.spec.networking.webrtc_port_start, 49_152);
        assert_eq!(template.spec.networking.webrtc_port_end, 50_175);
        assert_eq!(
            template.spec.networking.webrtc_media_cidrs,
            vec!["0.0.0.0/0"]
        );
    }

    #[test]
    fn unsupported_region_keeps_telnyx_networking_fail_closed() {
        let template = CloudDeployment::template(
            CloudProvider::Gcp,
            "thelve-test".into(),
            Some("example-project".into()),
            "asia-southeast1".into(),
            "asia-southeast1-b".into(),
        )
        .unwrap();
        assert!(
            template
                .spec
                .networking
                .telnyx_cidr_source_version
                .starts_with("REPLACE")
        );
        assert!(template.validate().is_err());
    }

    #[test]
    fn rejects_open_carrier_perimeter() {
        let mut template = deployable(CloudProvider::Aws);
        template.spec.networking.telnyx_media_cidrs = vec!["0.0.0.0/0".into()];
        assert!(
            template
                .validate()
                .unwrap_err()
                .to_string()
                .contains("media")
        );
    }

    #[test]
    fn rejects_overlapping_or_noncanonical_browser_media_networking() {
        let mut template = deployable(CloudProvider::Gcp);
        template.spec.networking.webrtc_port_start = 32_000;
        template.spec.networking.webrtc_port_end = 33_000;
        assert!(template.validate().is_err());

        let mut template = deployable(CloudProvider::Gcp);
        template.spec.networking.webrtc_media_cidrs = vec!["203.0.113.1/24".into()];
        assert!(template.validate().is_err());
    }

    #[test]
    fn managed_dns_requires_all_public_endpoints() {
        let mut intent = deployable(CloudProvider::Gcp);
        let Provider::Gcp {
            dns_managed_zone, ..
        } = &mut intent.spec.provider
        else {
            unreachable!();
        };
        *dns_managed_zone = "thelve-zone".into();
        assert!(
            intent
                .validate()
                .unwrap_err()
                .to_string()
                .contains("domains.app")
        );

        intent.spec.domains = [
            ("app".into(), "app.example.com".into()),
            ("api".into(), "api.example.com".into()),
            ("media".into(), "media.example.com".into()),
            ("sip".into(), "sip.example.com".into()),
        ]
        .into_iter()
        .collect();
        intent.validate().unwrap();
    }

    #[test]
    fn aws_zone_accepts_standard_and_local_zone_forms_only() {
        let standard = deployable(CloudProvider::Aws);
        standard.validate().unwrap();
        let mut invalid = standard.clone();
        if let Provider::Aws {
            availability_zone, ..
        } = &mut invalid.spec.provider
        {
            *availability_zone = "us-west-20a".into();
        }
        assert!(invalid.validate().is_err());
        if let Provider::Aws {
            availability_zone, ..
        } = &mut invalid.spec.provider
        {
            *availability_zone = "us-west-2-lax-1a".into();
        }
        invalid.validate().unwrap();
    }

    #[test]
    fn native_log_adapters_require_immutable_package_inputs() {
        let mut intent = deployable(CloudProvider::Gcp);
        if let Provider::Gcp {
            ops_agent_package, ..
        } = &mut intent.spec.provider
        {
            *ops_agent_package = Some(PinnedPackage {
                url: "https://packages.example.com/google-cloud-ops-agent.deb".into(),
                sha256: "a".repeat(64),
            });
        }
        intent.validate().unwrap();
        if let Provider::Gcp {
            ops_agent_package: Some(package),
            ..
        } = &mut intent.spec.provider
        {
            package.url = "http://mutable.example.com/agent.deb".into();
        }
        assert!(intent.validate().is_err());
    }

    pub(crate) fn deployable(provider: CloudProvider) -> CloudDeployment {
        let mut value = CloudDeployment::template(
            provider,
            "thelve-test".into(),
            Some("example-project".into()),
            "us-west-2".into(),
            "us-west-2a".into(),
        )
        .unwrap();
        value.spec.state.bucket = "thelve-test-state-123".into();
        value.spec.networking.telnyx_cidr_source_version = "signed-2026-08-23".into();
        value.spec.networking.telnyx_signaling_cidrs = vec!["192.0.2.0/24".into()];
        value.spec.networking.telnyx_media_cidrs = vec!["198.51.100.0/24".into()];
        value.spec.host_image = match provider {
            CloudProvider::Gcp => "projects/thelve-images/global/images/thelve-20260823".into(),
            CloudProvider::Aws => "ami-0123456789abcdef0".into(),
        };
        if provider == CloudProvider::Gcp {
            value.spec.provider = Provider::Gcp {
                project_id: "example-project".into(),
                region: "us-west1".into(),
                zone: "us-west1-b".into(),
                admin_principals: vec![],
                dns_managed_zone: String::new(),
                ops_agent_package: None,
            };
        }
        value
    }
}
