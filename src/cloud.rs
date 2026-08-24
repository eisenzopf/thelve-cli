use std::{thread, time::Duration};

use anyhow::{Context, Result, bail};

use crate::{
    config::{CloudDeployment, CloudProvider, Provider},
    process::{self, CommandPlan},
    terraform,
};

const GCP_DEPLOYMENT_SERVICES: &[&str] = &[
    "artifactregistry.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iap.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "osconfig.googleapis.com",
    "secretmanager.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
];

/// Create the customer-owned GCP project boundary used by a single-node
/// deployment. This operation deliberately does not change the operator's
/// active gcloud project and creates no VM, address, registry, secret value,
/// DNS record, or storage bucket.
pub fn bootstrap_gcp_project(
    project: &str,
    organization: &str,
    billing_account: &str,
    region: &str,
    monthly_budget_usd: u32,
) -> Result<()> {
    validate_project_bootstrap(
        project,
        organization,
        billing_account,
        region,
        monthly_budget_usd,
    )?;
    process::capture(&CommandPlan::new("gcloud").arg("--version"))
        .context("gcloud CLI is required")?;
    let active = process::capture(&CommandPlan::new("gcloud").args([
        "auth",
        "list",
        "--filter=status:ACTIVE",
        "--format=value(account)",
    ]))?;
    if active.trim().is_empty() {
        bail!("gcloud has no active identity; run gcloud auth login first");
    }

    let describe = CommandPlan::new("gcloud").args([
        "projects",
        "describe",
        project,
        "--format=json(projectId,parent)",
    ]);
    if let Ok(existing) = process::capture(&describe) {
        let value: serde_json::Value = serde_json::from_str(&existing)?;
        let parent_type = value
            .pointer("/parent/type")
            .and_then(serde_json::Value::as_str);
        let parent_id = value
            .pointer("/parent/id")
            .and_then(serde_json::Value::as_str);
        if parent_type != Some("organization") || parent_id != Some(organization) {
            bail!("existing project is outside the requested organization");
        }
    } else {
        process::inherit(&CommandPlan::new("gcloud").args([
            "projects",
            "create",
            project,
            "--organization",
            organization,
            "--name",
            "Thelve Preview",
            "--labels",
            "application=thelve,environment=preview,managed_by=thelve_cli",
            "--quiet",
        ]))?;
    }

    retry_provider_operation(|| {
        process::inherit(&CommandPlan::new("gcloud").args([
            "billing",
            "projects",
            "link",
            project,
            "--billing-account",
            billing_account,
            "--quiet",
        ]))
    })
    .context("link the new project to the selected billing account")?;

    let mut enable_args = vec!["services".to_owned(), "enable".to_owned()];
    enable_args.extend(
        GCP_DEPLOYMENT_SERVICES
            .iter()
            .map(|service| (*service).to_owned()),
    );
    enable_args.extend([
        "--project".to_owned(),
        project.to_owned(),
        "--quiet".to_owned(),
    ]);
    retry_provider_operation(|| {
        process::inherit(&CommandPlan::new("gcloud").args(enable_args.clone()))
    })
    .context("enable the bounded GCP deployment API set")?;

    ensure_project_budget(project, billing_account, monthly_budget_usd)?;
    println!(
        "GCP project {project} is isolated, billing-linked, budgeted at ${monthly_budget_usd}/month, and deployment APIs are enabled"
    );
    println!(
        "no VM, address, registry, bucket, DNS record, secret value, or Thelve workload was created"
    );
    println!("suggested deployment region: {region}");
    Ok(())
}

fn ensure_project_budget(project: &str, billing_account: &str, amount: u32) -> Result<()> {
    let display_name = format!("Thelve preview — {project}");
    let existing = process::capture(&CommandPlan::new("gcloud").args([
        "billing",
        "budgets",
        "list",
        "--billing-project",
        project,
        "--billing-account",
        billing_account,
        "--filter",
        &format!("displayName={display_name}"),
        "--format=value(name)",
    ]))?;
    if existing.trim().is_empty() {
        process::inherit(&CommandPlan::new("gcloud").args([
            "billing",
            "budgets",
            "create",
            "--billing-project",
            project,
            "--billing-account",
            billing_account,
            "--display-name",
            &display_name,
            "--budget-amount",
            &format!("{amount}USD"),
            "--filter-projects",
            &format!("projects/{project}"),
            "--calendar-period",
            "month",
            "--threshold-rule",
            "percent=0.50",
            "--threshold-rule",
            "percent=0.90",
            "--threshold-rule",
            "percent=1.00",
            "--quiet",
        ]))?;
    }
    Ok(())
}

fn retry_provider_operation(mut operation: impl FnMut() -> Result<()>) -> Result<()> {
    let mut last_error = None;
    for attempt in 0..4 {
        match operation() {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt < 3 {
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }
    Err(last_error.expect("at least one provider operation was attempted"))
}

fn validate_project_bootstrap(
    project: &str,
    organization: &str,
    billing_account: &str,
    region: &str,
    monthly_budget_usd: u32,
) -> Result<()> {
    let valid_project = (6..=30).contains(&project.len())
        && project
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        && project
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && project
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid_project {
        bail!("project must be a 6-30 character lowercase GCP project ID");
    }
    if organization.is_empty() || !organization.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("organization must be a numeric GCP organization ID");
    }
    let billing_parts = billing_account.split('-').collect::<Vec<_>>();
    if billing_parts.len() != 3
        || billing_parts
            .iter()
            .any(|part| part.len() != 6 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        bail!("billing-account must be an exact XXXXXX-XXXXXX-XXXXXX ID");
    }
    if region.len() < 4
        || region.len() > 32
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("region must be a canonical GCP region name");
    }
    if !(5..=10_000).contains(&monthly_budget_usd) {
        bail!("monthly-budget-usd must be between 5 and 10000");
    }
    Ok(())
}

pub fn doctor(
    provider: CloudProvider,
    project: Option<String>,
    region: Option<String>,
) -> Result<()> {
    let iac = terraform::iac_binary()?;
    let iac_version = process::capture(&CommandPlan::new(&iac).arg("version"))?;
    println!(
        "ok: IaC runner {}",
        iac_version.lines().next().unwrap_or("version available")
    );

    match provider {
        CloudProvider::Gcp => {
            let project = project.context("--project is required for provider=gcp")?;
            process::capture(&CommandPlan::new("gcloud").arg("--version"))
                .context("gcloud CLI is required")?;
            let account = process::capture(&CommandPlan::new("gcloud").args([
                "auth",
                "list",
                "--filter=status:ACTIVE",
                "--format=value(account)",
            ]))?;
            if account.trim().is_empty() {
                bail!(
                    "gcloud has no active identity; run gcloud auth login and application-default login"
                );
            }
            process::capture(&CommandPlan::new("gcloud").args([
                "projects",
                "describe",
                &project,
                "--format=value(projectId)",
            ]))?;
            println!(
                "ok: active gcloud identity {} can describe project {project}",
                account.trim()
            );
        }
        CloudProvider::Aws => {
            let region = region.context("--region is required for provider=aws")?;
            process::capture(&CommandPlan::new("aws").arg("--version"))
                .context("AWS CLI is required")?;
            let identity = process::capture(&CommandPlan::new("aws").args([
                "sts",
                "get-caller-identity",
                "--region",
                &region,
                "--output",
                "json",
            ]))?;
            let value: serde_json::Value = serde_json::from_str(&identity)?;
            let arn = value
                .get("Arn")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown identity");
            println!("ok: AWS identity {arn} in region {region}");
        }
    }
    println!("doctor passed; no cloud resources were changed");
    Ok(())
}

pub fn bootstrap_state(intent: &CloudDeployment) -> Result<()> {
    match &intent.spec.provider {
        Provider::Gcp {
            project_id, region, ..
        } => bootstrap_gcp_state(&intent.spec.state.bucket, project_id, region),
        Provider::Aws { region, .. } => bootstrap_aws_state(&intent.spec.state.bucket, region),
    }
}

fn bootstrap_gcp_state(bucket: &str, project: &str, region: &str) -> Result<()> {
    let url = format!("gs://{bucket}");
    let describe = CommandPlan::new("gcloud").args([
        "storage",
        "buckets",
        "describe",
        &url,
        "--project",
        project,
    ]);
    if process::capture(&describe).is_err() {
        process::inherit(&CommandPlan::new("gcloud").args([
            "storage",
            "buckets",
            "create",
            &url,
            "--project",
            project,
            "--location",
            region,
            "--uniform-bucket-level-access",
            "--public-access-prevention",
        ]))?;
    }
    process::inherit(&CommandPlan::new("gcloud").args([
        "storage",
        "buckets",
        "update",
        &url,
        "--project",
        project,
        "--versioning",
        "--public-access-prevention",
    ]))?;
    println!(
        "remote GCS state bucket is present, versioned, and public access is prevented: {url}"
    );
    Ok(())
}

fn bootstrap_aws_state(bucket: &str, region: &str) -> Result<()> {
    let head = CommandPlan::new("aws").args([
        "s3api",
        "head-bucket",
        "--bucket",
        bucket,
        "--region",
        region,
    ]);
    if process::capture(&head).is_err() {
        let mut plan = CommandPlan::new("aws").args([
            "s3api",
            "create-bucket",
            "--bucket",
            bucket,
            "--region",
            region,
        ]);
        if region != "us-east-1" {
            plan = plan.args([
                "--create-bucket-configuration",
                &format!("LocationConstraint={region}"),
            ]);
        }
        process::inherit(&plan)?;
    }
    process::inherit(&CommandPlan::new("aws").args([
        "s3api",
        "put-bucket-versioning",
        "--bucket",
        bucket,
        "--region",
        region,
        "--versioning-configuration",
        "Status=Enabled",
    ]))?;
    process::inherit(&CommandPlan::new("aws").args([
        "s3api", "put-public-access-block", "--bucket", bucket, "--region", region,
        "--public-access-block-configuration",
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    ]))?;
    process::inherit(&CommandPlan::new("aws").args([
        "s3api", "put-bucket-encryption", "--bucket", bucket, "--region", region,
        "--server-side-encryption-configuration",
        "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"},\"BucketKeyEnabled\":true}]}",
    ]))?;
    println!(
        "remote S3 state bucket is present, encrypted, versioned, and blocked from public access: {bucket}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_bootstrap_inputs_are_bounded() {
        assert!(
            validate_project_bootstrap(
                "thelve-preview-1234",
                "700093650283",
                "01B432-10E5BF-9E884E",
                "us-west1",
                50,
            )
            .is_ok()
        );
        assert!(
            validate_project_bootstrap(
                "zerosegfaults",
                "organizations/700093650283",
                "01B432-10E5BF-9E884E",
                "us-west1",
                50,
            )
            .is_err()
        );
        assert!(
            validate_project_bootstrap(
                "thelve-preview-1234",
                "700093650283",
                "01B432-10E5BF-9E884E",
                "us-west1;unexpected",
                50,
            )
            .is_err()
        );
        assert!(
            validate_project_bootstrap(
                "thelve-preview-1234",
                "700093650283",
                "01B432-10E5BF-9E884E",
                "us-west1",
                0,
            )
            .is_err()
        );
    }
}
