# Cloud single-node operations

## GCP

Use an explicitly selected project, region, and zone. Prefer short-lived operator identity through `gcloud`, OS Login/IAP or the deployment's reviewed access path, GCP Secret Manager, encrypted/versioned remote state, least-privilege service accounts, provider logging, backups, and a static public address for SIP signaling. Expose only reviewed HTTPS/WSS, SIP, and bounded RTP ranges.

## AWS

Use an explicitly selected account/profile and region. Prefer IAM Identity Center, SSM rather than public SSH, AWS Secrets Manager, encrypted/versioned/locked state, instance roles, CloudWatch, backups, and an Elastic IP. Expose only reviewed HTTPS/WSS, SIP, and bounded RTP ranges.

## CLI order

`doctor` → `release verify` → `deploy init` → edit intent → `deploy bootstrap-state` → `deploy plan` → human approval → `deploy prepare --approve` → `secret set` for every declared secret → `deploy up --approve` → `deploy status`.

Use `pause`/`resume` for a test server. Before `destroy`, verify backup and DID-release requirements separately; infrastructure teardown does not release carrier resources by implication.
