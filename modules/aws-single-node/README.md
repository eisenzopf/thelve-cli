# AWS single-node Thelve

This standalone root deploys one direct-media EC2 instance. It is not an EKS
module and does not change the portable Thelve application contract. Telnyx
SIP/RTP terminates directly on an Elastic IP; HTTPS and browser WSS terminate
at Caddy on the same host.

Security defaults include an encrypted gp3 volume, ENA, detailed monitoring,
IMDSv2-only metadata with hop limit one, SSM Session Manager, no public SSH,
exact Telnyx security-group ranges, exact-secret `GetSecretValue` permission,
blocked-public secret policies, and a private/versioned backup bucket.
Terraform creates Secrets Manager containers but never secret values or
versions. The startup path requires the qualification executable baked by
`thelve-image-factory` and never installs or upgrades Docker from a mutable
package repository. Optional CloudWatch installation accepts only a pinned
package URL and SHA-256.

`compute_profile` is the only sizing input. The module reads the shared
[compute profile catalog](../../../contracts/deployment/single-node-compute-profiles-v1.json)
and resolves it as follows:

| Profile | EC2 type | vCPU | RAM | Admitted use |
|---|---:|---:|---:|---|
| `budget_smoke` | `t3.large` | 2 | 8 GiB | Short smoke/evaluation work |
| `recommended_test` | `t3.xlarge` | 4 | 16 GiB | Telnyx and browser-agent test cluster |
| `production_baseline` | `m7i.xlarge` | 4 | 16 GiB | Initial measured production |
| `production_growth` | `m7i.2xlarge` | 8 | 32 GiB | Vertical production growth |

`environment = "production"` refuses either burstable T3-backed test profile.
Instance-type overrides are intentionally absent so a named profile cannot
drift from the desired-state and host-preflight contract.

Use an encrypted/versioned S3 Terraform backend with locking:

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config=bucket=YOUR_TF_STATE_BUCKET -backend-config=key=thelve/single-node/test.tfstate -backend-config=region=us-west-2 -backend-config=use_lockfile=true -backend-config=encrypt=true
terraform fmt -check
terraform validate
terraform plan
terraform apply
terraform output -json compute_profile
terraform output -json node_config_fragment
```

The non-secret startup script installs Docker Compose v2, nftables, chrony,
and optionally the pinned CloudWatch Agent. It does not install or activate a
Thelve release. Transfer the signed release through Session Manager, inspect
`thelve-node plan`, and run the explicit install/start ceremony.

Use `compute_profile = "recommended_test"` for the first public Telnyx
rehearsal. Set `instance_state = "stopped"` to pause compute charges while retaining the
Elastic IP, encrypted EBS volume, secrets, and backup bucket.
