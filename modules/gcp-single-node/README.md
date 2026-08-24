# GCP single-node Thelve

This standalone root deploys one direct-media Compute Engine VM. It is not a
GKE module and it does not change the portable Thelve application contract.
Telnyx SIP/RTP terminates on the VM's Premium-tier static IPv4 address; HTTPS
and WSS terminate at Caddy on the same host.

Security defaults include Shielded VM, Secure Boot, gVNIC, OS Login, optional
IAP-only SSH, exact Telnyx firewall ranges, a dedicated service account,
resource-level Secret Manager access, a versioned/private backup bucket, and
optional checksum-pinned Google Ops Agent export. Terraform creates secret
containers but no secret versions or values. The startup path requires the
qualification executable baked by `thelve-image-factory` and never installs or
upgrades Docker from a mutable package repository. Populate secret versions
through a separate authorized rotation workflow.

`compute_profile` is the only sizing input. The module reads the shared
[compute profile catalog](../../../contracts/deployment/single-node-compute-profiles-v1.json)
and resolves it as follows:

| Profile | Compute Engine type | vCPU | RAM | Admitted use |
|---|---:|---:|---:|---|
| `budget_smoke` | `e2-standard-2` | 2 | 8 GiB | Short smoke/evaluation work |
| `recommended_test` | `e2-standard-4` | 4 | 16 GiB | Telnyx and browser-agent test cluster |
| `production_baseline` | `n2-standard-4` | 4 | 16 GiB | Initial measured production |
| `production_growth` | `n2-standard-8` | 8 | 32 GiB | Vertical production growth |

`environment = "production"` refuses either E2-backed test profile. Machine
type overrides are intentionally absent so a named profile cannot drift from
the desired-state and host-preflight contract.

Use a restricted, versioned GCS Terraform backend:

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config=bucket=YOUR_TF_STATE_BUCKET -backend-config=prefix=thelve/single-node/test
terraform fmt -check
terraform validate
terraform plan
terraform apply
terraform output -json compute_profile
terraform output -json node_config_fragment
```

The non-secret startup script installs Docker Compose v2, nftables, chrony,
and (when enabled) the Ops Agent. It does not download, install, or start a
Thelve release. Transfer the signed bundle and safe node configuration through
IAP/OS Login, run `thelve-node plan`, then perform the explicit install/start
ceremony.

Use `compute_profile = "recommended_test"` for the first public Telnyx
rehearsal. To pause a test deployment, set `instance_status = "TERMINATED"` and apply.
The reserved address, disk, secret containers, and backup bucket continue to
incur their small storage/address charges until destroyed.
