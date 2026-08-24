# Thelve CLI

`thelve` is the cloud-only workstation client for deploying and operating a
single-node Thelve appliance in a customer-owned Google Cloud project or AWS
account. It embeds the reviewed infrastructure modules, uses the operator's
existing `gcloud` or `aws` identity, and writes secret values directly to the
provider secret manager. It never starts a Thelve application workload on the
workstation.

This repository is intentionally independent of private Thelve application
crates. Product images, the host image, and release catalogs are immutable
remote inputs verified by digest and signature.

## Current implementation

- cloud and IaC prerequisites: `thelve doctor`
- signed release, channel, machine-image, and private GCP preview documents:
  `thelve release verify`
- authenticated private preview retrieval with signed per-object size/digest
  enforcement and tamper-resistant receipt revalidation:
  `thelve release fetch-gcp-preview`
- strict non-secret deployment intent: `thelve deploy init`
- remote-state creation: `thelve deploy bootstrap-state`
- redacted Terraform plans and explicit prepare/apply/pause/resume/destroy
- direct hidden-input writes to GCP Secret Manager or AWS Secrets Manager
- one-shot correlated generation of non-Telnyx GCP runtime secrets without
  local persistence: `thelve secret initialize-internal`
- value-free node configuration rendering and signed-release activation over
  GCP IAP/OS Login with remote digest checks, exact-repository Artifact Registry
  IAM, metadata-backed registry credentials, and a redacted readiness receipt
- detached Ed25519 catalog verification with an independently pinned
  trust-root digest and embedded root/envelope/document schemas
- protected Ed25519 AAuth profiles for signed access to a deployed Thelve API
- effective live capability discovery (role × delegator × delegation × AI
  eligibility), guarded reads, immutable exact-payload plans, and
  approved-plan application
- a constrained local stdio MCP server with no generic HTTP or unrestricted
  mutation tool
- packaged, validated `thelve-admin` and `thelve-cloud` skills installable for
  Codex, Claude, or both

The application release publication, machine-image catalog publication, and
live Telnyx acceptance receipts are external release gates and are not faked by
this repository.

## Developer verification

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
terraform -chdir=modules/gcp-single-node init -backend=false
terraform -chdir=modules/gcp-single-node validate
terraform -chdir=modules/aws-single-node init -backend=false
terraform -chdir=modules/aws-single-node validate
```

See [cloud-single-node.md](docs/runbooks/cloud-single-node.md) for the command
sequence and safety boundaries. Current delivery gates are recorded in
[implementation-status.md](docs/implementation-status.md).

See [agent-access.md](docs/runbooks/agent-access.md) to enroll a public key,
bind a bounded human-approved delegation, install the agent surfaces, and run
the exact-plan workflow.
