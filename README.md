# Thelve CLI

`thelve` is the workstation client for deploying and operating a single-node
Thelve appliance in a customer-owned Google Cloud project or AWS account. Its
developer-only local provider deploys a prebuilt release into Colima. It embeds
the reviewed infrastructure modules, uses the operator's existing `gcloud` or
`aws` identity, and writes cloud secret values directly to the provider secret
manager.

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
- one-shot correlated generation of non-Telnyx GCP or AWS runtime secrets without
  local persistence: `thelve secret initialize-internal`
- encrypted GCS backup creation/verification/restore and exact GCE node replacement
  with retained static IP, network, secret containers, backup bucket, and
  application state
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

- issuer trust capture and licence installation on a deployed appliance,
  either at boot through the deployment intent (before any administrator
  exists) or through a bound AAuth profile: `thelve license trust`,
  `thelve license install`
- the whole GCP sequence as one resumable, receipt-recorded command:
  `thelve launch`

The application release publication, machine-image catalog publication, and
live Telnyx acceptance receipts are external release gates and are not faked by
this repository.

Tagged releases publish compiled-only Linux and macOS binaries, archives,
SHA-256 files, keyless Sigstore bundles, and GitHub build provenance. The
direct Linux binary is also the immutable input used by GCP release
qualification. The intended familiar installation command is
`brew install thelve`; admission to Homebrew/core is a public-release gate, so
until that formula is accepted operators install the exact verified GitHub
Release asset documented with the release.

## Linux container installation (release testing)

`thelve install` runs on the Linux appliance host as root and downloads an
existing image; it does not compile application code. Docker Engine and
`cosign` must already be installed. This path is under release qualification;
a successful compilation alone does not qualify an image for installation.

Supply an exact digest-pinned image signed by the Thelve candidate workflow
and the corresponding signed release directory:

```sh
sudo thelve install \
  --image REGISTRY/REPOSITORY/IMAGE@sha256:DIGEST \
  --hostname thelve.example.com \
  --public-ip 203.0.113.10 \
  --contact-email operator@example.com \
  --admin-email admin@example.com \
  --release-directory /path/to/verified-release \
  --approve
```

Replace the example values with the published release identity and your host's
settings. Configure DNS for the hostname and its `api.` and `media.` subdomains
before installation. Existing nonempty configuration or data is refused, not
overwritten. Fresh configuration contains no Telnyx or Vapi credentials.

The administrator email is separate from the licensing contact. The CLI
generates a temporary password, shows it only in an interactive terminal, and
saves an owner-only recovery copy at `/etc/thelve/initial-admin-password`.
Keycloak requires a password change at first login. Do not capture an
interactive installation in a terminal recording. After changing the password,
remove the obsolete recovery copy. An interrupted administrator setup can be
resumed without reinstalling the appliance:

```sh
sudo thelve complete-setup --admin-email admin@example.com --approve
```

This command does not reset an existing administrator's password. Keep the
same administrator email when resuming setup.

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

## License and security

The CLI is dual-licensed under Apache-2.0 or MIT. See [LICENSE-APACHE](LICENSE-APACHE)
and [LICENSE-MIT](LICENSE-MIT). Report suspected vulnerabilities through the
private process in [SECURITY.md](SECURITY.md), never through a public issue.

## Local developer appliance

The development CLI can launch a prebuilt Thelve release in Colima, including
bundled sign-in and a real Rudeless licence. Private build tooling in the Thelve
repository creates that release; the public CLI has no build command. See
[the local development runbook](docs/runbooks/local-development.md).
