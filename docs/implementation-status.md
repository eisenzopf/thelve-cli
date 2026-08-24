# Thelve CLI implementation status

Overall status: **Partial — local core and GCP preview activation path
implemented and validated; public binary, live cloud receipts, and Telnyx
workflow pending** · Updated 2026-08-24

## Implemented

- Independent Rust binary with no private product-crate dependency and native
  Linux/macOS release workflow.
- `thelve doctor` for GCP/AWS identity and IaC-runner diagnostics.
- Strict no-secret deployment intent and validation, including compute
  profiles, exact host-image IDs, Telnyx perimeter inputs, DNS, concurrency,
  and the complete runtime-secret inventory.
- Embedded GCP and AWS single-node Terraform modules plus byte-identical
  cross-repository compatibility gates.
- Versioned GCS or encrypted/versioned/locked S3 remote-state bootstrap.
- Redacted plan, stopped-host prepare, required-secret gate, up, status,
  pause/resume, and exact-name destroy commands with explicit approvals.
- GCP Secret Manager and AWS Secrets Manager writes through hidden input/stdin;
  values never enter CLI argv or Terraform variables/state.
- Fail-closed GCP internal-secret initialization generates one correlated
  version-1 set for database URLs/password, Redis, internal service tokens,
  Keycloak, MinIO, OIDC, and backup destination; Telnyx inputs remain separate
  hidden operator actions.
- Optional provider-native log agents are disabled by default and admitted only
  with an immutable HTTPS package URL plus lowercase SHA-256.
- Independently pinned trust-root digest plus JSON Schema checks for the root
  and signature envelope, followed by Ed25519 signature, document digest,
  active-key, document-kind, and embedded schema verification for channel,
  product-release, and machine-image documents.
- Private GCP preview descriptor verification and retrieval enforces explicit
  preview admission, one immutable GCS prefix, signed size/digest checks for
  the deployment bundle, node manager, and offline trust store, and an atomic
  local fetch receipt. Every later use re-verifies the detached signature and
  binds all receipt identity and artifact fields back to the signed descriptor.
- Value-free node configuration rendering from applied Terraform outputs and
  GCP IAP/OS Login activation with local/remote SHA-256 checks, signed bundle
  verification, activation preflight, idempotent install operation ID, secret
  materialization, exact-repository Artifact Registry reader IAM, standalone
  GCE credential-helper configuration with no persisted access token, systemd
  start, readiness assertion, and redacted receipt.
- CI gates for formatting, clippy, unit tests, Terraform validation, contract
  fixtures, compiled release archives, checksums, signatures, and provenance.
- Protected local Ed25519 AAuth profiles, HTTPS-only remote clients, RFC
  9421-style signed envelopes, live capability discovery, guarded reads,
  exact-payload configuration plans, approved-plan verification, and apply.
- Signed discovery is an effective-authority projection: AI actor role,
  delegator authority, exact delegation scopes, and AI-tool eligibility are
  intersected server-side before descriptors are returned.
- Local stdio MCP tools limited to discovery, reads, plan lifecycle, and frozen
  apply; no raw HTTP or unplanned mutation tool exists.
- Validated `thelve-admin` and `thelve-cloud` skills, Codex/Claude plugin
  manifests, managed per-user installation, and optional native MCP
  registration.
- A real local PostgreSQL/control-API/compiled-CLI rehearsal covering signed
  bounded catalog/read, immutable plan, accountable-human confirmation,
  single-use consumption, queue creation, idempotent replay, non-delegated
  denial, and local MCP discovery. An altered post-approval role payload was
  also refused by the server's exact admin-operation fence; immediate human
  delegation revocation refused the profile's next signed request.

## Open gates

- Create the hosted repository, set visibility, CODEOWNERS, protected `main`,
  and required release-environment approvals.
- Publish the signed CLI and authenticated trust-root/install instructions.
- Verify channel-to-release linkage, freshness/rollback state, catalog
  revocation, CLI-version compatibility, and provider/region image selection as
  a single transaction.
- Run the implemented GCP retrieval/activation path against a qualified host
  image and retain its first real receipt; implement equivalent AWS SSM
  transport and activation.
- Add release list/select, logs, readiness, backup/restore, upgrade/rollback,
  support bundle, capacity change, and governed inbound-test commands.
- Run clean-workstation GCP and AWS apply/security/recovery/cleanup receipts.
- Complete one spend-capped Telnyx DID-to-queue-to-browser two-way-audio test.
- Add native OS credential-store or hardware-backed AAuth key options for
  higher-assurance profiles and production OIDC/DPoP enrollment receipts.

## Local verification

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
terraform -chdir=modules/gcp-single-node init -backend=false
terraform -chdir=modules/gcp-single-node validate
terraform -chdir=modules/aws-single-node init -backend=false
terraform -chdir=modules/aws-single-node validate
```

The CLI is not a public quickstart until the signed-distribution and remote
activation gates pass. Infrastructure reconciliation alone is not application
or carrier readiness.
