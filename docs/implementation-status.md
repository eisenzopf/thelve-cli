# Thelve CLI implementation status

Overall status: **Partial — local core, signed GCP preview retrieval, and
qualified-image infrastructure reconciliation are live-validated; public
binary, application activation, and Telnyx workflow remain** · Updated
2026-08-24

## Implemented

- Independent Rust binary with no private product-crate dependency and native
  Linux/macOS release workflow.
- `thelve doctor` for GCP/AWS identity and IaC-runner diagnostics.
- Strict no-secret deployment intent and validation, including compute
  profiles, exact host-image IDs, Telnyx perimeter inputs, DNS, concurrency,
  and the complete runtime-secret inventory.
- Dated, CLI-embedded Telnyx US signaling and global media CIDRs for US cloud
  regions; unsupported regions keep fail-closed review sentinels.
- GCP and AWS carrier perimeters admit RTP plus AnchorSite ICMP probes only
  from the explicit Telnyx media profile, preserving automatic nearest-PoP
  media routing without global ICMP ingress.
- Embedded GCP and AWS single-node Terraform modules plus byte-identical
  cross-repository compatibility gates.
- Versioned GCS or encrypted/versioned/locked S3 remote-state bootstrap.
- Backend initialization passes only provider-specific values to the module's
  single declared backend, and idempotently removes the duplicate block emitted
  by the earliest preview CLI; a real GCP rehearsal now guards this path.
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
- Live GCP preview evidence: signed release `0.1.0-preview.2` was fetched and
  reverified against an independently pinned trust-root digest; the prepared
  deployment was then reconciled onto qualified image
  `thelve-host-0-1-0-preview-4-20260824-2a383b6`, preserving the static IP and
  external state while leaving the host stopped.
- Activation and remote qualification preserve the required open-file limit
  across privilege elevation by setting it inside the audited root shell; this
  was discovered and fixed during the first real image qualification.
- CI gates for formatting, clippy, unit tests, Terraform validation, contract
  fixtures, compiled release archives, checksums, signatures, and provenance.
- Dual Apache-2.0/MIT license texts, a private vulnerability-reporting policy,
  CODEOWNERS, and immutable full-commit pins for every third-party GitHub
  Action used by verification and release workflows. Release jobs use the
  current standard `macos-15-intel` and `macos-15` runner labels instead of the
  retired macOS 13 label.
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

- Create the hosted repository, enable private vulnerability reporting, protect
  `main` and release tags using the checked-in CODEOWNERS rules, and require
  release-environment approvals before making the repository public.
- Publish the signed CLI and authenticated trust-root/install instructions.
- Verify channel-to-release linkage, freshness/rollback state, catalog
  revocation, CLI-version compatibility, and provider/region image selection as
  a single transaction.
- Run the implemented GCP application-activation path against the already
  qualified/prepared host and retain its first real receipt; implement
  equivalent AWS SSM transport and activation.
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

## Publication posture

This repository is the intended public surface: it contains the independent
operator client, schemas, embedded infrastructure adapters, agent skills, and
runbooks, but no private Thelve application source or container layers. A clean
history secret scan currently reports no findings. License, security-policy,
CODEOWNERS, and immutable Action-pin files are checked in. Public visibility is
still a controlled release decision, not a runner workaround: hosted branch and
tag protection, private vulnerability reporting, release approvals, and signed
binary publication must be configured first. The separate image factory should
remain private and use protected cloud-native builds.
