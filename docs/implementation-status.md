# Thelve CLI implementation status

Overall status: **Partial — provider-neutral outbound and GCP recovery contracts
are implemented, signed CLI `v0.1.6` is public, and an exact clean-node restore
has passed; the hardened local-only GCP observability profile is publishing for
one more node rehearsal, while live outbound acceptance remains** · Updated
2026-08-31

## Implemented

- Independent Rust binary with no private product-crate dependency and native
  Linux/macOS release workflow.
- `thelve doctor` for GCP/AWS identity and IaC-runner diagnostics.
- Strict no-secret deployment intent and validation, including compute
  profiles, exact host-image IDs, Telnyx perimeter inputs, DNS, concurrency,
  and the complete runtime-secret inventory.
- `maxConcurrentInboundCalls`, `maxConcurrentOutboundCalls`, and
  `maxConcurrentVoiceCalls` are projected into the value-free SingleNode
  activation contract and independently revalidated before upload. The test
  defaults are two inbound, two outbound, and two total carrier calls.
- Dated, CLI-embedded Telnyx US signaling and global media CIDRs for US cloud
  regions; unsupported regions keep fail-closed review sentinels.
- GCP and AWS carrier perimeters admit RTP plus AnchorSite ICMP probes only
  from the explicit Telnyx media profile, preserving automatic nearest-PoP
  media routing without global ICMP ingress.
- GCP and AWS expose a separate configurable browser-media UDP range
  (`49152-50175` by default), feed the range and source CIDRs into the node
  contract, and never widen the Telnyx RTP perimeter for roaming agents.
- Embedded GCP and AWS single-node Terraform modules plus byte-identical
  cross-repository compatibility gates.
- Versioned GCS or encrypted/versioned/locked S3 remote-state bootstrap.
- Backend initialization passes only provider-specific values to the module's
  single declared backend, and idempotently removes the duplicate block emitted
  by the earliest preview CLI; a real GCP rehearsal now guards this path.
- Redacted plan, stopped-host prepare, required-secret gate, up, status,
  pause/resume, and exact-name destroy commands with explicit approvals.
- GCP required-version checks convert Terraform's full secret resource name to
  an exact same-project secret ID before invoking `gcloud`; the live gate now
  recognizes the declared version inventory without disclosing values.
- GCP Secret Manager and AWS Secrets Manager writes through hidden input/stdin;
  values never enter CLI argv or Terraform variables/state.
- Fail-closed GCP and AWS internal-secret initialization generates one correlated
  version-1 set for database URLs/password, Redis, internal service tokens,
  Keycloak, MinIO, OIDC, backup destination, and the SIP egress derivation
  root; Telnyx API and webhook inputs remain separate hidden operator actions.
- GCP backup creation and verification invoke the signed node's bounded backup
  tools over IAP, accept only value-free contract receipts, and preserve
  encrypted/versioned backup objects in the deployment's private GCS bucket.
- `backup restore` independently re-verifies the signed target release and
  immutable recovery point, accepts only the current ready gateway receipt,
  writes a private value-free receipt, and stops the application again if
  execution or receipt validation fails.
- `deploy replace-node` verifies the target signed release and retained backup,
  applies a saved Terraform plan containing only an exact GCE instance
  replacement, proves changed instance and boot-disk identities, proves the
  static IP/network/runtime identity/secret containers/backup bucket were
  retained, activates the target release, restores state, and leaves a failed
  restoration stopped with the backup retained.
- Replacement evidence projects activation readiness from the current signed
  gateway contract (`readiness.status == ready`); the obsolete boolean shape is
  explicitly rejected so a successful replacement cannot emit an ambiguous
  `null` readiness value.
- Optional provider-native log agents are disabled by default and admitted only
  with an immutable HTTPS package URL plus lowercase SHA-256.
- The GCP local-only observability profile now explicitly disables guest-agent
  Cloud Logging and guest telemetry instead of granting unused writer roles or
  continuously emitting denied API calls. Enabling the Ops Agent retains the
  existing conditional Logging Writer and Monitoring Metric Writer roles. A
  dedicated regression plus Terraform/template and cross-repository drift gates
  bind both branches to the same public embedded module.
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
- Activation is safely resumable only when the CLI first reverifies the active
  installed bundle against staged trust, verifies the exact root-owned signed
  systemd unit bytes, and proves the listeners belong to that installation.
  The incoming verifier validates every incoming byte, while the exact
  root-owned installed verifier validates the active bundle under the contract
  version that installed it. This preserves fail-closed verification across a
  forward contract change instead of asking a newer verifier to reinterpret an
  older valid release. Foreign listeners still fail closed. Receipts distinguish
  fresh start from a verified service restart without mixing lifecycle JSON into
  their output.
- First-boot activation retries only the idempotent remote-stage preparation
  and artifact-transfer steps across six bounded IAP/SSH attempts. Reused
  staging directories must be owned by the OS Login caller and mode `0700`;
  activation never silently resets or replaces a node.
- Activation treats a verified `/opt/thelve/current` installation as managed
  state even when systemd is inactive. Before installing a new release it
  verifies the prior signed bundle, exact systemd unit, root ownership and
  modes of Compose/runtime inputs, invokes the signed stop path, and performs
  an explicit Compose teardown. This prevents Docker from reviving
  recovery-only containers on reboot and creating directories at missing
  tmpfs secret bind paths. An active service without a verifiable current
  installation remains fail-closed.
- Live GCP preview evidence: signed release `0.1.0-preview.15` was fetched and
  reverified against an independently pinned trust-root digest, rendered, and
  activated on qualified image
  `thelve-host-0-1-0-preview-5-20260825-028cdb5`, preserving static IP
  `34.168.66.188` and the restricted SIP/RTP/browser perimeter. All 14 pinned
  secrets were materialized without values entering the receipt; all six
  services became healthy, the gateway reported ready, trusted public TLS and
  API health/readiness passed, and the redacted activation receipt recorded an
  active service. The CLI then paused the VM for cost control while the product
  web/bridge corrections are signed.
- Activation and remote qualification preserve the required open-file limit
  across privilege elevation by setting it inside the audited root shell; this
  was discovered and fixed during the first real image qualification.
- CI gates for formatting, clippy, unit tests, Terraform validation, contract
  fixtures, compiled release archives, checksums, signatures, and provenance.
- All 45 CLI tests pass with outbound-capacity, SIP-egress-secret, exact
  replacement coverage; final strict Clippy and release-workflow validation
  are rerun before publication.
- Public repository `https://github.com/eisenzopf/thelve-cli` hosts `main`; its
  first standard-runner verification passed every Rust, Terraform and
  no-secret job. Repository defaults are read-only Actions tokens, squash-only
  merging, automatic branch deletion, secret scanning with push protection,
  Dependabot alerts/security updates, and private vulnerability reporting.
- `main` requires the four strict hosted checks plus one code-owner review,
  resolved conversations, and linear history. Active `v*` tag rules restrict
  creation, update, and deletion to the owner recovery path; force-push and
  branch deletion are disabled while the owner retains administrative bypass.
- Dual Apache-2.0/MIT license texts, a private vulnerability-reporting policy,
  CODEOWNERS, and immutable full-commit pins for every third-party GitHub
  Action used by verification and release workflows. Runtime actions use
  Node.js 24-compatible majors, release jobs use the current standard
  `macos-15-intel` and `macos-15` labels, and Dependabot tracks Cargo,
  Terraform and GitHub Actions updates.
- The `cli-release` GitHub environment requires explicit owner review and a
  protected branch; tagged binary publication is bound to that environment.
- Public release `v0.1.4` is bound to commit
  `6079091e5a2a6ac86cfe820f92a3d91542713031`. Hosted run `33434224995`
  passed all Linux, Intel macOS, and Apple Silicon build, test,
  keyless-signing, provenance, and publication jobs. The independently checked
  Linux binary digest used by GCP qualification is
  `sha256:6c59c2cb7eca916dfd78f275241f5f629f53850d246904da22b4cc6d882fc8ae`;
  the installed Apple Silicon rehearsal binary is independently attested at
  `sha256:78b9552821e429ec845c684ec7dccbdb7add27ba09392abc5ee81107bfbc7f23`.
- Public release `v0.1.5` is bound to commit
  `ff6c15591f8fc5b050b99af726eb37034d4eb965`. Hosted release run
  `33442009508` passed Linux, Intel macOS, and Apple Silicon publication jobs;
  hosted main verification run `33442008454` also passed. The independently
  verified Linux binary used for release qualification is
  `sha256:f80067882277130402b36d35a8da9c09f8c4f34c9f24425ae8df19bb29c4f690`;
  the installed Apple Silicon binary is checksum- and attestation-verified at
  `sha256:ce5accb5794f2844f12b0f4836278228028def18f804a4e32c2b5517ae0fd348`.
- Public release `v0.1.6` is bound to commit
  `9b4587753124bf56cb1ee95ada95709ffdab2bc5`. Hosted verification run
  `33466644620` passed Rust, both Terraform modules, and the no-secret gate;
  protected release run `33466650748` passed all Linux, Intel macOS, and Apple
  Silicon build, test, keyless-signing, provenance, and publication jobs. The
  independently checksum- and provenance-verified Linux qualification binary
  is `sha256:4f65bd01371c1c4cf49bffe0f225f08694290f416d06839a2c2d0b8553e03308`;
  the installed Apple Silicon binary is
  `sha256:5b2e9ce4babbc054de532cdd3b26d4872aad64fc98c2da827008545926ef15a7`.
- The released exact-node workflow has now completed against the retained GCP
  deployment. It replaced only the GCE instance and auto-deleting boot disk,
  changed instance identity `6166252024103462821` to `3259657022777064453`
  and disk identity `6340953216187393957` to `1957598684396649477`, activated
  signed Preview 45, restored verified backup
  `75d4f6e2-6325-415b-8c91-1a8f0d001481`, applied migrations, and returned a
  ready gateway. Static IP `34.168.66.188`, network, runtime identity, backup
  bucket, and all 15 secret containers remained unchanged; no secret value or
  Redis cache entered the receipt.
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

- Publish standard `brew install thelve` metadata and authenticated
  trust-root/install instructions around the already signed public CLI.
- Verify channel-to-release linkage, freshness/rollback state, catalog
  revocation, CLI-version compatibility, and provider/region image selection as
  a single transaction.
- Activate the guest-telemetry-hardened GCP release and retain its clean serial,
  browser/WebRTC, and call evidence; implement equivalent AWS SSM transport and
  activation.
- Add release list/select, logs, upgrade/rollback, support bundle, capacity
  change, and governed inbound-test commands; add AWS backup/restore parity.
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

The CLI is not a public quickstart until the signed-distribution, remote
qualification, clean restore, and outbound acceptance gates pass.
Infrastructure reconciliation alone is not application or carrier readiness.

## Publication posture

This public repository is the intended external surface: it contains the independent
operator client, schemas, embedded infrastructure adapters, agent skills, and
runbooks, but no private Thelve application source or container layers. A clean
history secret scan currently reports no findings. License, security-policy,
CODEOWNERS, immutable Action pins, private vulnerability reporting, push
protection and release approval are configured. Public source visibility does
not make this a public quickstart: signed binary publication and the remaining
activation evidence still gate that claim. The separate image factory remains
private and uses protected cloud-native builds.
