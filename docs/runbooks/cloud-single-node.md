# Cloud single-node operator runbook

Status: local CLI implementation available, including live-validated private
GCP preview retrieval, signed activation, provider-neutral outbound capacity,
encrypted GCS backup, and exact GCE node replacement. Publication and a clean
replacement/live outbound receipt remain open.
`deploy up` starts the host, while
`deploy activate-gcp` is the separate application-readiness boundary.
Activation grants the deployment's exact runtime service account read access
to the exact signed Artifact Registry repository. The host obtains short-lived
credentials from its GCE identity through `docker-credential-gcr`; neither the
CLI nor the host stores an OAuth access token or registry password.

## Safety model

The workstation runs only the signed `thelve` CLI, the selected audited IaC
runner, and the provider CLI. Thelve application processes run only on the
remote VM. Deployment intent and Terraform state contain cloud resource and
secret-version references but no secret values. GCP and AWS secret values are
sent to the provider process over stdin.

Every mutating CLI operation requires `--approve`. Destroy additionally
requires `--confirm DEPLOYMENT_NAME`. `prepare` deliberately creates a stopped
host and empty secret containers. `up` refuses to start until every declared
secret has an enabled version.

Verify each exact channel, product-release, and machine-image document before
copying a release or host-image identifier into deployment intent:

```sh
thelve release verify --kind release --document product-release.json \
  --signature product-release.signature.json --trust-root thelve-trust-root.json \
  --trust-root-sha256 sha256:REPLACE_WITH_INDEPENDENTLY_PINNED_DIGEST
```

For the private GCP preview, first obtain the descriptor, detached signature,
and trust root from the authenticated release location. The trust-root digest
must come from an independent Thelve release/install channel, not from the same
bucket listing. Then fetch every signed artifact atomically:

```sh
thelve release fetch-gcp-preview \
  --descriptor preview-release.json \
  --signature preview-release.signature.json \
  --trust-root trust-root.json \
  --trust-root-sha256 sha256:REPLACE_WITH_INDEPENDENTLY_PINNED_DIGEST \
  --output verified-preview --admit-preview
```

## GCP sequence

```sh
gcloud auth login
gcloud auth application-default login
gcloud config set project PROJECT_ID

thelve doctor --provider gcp --project PROJECT_ID
thelve deploy init --provider gcp --name thelve-test \
  --project PROJECT_ID --region us-west1 --zone us-west1-b \
  --output deployment.yaml
```

Edit `deployment.yaml`. Select the exact GCP image only from a verified machine
catalog, use a globally unique state bucket, review the CLI-embedded dated
Telnyx signaling/media network profile, and set `provider.dnsManagedZone` plus the
`app`, `api`, `media`, and `sip` domains when the module manages Cloud DNS.
US cloud regions receive the audited US profile automatically; unsupported
regions remain fail-closed with `REPLACE` sentinels until an operator supplies a
reviewed regional profile.
The cloud perimeter also admits ICMP only from those explicit Telnyx media
ranges. Telnyx uses those probes for its default latency-based AnchorSite
selection, so media follows the nearest healthy carrier PoP without exposing
ICMP to the public Internet.
Set `provider.opsAgentPackage` only with a reviewed immutable HTTPS package and
SHA-256; omit it to keep provider-native export disabled.
Then:

```sh
thelve deploy bootstrap-state --config deployment.yaml --approve
thelve deploy plan --config deployment.yaml
thelve deploy prepare --config deployment.yaml --approve
thelve secret initialize-internal --config deployment.yaml --approve
thelve secret set --config deployment.yaml --name telnyx-api-key
thelve secret set --config deployment.yaml --name telnyx-public-key
thelve deploy up --config deployment.yaml --approve
thelve deploy render-node-config --config deployment.yaml \
  --release-dir verified-preview --tls-contact-email operator@example.com \
  --output node.yaml
thelve deploy activate-gcp --config deployment.yaml \
  --release-dir verified-preview --node-config node.yaml \
  --receipt activation-receipt.json --approve
thelve deploy status --config deployment.yaml
```

The API-key and Telnyx Ed25519 webhook-public-key prompts are hidden. The public
key is integrity-sensitive and must be the base64 value shown by Telnyx. For
automation, pass `--stdin` and pipe from an authorized process; never put either
value in a command argument or deployment file. Internal-secret initialization
refuses a mixed version-1 state so correlated database credentials cannot drift
after a partial attempt.

For bundled PostgreSQL, initialization generates bridge-DNS URLs for the
control plane and migrator and a separate `127.0.0.1:5432` URL for the
host-network realtime gateway. `render-node-config` then verifies the exact
GCP project and secret-binding set, resolves the newest enabled numeric version
of every secret, and records those immutable version pins without reading any
secret value. A later activation therefore adopts an intentional rotation but
cannot silently follow a mutable alias.

Internal initialization also creates the SIP egress root used only by the
backend to derive tenant-scoped carrier credentials. The root and derived
credentials never enter deployment intent, Terraform state, receipts, logs,
or CLI arguments. Set the three call limits to two inbound, two outbound, and
two total for the spend-capped test deployment; raise them only after carrier,
gateway, and host capacity review.

Before replacing a GCP node, fetch and verify the exact target release, resume
the current node, and create a consistent encrypted backup:

```sh
thelve backup create --config deployment.yaml --release-dir verified-preview \
  --output backup-receipt.json --approve
thelve backup verify --config deployment.yaml --backup-id BACKUP_UUID
thelve deploy replace-node --config deployment.yaml \
  --release-dir verified-preview --backup-id BACKUP_UUID \
  --receipt replacement-receipt.json --approve --confirm thelve-test
```

Replacement refuses a Terraform plan containing any resource mutation other
than replacement of the exact GCE instance. The boot disk auto-deletes; the
static IP, VPC/subnet, Secret Manager containers and versions, GCS state and
backup storage, deployment identity, tenant state, DID, and carrier resources
remain. Restore failure leaves the new application stopped and retains the
backup. The current recovery transport is deliberately GCP-first; AWS recovery
must not be inferred from these commands.

After Terraform applies the exact VM replacement, the CLI writes a private
`RECEIPT.pending` checkpoint containing only the verified backup/release,
non-secret TLS contact, old/new cloud identities, and exact-plan evidence. If a
transient IAP transfer or restore safety gate stops the combined command, rerun
the exact same `replace-node` command. The CLI re-verifies the signed release,
backup, checkpoint, and current VM/disk plus retained-resource identities, then
resumes activation and restore without applying Terraform or replacing compute
again. A mismatched deployment, backup, release, VM, disk, address, network,
identity, secret-container inventory, or backup bucket fails closed.

IAP staging, transfer, and remote-command setup each tolerate up to twelve
bounded pre-session failures. Only failures proven to occur before an SSH
session exists are retried; an application command with uncertain execution is
never replayed automatically. On successful activation and restore, the CLI
writes the final replacement receipt and removes the pending checkpoint.

CLI releases before `v0.1.8` do not create this checkpoint. If one of those
older releases has already created the fresh VM, do not invoke `replace-node`
again. Activate the same verified target release, then resume only the verified
restore:

```sh
thelve deploy activate-gcp --config deployment.yaml \
  --release-dir verified-preview --node-config node.yaml \
  --receipt recovery-activation-receipt.json --approve
thelve backup restore --config deployment.yaml \
  --release-dir verified-preview --backup-id BACKUP_UUID \
  --output restore-receipt.json --approve
```

`backup restore` re-verifies the signed target release and immutable backup,
accepts only the current ready gateway receipt, writes a value-free local
receipt, and stops the application again if execution or receipt validation
fails. Activation retries only the idempotent, owner-checked staging and SCP
steps across bounded transient IAP/SSH failures; it never silently replaces or
resets a node.

The TLS contact email is operational metadata, not a secret, but it must be a
real operator-selected address for ACME notices. Do not substitute an example
address in an actual activation. Stop after `prepare` if the contact or either
Telnyx value is not yet available; the static address, state, backup bucket and
secret containers remain provisioned while compute stays stopped.

`activate-gcp` also confirms that the immutable host image contains the
checksum-pinned standalone GCP registry helper and that the installed systemd
unit uses the root-only `/etc/thelve/docker` configuration. Its redacted receipt
records the repository, runtime service account, IAM role, helper, and the fact
that no access token was persisted. Repository IAM is idempotent and remains in
place if a later application-readiness check fails; remove that exact binding
only as an explicit deprovisioning action.

## AWS sequence

```sh
aws configure sso
aws sso login --profile YOUR_PROFILE
export AWS_PROFILE=YOUR_PROFILE

thelve doctor --provider aws --region us-west-2
thelve deploy init --provider aws --name thelve-test \
  --region us-west-2 --zone us-west-2a --output deployment.yaml
thelve deploy bootstrap-state --config deployment.yaml --approve
thelve deploy plan --config deployment.yaml
thelve deploy prepare --config deployment.yaml --approve
thelve secret initialize-internal --config deployment.yaml --approve
thelve secret set --config deployment.yaml --name telnyx-api-key
thelve secret set --config deployment.yaml --name telnyx-public-key
thelve deploy up --config deployment.yaml --approve
thelve deploy status --config deployment.yaml
```

For AWS-managed DNS, set `provider.route53ZoneId` and all four domain keys
before planning. Set `provider.cloudwatchAgentPackage` only with a reviewed
immutable HTTPS package and SHA-256.

## Pause, resume, and cleanup

```sh
thelve deploy pause --config deployment.yaml --approve
thelve deploy resume --config deployment.yaml --approve
thelve deploy destroy --config deployment.yaml --approve --confirm thelve-test
```

Destroy does not delete the separately bootstrapped state bucket. Backup-bucket
retention, GCP secret deletion protection, AWS secret recovery windows, and DNS
may also intentionally retain resources. Review the final provider inventory
and billing console before closing a test.

## Open preview gates

Do not call the path production-ready until a signed product release and host
catalog are published, the remote `thelve-node` installs the release, provider
IAM-negative tests pass, clean-host restore passes, and an external Telnyx call
lands on a logged-in browser agent with confirmed two-way audio.
