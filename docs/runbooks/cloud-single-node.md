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

## One-command launch

`thelve launch` is the GCP sequence below composed into one resumable
command. It takes as arguments what the sequence has the operator edit into
`deployment.yaml` by hand, runs each step in the runbook's order under the
same `--approve` gate, and records each completed step in
`launch-receipt.json`; a stopped launch rerun with the same arguments resumes
at the first incomplete step and never re-applies a completed one. The two
Telnyx values are still typed at hidden prompts.

```sh
thelve launch --provider gcp --name thelve-test \
  --project PROJECT_ID --region us-west1 --zone us-west1-b \
  --host-image projects/PROJECT_ID/global/images/IMAGE_FROM_VERIFIED_CATALOG \
  --state-bucket UNIQUE-STATE-BUCKET \
  --domain app=desk.example.com --domain api=api.example.com \
  --domain media=media.example.com --domain sip=sip.example.com \
  --tls-contact-email operator@example.com \
  --release-dir verified-preview \
  --oidc-issuer https://login.example.com/realms/acme --oidc-client-id thelve-desk \
  --approve
```

After the host is up, the launch asks Rudeless for the installation's
licence (free, one per installation, without expiry) using the installation
id it derives from the deployment name and the `--tls-contact-email`
address, fetches the issuer's published trust anchors, and records both in
`deployment.yaml`; the node installs the certificate at first boot. Asking
again for the same installation returns the same certificate, so a resumed
launch is safe. `--issuer-trust-sha256` pins the trust document to the digest
Rudeless publishes beside the issuer URL; `--issuer-url` and
`--license-service-url` point at another issuer or service; `--skip-license`
leaves the appliance unlicensed and prints the manual command.

`--oidc-issuer` and `--oidc-client-id` name the OIDC provider people sign in
with; the client secret your provider issued is typed at a hidden prompt
(`oidc/client-secret`) and written straight to the cloud secret store. A
deployment made through this CLI never renders demo identity: there is no
flag for it, and the appliance refuses to boot with it outside a preview
render produced by the release tooling.

It ends with `deploy status` and the next steps: open the app domain and
complete the setup checklist (first administrator, sign-in, telephony).
`thelve license status` shows the certificate the intent carries. On AWS the launch stops after `up` with the node configuration
rendered, because activation is GCP-only today.

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

## Licence

`thelve launch` licenses the installation itself; the two steps below are
the manual path for an air-gapped launch (`--skip-license`) or an issuer
other than Rudeless. An appliance runs `legacy_unmanaged` — every module
readable, nothing commercially bounded — until a signed entitlement
certificate is installed. Both steps are value-free on the workstation:

1. Before `render-node-config`, record which issuer the appliance trusts.
   `thelve license trust` fetches the issuer's published Ed25519 public keys
   and prints them as the `licensing` block for `deployment.yaml`; the render
   projects it into the control API's trust anchors. An appliance with an
   empty `licensing.trustedIssuers` cannot install any certificate.

   ```sh
   thelve license trust --issuer-url https://licenses.rudeless.ai
   ```

2. Install the certificate the issuer produced for this installation. The
   issuer needs the installation's tenant id, which `thelve launch` prints
   and which is derived from the deployment name; the node provisions that
   tenant at first boot. Before any administrator exists, record the
   certificate in the deployment intent and re-activate; the control API
   installs it at boot, enrolling the tenant with the certificate's issuer
   on first use and ingesting with the usual anti-rollback and exact-replay
   rules:

   ```sh
   thelve license install --config deployment.yaml --certificate licence.json \
     --release-dir verified-preview --tls-contact-email operator@example.com \
     --node-config node-licensed.yaml --activation-receipt licence-activation-receipt.json \
     --approve
   ```

   Once an AAuth profile is bound, the same certificate (or a renewal)
   installs through the API instead, without re-activation:

   ```sh
   thelve license install --profile thelve-test --certificate licence.json
   ```

The certificate names product suites expanded into component grants by the
issuer; Tenant Admin → Entitlement shows each suite's coverage. A lapsed
certificate drops the granted modules to read-only rather than removing data.

## Upgrade, rollback, and support

An upgrade is `deploy activate-gcp` with the newer verified release: the
node manager's install is convergent and hash-chains its receipt after the
previous one, so the node's own ledger records the step. To go back:

```sh
thelve deploy support-bundle --config deployment.yaml --output support-bundle.json
thelve deploy rollback --config deployment.yaml \
  --to INSTALLED_RELEASE_ID --receipt rollback-receipt.json --approve
```

The support bundle lists every installed release with its id (the release id
plus the install-intent suffix) and which one is current, the verified
receipt chain, readiness, and the last two hours of the service journal; it
carries no runtime settings or secret files and attests
`secretValuesRecorded: false`. Rollback re-verifies the target's bundle
against the node's trust store, refuses if the node configuration has changed
since that release was installed (install the release instead), reinstalls
the target's node artifacts, moves the `current` pointer, appends a
`rollback` receipt to the chain, and restarts the service.

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
