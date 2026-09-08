# Local development through the CLI (Colima)

Run the Linux single-node appliance through `thelve launch --provider local`.
The private build pipeline supplies locally built Thelve API, realtime
gateway, and UI images. PostgreSQL, Keycloak, Redis, MinIO, and Caddy use
pinned upstream images. No released Thelve image is downloaded
for a service in this appliance.

## Prerequisites

- A running default Colima profile using Docker, with a reachable VM address,
  at least 8 CPUs and 16 GiB RAM, and sufficient disk for appliance images.
  For a new profile: `colima start --cpu 8 --memory 16 --disk 60 --network-address`.
- The `colima` Docker context selected: `docker context use colima`.
- Docker Compose inside Colima and the installed Thelve CLI.
- A prebuilt local release directory from the private build pipeline.

The default Colima VM hosts one local appliance at a time. An owner marker
prevents one local directory from overwriting another appliance. The CLI
uses `/etc/thelve`, `/opt/thelve`, and `/var/lib/thelve` **inside Colima**.
It does not install these directories or a system service on macOS.

## Release package

Obtain a prebuilt local release package from the private Thelve build tools.
The public CLI does not build images, compile installation tools, or run a
licence issuer. The package includes the host-native renderer, Linux node
manager, configuration assets, signed manifest, and trust store. Use a package
built for your workstation architecture and Colima platform.

## Launch

```sh
./target/debug/thelve launch \
  --provider local \
  --release-dir ../thelve-dev-appliance/my-local-release \
  --local-dir ../thelve-dev-appliance/my-thelve \
  --name my-thelve \
  --admin-email you@example.com \
  --approve
```

The CLI verifies the signed release before requesting a licence or writing
secrets. It generates correlated credentials, obtains the real licence from
Rudeless, renders the shared Compose plan, materializes owner-only secrets in
Colima's runtime tmpfs, and waits for every service's health check. Compose
uses `--pull never`: all runtime images must have been prepared by the build.

It then creates the first person in bundled Keycloak, binds that exact issuer
and subject to the installation administrator through the transactional tenant
provisioner, and prints a temporary password. The Thelve-branded sign-in flow requires a password change at first sign-in. A mode-0600
`initial-admin-password` file in the local directory preserves the first
password in case the terminal disconnects; receipts contain no password.
Repeating launch preserves the administrator and credentials. Passing a newer
local release preserves the database and recreates services to refresh images
and cached presentation artifacts. The desk avatar opens Your account, with
workspace/role details, Change password, and Sign out. Password changes use the
same Thelve-branded authentication pages; username editing remains disabled.
The shared signed node artifact also carries this theme for remote installs;
remote releases must include the updated node binary and web image.

The app name is generated from Colima's reachable address, for example
`https://app-192-168-64-2.sslip.io`. The API and realtime names use `control-`
and `realtime-` with the same address. A private VM address cannot obtain a
public ACME certificate, so the signed development Caddy template uses an
internal certificate authority. Local installs reuse the machine-level
authority stored inside Colima at `/var/lib/thelve-developer-ca`; appliance
removal does not delete it. On the first launch, the CLI adds its root
certificate to the macOS login keychain and macOS may ask for approval. Later
destroy/recreate cycles use the same trusted authority and require no additional
certificate approval. The CLI's HTTPS checks use that CA and never disable TLS
validation.

The default licence trust is `https://licenses.rudeless.ai/v1/trust`, and the
request goes to `https://rudeless.ai/api/v1/thelve/licenses/trial`. The local
installation receives the same signed certificate and uses the same verifier
as a remote launch. `--issuer-url`, `--license-service-url`, and
`--issuer-trust-sha256` also work locally. Licence issuance stays with Rudeless.

## Check, stop, and remove

```sh
./target/debug/thelve dev status --local-dir ../thelve-dev-appliance/my-thelve
./target/debug/thelve dev stop --local-dir ../thelve-dev-appliance/my-thelve --approve
./target/debug/thelve dev destroy --local-dir ../thelve-dev-appliance/my-thelve --approve
```

`stop` drains the gateway and stops the containers, preserving data. Run the
same launch command to start again. `destroy` removes containers, networks,
appliance data, runtime secrets, and the local appliance directory. Built
release directories, cached images, Colima itself, and the machine-level
developer CA are retained.

## Qualification

For a disposable fresh launch, before manually changing the first password:

```sh
python3 tools/verify-local-auth.py \
  --local-dir ../thelve-dev-appliance/my-thelve \
  --email you@example.com
```

This checks HTTPS with the generated CA, OIDC configuration, the bundled
login form, browser CSP and authenticated CORS preflight, and that the generated password reaches the mandatory password
change. It does not change the password or print it.

The local mode qualifies the images, renderer, migrations, licence, identity,
and container lifecycle. It does not qualify cloud provisioning, public ACME,
reboot/systemd integration, or carrier calls. Carrier credentials are omitted.

For a disposable appliance whose name ends in `-verification`,
`tools/verify-local-session.mjs LOCAL_DIR THELVE_SOURCE EMAIL` also exercises the
real browser SDK's PKCE/DPoP exchange and an authenticated CRM API read. Set
`NODE_EXTRA_CA_CERTS=LOCAL_DIR/local-ca.crt` when running it. This extended test
completes the test admin's required password change via Keycloak's admin API;
it is intentionally refused for normally named instances. Run the initial
password test first, then destroy the qualification instance.
