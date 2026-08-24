# Agent access runbook

Use this flow after a Thelve API is reachable. Remote deployments require
HTTPS; loopback HTTP is accepted only for local qualification.

## Create and enroll a profile

```sh
thelve agent profile create \
  --name default \
  --api-url https://thelve.example.com \
  --tenant-id TENANT_UUID \
  --key-id operator-workstation-1
```

In **Tenant Admin → Agent access**, stage an AI identity. Root-authority writes
are exact four-eyes operations: request approval for the displayed frozen
payload, have a different authorized human decide it, then switch back to the
requester to execute it. Create the linked canonical AI tenant actor and grant
the least-privileged role through the same ceremony.

Paste the command's complete JSON output into **CLI public JSON**. Only the
public JWK is sent to Thelve. Complete the four-eyes key-registration ceremony,
then create a delegation with the smallest practical scopes, resource
allowlists, expiry, and invocation quota. Delegation creation is four-eyes;
the resulting pending delegation also needs distinct-human activation.

Bind the returned delegation id:

```sh
thelve agent profile bind --name default --delegation-id DELEGATION_UUID
thelve agent capabilities --profile default
```

## Read, plan, and apply

Reads use the deployment's live catalog to prove that the target is a read and
an AI tool. The returned catalog is filtered by actor role, delegator
authority, exact delegation scopes, and AI-tool eligibility:

```sh
printf '{}' | thelve agent invoke \
  --profile default \
  --capability queues.list \
  --resource-type queue \
  --input -
```

Mutations must first freeze a complete contract-valid input:

```sh
thelve agent plan \
  --profile default \
  --capability queues.configure \
  --resource-type queue \
  --resource-id QUEUE_UUID \
  --input queue.json \
  --reason "Create the inbound support queue"
```

After the accountable human directly confirms the complete immutable payload
in Thelve (or a distinct human performs the four-eyes decision required for an
Always/destructive operation):

```sh
thelve agent apply --profile default --approval-id APPROVAL_UUID
```

There is no input argument on `apply`; it executes only the capability,
resource, payload, digest, and idempotency key frozen in the approved record.

## Install the agent integrations

```sh
thelve skill install \
  --target all \
  --profile default \
  --configure-mcp
```

This installs managed `thelve-admin` and `thelve-cloud` skills for Codex and
Claude and registers `thelve mcp serve --profile default` as a local stdio MCP
server. The model receives constrained tools, not the signing seed, a bearer
token, a shell, or generic HTTP.

## Revoke

Revoke the delegation in Tenant Admin to remove its authority. Revoke the key
as well when the workstation or signing material may be compromised. Create a
new profile/key rather than reusing revoked material. These root changes use
an immediate user-authorized human path so incident containment never waits for
a second administrator.
