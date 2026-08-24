# Governed capability plans

## Required enrollment

An operator creates an AAuth profile and public JWK with `thelve agent profile create`, registers that public key and AI identity in the deployed system, creates a bounded delegation, has a distinct authorized human approve that delegation, and binds its ID with `thelve agent profile bind`.

Recommended administration scopes include `capabilities.list`, `approvals.request`, `approvals.read`, `approvals.list`, and only the exact read/write capabilities needed for the task. Set short expiry, resource constraints, and an invocation quota.

## MCP tools

- `thelve_capabilities`: live catalog discovery.
- `thelve_read`: catalog-enforced reads only.
- `thelve_plan`: writes an immutable approval record; it does not run the target.
- `thelve_plan_read` and `thelve_plan_list`: decision recovery and polling.
- `thelve_plan_apply`: verifies the frozen input digest and executes only the approved target.

The approval policy binds capability, resource type, optional resource ID, complete JSON input, RFC 8785 input SHA-256, and the target idempotency key. The approval is single-use; a retry with the same idempotency key is allowed.

## Telnyx inbound-call acceptance

Inspect managed-SIP readiness first. Then propose the smallest plans needed to bootstrap telephony, order or attach the DID, configure the queue, create and enable the human membership, and assign the DID. Verify an eligible human has live available voice presence and browser media readiness before arming an inbound test.

The caller manually dials the DID. Follow durable events through SIP admission, queue offer, browser media, human acceptance, gateway bridge, and completion. A human must explicitly confirm two-way audio. Do not infer audio success from signaling alone.

Secret values are never capability input. Use a secret reference already populated by the operator.
