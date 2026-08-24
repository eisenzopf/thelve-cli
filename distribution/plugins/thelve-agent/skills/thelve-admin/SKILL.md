---
name: thelve-admin
description: Safely inspect, configure, provision, and test a deployed Thelve system through its governed AAuth capability API. Use for tenant or platform administration, Telnyx managed-SIP provisioning, queues and agent membership, inbound-call tests, deployment readiness, or any request to change live Thelve configuration with human review.
---

# Thelve Admin

Use the local Thelve MCP tools. They keep the AAuth private key outside the conversation, discover the deployment's live capability catalog, and route every mutation through an immutable human-reviewed plan.

## Workflow

1. Call `thelve_capabilities` before selecting operations. Treat its risk, approval, AI-tool, and schema-digest fields as authoritative.
2. Inspect current state with `thelve_read`. State assumptions and surface readiness failures before proposing changes.
3. Call `thelve_plan` for every mutation. Use a complete exact input and a plain-language reason describing the intended outcome and impact.
4. Stop after proposal. Give the user the approval ID and ask them to review the immutable payload in Thelve's approval inbox. Never call or imitate `approvals.decide`.
5. Use `thelve_plan_read` or `thelve_plan_list` to observe the decision. Do not apply a pending, rejected, expired, or changed plan.
6. Call `thelve_plan_apply` only after the user says the plan was approved. Report the operation receipt and re-read affected state.

Use `confirmation` for an ordinary reversible configuration change by the accountable human. Use `four_eyes` for destructive changes, spend, credential/identity authority, expanded agent autonomy, or whenever the live catalog requires `always`; never downgrade a server-required control.

## Hard boundaries

- Never request, accept, echo, store, or place secret values in a plan. Refer only to server-side secret names or versions. Telnyx and cloud credentials enter through the CLI's hidden secret flow or provider credential tooling, outside the model context.
- Never construct raw HTTP, signatures, bearer tokens, approval IDs, or alternate endpoints. Use only the provided MCP tools.
- Never modify an approved plan. A different input, target, resource, or idempotency key requires a new plan and human decision.
- Never claim a call test passed without the durable inbound-test timeline and explicit human two-way-audio confirmation.
- Read operations may proceed without a plan, but respect tenant isolation and avoid broad evidence/content reads unless necessary for the request.

For tool semantics, enrollment requirements, and the Telnyx test sequence, read [references/capability-plans.md](references/capability-plans.md).
