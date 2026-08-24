---
name: thelve-cloud
description: Deploy and operate Thelve's secure single-node target in a customer-owned GCP project or AWS account with the compiled thelve CLI. Use for cloud prerequisites, compute selection, Terraform planning, secret-manager population, start, pause, resume, status, recovery, or teardown of a Thelve test or production server.
---

# Thelve Cloud

Use the compiled `thelve` CLI and the operator's existing `gcloud` or `aws` identity. The workstation is a control client; Thelve workloads run only on the remote cloud host.

## Workflow

1. Run `thelve doctor` for the selected provider and resolve every failed prerequisite.
2. Create or inspect the non-secret deployment intent. Verify release, image, region, compute profile, public DNS, SIP/RTP network ranges, backups, and logging before mutation.
3. Bootstrap remote state, then run `thelve deploy plan`. Summarize material resources, cost-bearing choices, network exposure, and destructive replacements.
4. Ask the human to approve that exact operation. Add `--approve` only after explicit approval in the current interaction. Destroy also requires the exact deployment-name confirmation.
5. Put secret values directly into GCP Secret Manager or AWS Secrets Manager with `thelve secret set`; use its hidden prompt or an authorized stdin source. Never solicit a secret in chat or place one in argv, YAML, Terraform variables, logs, or a plan.
6. Run the requested lifecycle command, then verify `status`, readiness, logging, backup, and security evidence. Infrastructure success is not Telnyx or browser-call readiness.

Prefer pause/resume for temporary test clusters. Do not destroy persistent disks, addresses, secret versions, state buckets, backups, or DIDs unless the user's request explicitly includes that irreversible scope.

Read [references/cloud-operations.md](references/cloud-operations.md) before the first mutation or when provider behavior is uncertain.
