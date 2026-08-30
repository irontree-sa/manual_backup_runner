# Release Hardening Design

**Status:** approved for planning

## Goal

Repair the release blockers while preserving the one-file Windows deployment: a standard user must neither create nor read an audit log, packaged hash metadata must identify the exact executable, and the implementation must match the specified Trigger-module boundary.

## Scope

- Work only on branch `repair/release-hardening`; do not merge, push, or release.
- Reconcile the local Markdown tracker vocabulary and completion state.
- Remove the production-only logging test hook and incidental timestamp-layout assertion.
- Replace paired policy/resource primitive arguments in execution operations with one typed configured target.
- Move run exit translation, result output, and audit logging behind a Trigger interface.
- Produce artifact-local provenance from a clean committed source revision.
- Verify the exact locally built executable on the Windows Server lab without starting another backup.

## Secure audit-log lifecycle

`ConfigurationStore` remains the sole component that creates and ACL-protects the machine-wide directory. It does so before elevated setup performs network discovery and whenever it saves configuration.

`RotatingLog` never creates the directory. The log is used only by the Trigger module after `CommandHost` has successfully loaded a configured target; failed setup, missing-configuration, lock-contention, and budget-expiry paths do not create an audit log. This prevents a standard user from creating an inherited-access log before setup. Existing configured installations retain their protected directory and log normally.

The production `postAcquire` callback is removed. The lock factory remains injectable because it models real lock acquisition and contention. Tests retain held-lock and lock-creation-failure behavior but remove synthetic release-failure and hook-throwing cases.

## Domain model and Trigger boundary

Add a non-null `ConfiguredTarget` value object containing the policy ID/name and resource ID/name. `TriggerConfiguration` exposes an optional `ConfiguredTarget`; legacy persisted JSON containing the prior four fields is converted on load, while new saves use the target object only.

`IAcronisTransport.GetExecutionStateAsync` and `StartPolicyAsync` accept `ConfiguredTarget`, eliminating the execution-path policy/resource string pair. Resource discovery continues to accept a policy ID because it is not operating on a selected target.

Add `ITrigger` with `RunAsync(TriggerConfiguration, CancellationToken) -> Task<int>`. Its implementation owns the `BackupTrigger` engine, TriggerOutcome-to-exit-code translation, best-effort console result emission, and sanitized audit log emission. `CommandHost` loads configuration and invokes `ITrigger`; it no longer constructs `BackupTrigger`, maps outcomes, or writes run audit records.

## Tracker and artifact provenance

Add `done` to the canonical triage mapping with the meaning “implemented and verified”. Change the primary spec status from `ready-for-agent` to `done`; retain the five completed issue statuses. Remove the stale static hash from ticket 04 and state that a release record must reference the manifest packaged with the exact executable.

`build/publish.sh` requires a clean tracked Git worktree, writes `SHA256SUMS.txt`, and adds `PROVENANCE.txt` containing the source commit, executable filename, and SHA-256. The manifest is generated in the same output directory as the executable and is the sole release-specific hash record. Source documents do not pin a build hash.

## Tests and verification

Use test-first changes for each behavior:

- A log writer with no protected configuration must not create its directory or log.
- A configured run invokes `ITrigger`, and the Trigger module alone maps output, exits, and logging.
- Legacy JSON migration preserves the selected target; a re-save emits only the typed target shape.
- Transport execution calls receive the typed target.
- Concurrent logging asserts durable lines and each payload, not timestamp rendering.
- The publish script rejects dirty tracked state and the manifest SHA matches the emitted executable.

After the branch is clean and committed, publish once, verify the manifest against that exact executable, deploy that artifact to the Windows Server lab, and run `help`, `diagnose`, and `list-policies`. Do not invoke a live backup run without separate explicit approval.

## Non-goals

- No code signing, installer, proxy support, retry redesign, or change to Acronis API behavior.
- No merge to `master`, remote push, release, or live-backup smoke test.
- No generalized Windows ACL framework.
