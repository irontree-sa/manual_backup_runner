# Publication Security Repair Design

**Status:** approved

## Goal

Remove the remaining publication-readiness risks in the renamed `BackupPolicyTrigger` workspace without sending an Acronis request, changing backup semantics, or staging unrelated rename work.

## Scope

- Create trusted Windows named semaphores for machine execution and audit serialization.
- Replace the ACL lab script’s live DPAPI-configuration copy with non-destructive inspection.
- Reconcile the unsigned-artifact ADR with the attestation policy already documented in README.
- Append an evidence-based correction to the stored publication-readiness review.

## Trusted named semaphores

Add a focused Windows-only `NamedSemaphore` factory using `System.Threading.AccessControl`. It creates `Global\BackupPolicyTrigger` and `Global\BackupPolicyTrigger.Log` with a protected DACL granting full control only to `SYSTEM` and the Configuration administrator SID.

When the semaphore already exists, the factory reads its security descriptor and accepts it only when the protected DACL and access rules exactly match the expected descriptor for the current Configuration administrator. A mismatched, inaccessible, or malformed existing object is untrusted.

The machine-run lock fails closed: print a synchronization-security error, return existing `ExitCodes.InternalError` (8), and do not perform any configuration, transport, pending-marker, or backup-start work. A valid, held machine semaphore keeps current behavior and returns `AlreadyRunning` (11) after the bounded wait.

The log semaphore remains best effort. An untrusted or inaccessible log semaphore causes the audit line to be skipped; it never changes the command result. The default factories retain process-local semaphores on non-Windows so deterministic macOS tests remain available.

## ACL lab script

Rewrite `.scratch/lab-acl-test.ps1` to inspect only the deployed `BackupPolicyTrigger` configuration directory and file. It reports owner/DACL and scans the existing encrypted bytes for a caller-provided sentinel only when one is supplied. It does not copy, replace, decrypt, restore, or delete `configuration.dat`; it does not invoke setup or diagnose.

## Publication policy and review record

ADR-0002 becomes explicit: a detached, authenticated release attestation is the publisher-authentication boundary; `SHA256SUMS.txt` and `PROVENANCE.txt` bind the delivered executable only after that attestation is verified. The build remains unsigned and single-file; no code-signing certificate is introduced.

The security review gains an addendum rather than rewriting its historical scan: the old ACL-copy and disclosure findings are stale after the rename/sanitization; the publication finding is controlled by the documented attestation requirement; and the named-object finding is resolved by this change, subject to Windows lab validation.

## Tests and verification

- Add deterministic tests for expected named-semaphore DACL construction and rejection of invalid existing-object descriptors through an injectable factory/security-reader seam.
- Add machine-lock tests proving an untrusted object returns 8 without constructing transport or touching the pending marker; valid held locks still return 11.
- Add log tests proving invalid log-lock security skips the record.
- Run the full suite and publish from a clean archived-HEAD source.
- On the Windows lab, verify creation of both named semaphore DACLs, a valid concurrent-run lock result, and non-destructive ACL script output. Do not invoke a no-argument backup run.

## Non-goals

- No merge, push, release, code signing, retry redesign, or Acronis API change.
- No changes to configuration DPAPI scope, policy/resource selection, pending-marker lifecycle, or no-argument dispatch.
- No staging, resetting, renaming, or otherwise modifying concurrent user-owned workspace changes outside the named files.
