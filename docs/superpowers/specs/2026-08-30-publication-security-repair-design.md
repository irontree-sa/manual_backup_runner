# Publication Security Repair Design

**Status:** approved — revised random-name architecture

## Goal

Remove the remaining publication-readiness risks in the renamed `BackupPolicyTrigger` workspace without sending an Acronis request, changing backup semantics, or staging unrelated rename work.

## Scope

- Create trusted Windows named semaphores for machine execution and audit serialization.
- Replace the ACL lab script’s live DPAPI-configuration copy with non-destructive inspection.
- Reconcile the unsigned-artifact ADR with the attestation policy already documented in README.
- Append an evidence-based correction to the stored publication-readiness review.

## Private named semaphores

Fixed global names cannot establish their creator: a low-privilege process can precreate an object with the expected DACL and retain its creator handle. The application instead uses a cryptographically random, per-installation identifier that only authorized accounts can read.

`SynchronizationMetadataStore` stores a version, Configuration administrator SID, and at least 128 random bits from `RandomNumberGenerator` inside the protected configuration directory. It creates the metadata atomically with `FileMode.CreateNew`, then applies the same protected owner/DACL model as configuration storage: only `SYSTEM` and the stored administrator receive full control. The identifier and all derived semaphore names are secret operational metadata: they must never be printed, logged, diagnosed, or included in review evidence.

Before metadata is trusted, the store rejects directory or metadata reparse points, validates the protected owner/DACL, validates the serialized version/SID/random-byte format, and requires the stored SID to match the validated Configuration administrator. Existing installations derive that administrator from validated pre-existing protected storage; they must not bind it to whichever account first invokes the upgraded executable. Missing legacy metadata is created atomically only after this validation. Setup and reset retain a valid identifier rather than rotating it casually.

`NamedSemaphoreFactory` derives distinct machine and log names from the private identifier using fixed domain labels. It uses `System.Threading.AccessControl` to create each Windows semaphore with a protected DACL granting full control only to `SYSTEM` and the stored Configuration administrator SID. For an existing derived object, it requires an exact protected-DACL match; a mismatched, inaccessible, malformed, or wrong-type object is untrusted. Random names prevent a low-privilege account from guessing the object before creation; DACL validation limits use if a name is later disclosed.

The machine-run lock fails closed: print a synchronization-security error, return existing `ExitCodes.InternalError` (8), and do not perform configuration loading, transport construction, pending-marker changes, or a backup start. A valid, held machine semaphore keeps current behavior and returns `AlreadyRunning` (11) after the bounded wait.

The log semaphore remains best effort. Untrusted/inaccessible metadata or a log semaphore skips that audit line only. The default factories retain process-local semaphores on non-Windows so deterministic macOS tests remain available.

## ACL lab script

Rewrite `.scratch/lab-acl-test.ps1` to inspect only the deployed `BackupPolicyTrigger` configuration directory and file. It reports owner/DACL and scans the existing encrypted bytes for a caller-provided sentinel only when one is supplied. It does not copy, replace, decrypt, restore, or delete `configuration.dat`; it does not invoke setup or diagnose.

## Publication policy and review record

ADR-0002 becomes explicit: a detached, authenticated release attestation is the publisher-authentication boundary; `SHA256SUMS.txt` and `PROVENANCE.txt` bind the delivered executable only after that attestation is verified. The build remains unsigned and single-file; no code-signing certificate is introduced.

The security review gains an addendum rather than rewriting its historical scan: the old ACL-copy and disclosure findings are stale after the rename/sanitization; the publication finding is controlled by the documented attestation requirement; and the named-object finding is resolved by this change, subject to Windows lab validation.

## Tests and verification

- Add deterministic tests for 128-bit metadata generation, atomic concurrent first use, stable restart identity, reparse/ACL/SID/format rejection, and distinct derived machine/log names.
- Add factory tests for expected named-semaphore DACL construction and rejection of invalid existing-object descriptors through an injectable security-reader seam.
- Add machine-lock tests proving invalid metadata or an untrusted object returns 8 without constructing transport or touching the pending marker; valid held locks still return 11.
- Add log tests proving invalid metadata/log-lock security skips the record and never emits the identifier.
- Run the full suite and publish from a clean archived-HEAD source.
- On the Windows lab, verify the protected metadata file and creation of both derived semaphore DACLs, a valid concurrent-run lock result, and non-destructive ACL script output. Do not invoke a no-argument backup run.

## Non-goals

- No merge, push, release, code signing, retry redesign, or Acronis API change.
- No changes to configuration DPAPI scope, policy/resource selection, pending-marker lifecycle, or no-argument dispatch.
- No staging, resetting, renaming, or otherwise modifying concurrent user-owned workspace changes outside the named files.
