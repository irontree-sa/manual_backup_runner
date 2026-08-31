# Publication Security Repair Implementation Plan

> **For agentic workers:** Implement the ordered tasks directly. The metadata, lock factory, and callers share one security contract and must not be split across independently editing agents.

**Status:** approved — private deployment identity architecture.

**Goal:** Replace predictable global semaphore names with a validated private deployment identity; remove destructive ACL inspection; and reconcile public publication-security evidence without invoking Acronis or changing the user-owned rename.

**Architecture:** `SynchronizationMetadataStore` owns a `DeploymentIdentity`: an immutable 128-bit deployment identity and Configuration administrator identity. The store validates protected configuration storage before using or creating metadata, publishes complete metadata atomically without replacement, and validates matching owner/DACL and reparse-point safety. `NamedSemaphoreFactory` derives distinct machine and log names with exact domain-separated HMAC construction, creates them with exact protected DACLs, and rejects a pre-existing descriptor mismatch. `Program` fails closed before transport construction; `RotatingLog` remains best effort.

**Tech Stack:** C# 12/.NET 8, `System.Threading.AccessControl` 8.0.0, `System.Security.Cryptography.RandomNumberGenerator`, xUnit, Windows Server PowerShell.

## Global Constraints

- Work in the existing `repair/release-hardening` checkout. The concurrent `BackupPolicyTrigger` rename is user-owned: stage and commit only listed repair files via `git commit --only`.
- Do not merge, push, tag, release, reset, or invoke a no-argument backup run.
- Preserve the static `help` bypass at `src/BackupPolicyTrigger/Program.cs:4-13`; it must not resolve metadata, acquire a lock, read configuration, or construct transport/logging.
- Use at least 128 cryptographically random bits. Never print, audit, diagnose, serialize into public artifacts, or include the identifier/derived names in exception text.
- Use the `Deployment identity` term defined in `CONTEXT.md`; use no deprecated synonym.
- Do not trust a missing, malformed, unreadable, reparse-point, owner/DACL/SID-mismatched configuration directory or synchronization metadata file.
- Legacy migration derives the Configuration administrator SID only from validated pre-existing protected storage. It must never adopt the SID of the account that happens to first run the upgraded executable.
- Setup/reset retain valid synchronization metadata; no casual identity rotation.
- Invalid/inaccessible metadata fails the machine path closed before configuration loading, transport construction, pending-marker work, or Acronis requests. Audit failure remains best effort.
- Follow red/green/refactor and run each focused test before and after implementation.

---

### Task 1: Establish a validated protected-storage identity

**Files:**
- Modify: `src/BackupPolicyTrigger/ConfigurationStore.cs:39-76,181-225`
- Create: `src/BackupPolicyTrigger/SynchronizationMetadataStore.cs`
- Create: `tests/BackupPolicyTrigger.Tests/SynchronizationMetadataStoreTests.cs`
- Modify: `src/BackupPolicyTrigger/BackupPolicyTrigger.csproj`

**Interfaces:**

```csharp
internal sealed record ProtectedStorageIdentity(SecurityIdentifier AdministratorSid);

internal sealed class DeploymentIdentity
{
    public const int ByteLength = 16;
    public static DeploymentIdentity CreateRandom();
    public static DeploymentIdentity FromBytes(ReadOnlySpan<byte> bytes);
    internal ReadOnlySpan<byte> Bytes { get; }
}

internal sealed record SynchronizationMetadata(
    int Version,
    SecurityIdentifier AdministratorSid,
    DeploymentIdentity Identifier);

internal sealed class SynchronizationMetadataStore(string directory)
{
    public SynchronizationMetadata ResolveExisting(ProtectedStorageIdentity identity);
    public SynchronizationMetadata ResolveOrCreateForValidatedStorage(ProtectedStorageIdentity identity);
}
```

`ConfigurationStore` gains one narrow Windows-only helper that validates the pre-existing storage directory and returns `ProtectedStorageIdentity`. It must be used before legacy metadata creation; it is not a configuration-load API.

- [ ] **Step 1: Write failing protected-storage and metadata tests**

Add deterministic tests for:

```csharp
[Fact]
public void ResolveOrCreate_creates_an_immutable_16_byte_deployment_identity_and_persists_it_stably();

[Fact]
public async Task ResolveOrCreate_concurrent_first_use_publishes_one_complete_valid_metadata_record();

[Theory]
[InlineData("corrupt metadata")]
[InlineData("unsupported version")]
public void ResolveExisting_rejects_invalid_metadata_format(string contents);

[Fact]
public void ResolveExisting_rejects_a_metadata_administrator_sid_that_differs_from_validated_storage();

[Fact]
public void ResolveExisting_rejects_a_metadata_or_storage_reparse_point();

[Fact]
public void EnsureProtectedStorage_rejects_a_second_configuration_administrator_without_changing_existing_acls();
```

Do not depend on a Windows kernel object in macOS tests. Use injected filesystem/ACL inspection primitives that report a canonical protected-storage identity, a reparse point, and durable no-overwrite publication outcomes. The concurrency test uses a single fake backing store and two callers: each writes a complete protected temporary record, exactly one atomically publishes it, and both validate the identical completed destination. Verify `DeploymentIdentity.FromBytes` copies input bytes and exposes no mutable array.

- [ ] **Step 2: Run focused tests and observe failure**

```bash
dotnet test tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj --filter "FullyQualifiedName~SynchronizationMetadataStoreTests"
```

Expected: compilation fails because the metadata store and protected-storage identity contract do not exist.

- [ ] **Step 3: Implement secure storage validation**

Add `System.Threading.AccessControl` version `8.0.0` if not already added by the source’s Windows ACL helpers; do not add duplicate package references.

Implement a small internal filesystem/ACL seam, scoped only to metadata tests. The Windows implementation must:

1. Reject any storage directory, temporary metadata file, or published metadata file marked as a reparse point before opening, and recheck after obtaining the handle. Use an open mode that does not follow reparse points; do not implement this as a string-path-only check.
2. Read owner and DACL with `AccessControlSections.Owner | Access`; require DACL protection, owner equal to the Configuration administrator SID, and exactly two non-inherited full-control allow ACEs: `LocalSystemSid` and that administrator. Reuse the existing `ConfigurationStore.Restrict` rule construction rather than creating a second ACL convention.
3. For existing deployments, return the validated directory owner as `ProtectedStorageIdentity.AdministratorSid`. Do not call `WindowsIdentity.GetCurrent()` on this migration path. `EnsureProtectedStorage` must preserve a valid existing owner/DACL; a different Configuration administrator attempting setup/save fails before changing either one.
4. For first-time elevated setup only, create the configuration directory using protected ACLs, then validate it before metadata creation. If the location pre-exists but does not validate, fail rather than repairing or following it.

Store UTF-8 metadata with a version, canonical SID value, and Base64Url encoding of a `DeploymentIdentity`. `CreateRandom` uses `RandomNumberGenerator.GetBytes(DeploymentIdentity.ByteLength)` and `FromBytes` requires exactly 16 bytes while copying them into private immutable storage. Validate exact field presence, version, SID parsing, encoding, and identifier length.

Publish metadata only as follows: create a randomized protected temporary file in the validated directory; write the complete serialized record; call durable `Flush(flushToDisk: true)`; close and validate the temporary handle/ACL; atomically move it within that directory to the fixed metadata destination with no replacement. If the destination exists, discard only the validated temporary file and validate the complete destination; never parse a just-created destination until publication succeeds. Crash-left temporary files are not metadata and may only be removed after their path, reparse state, owner, and DACL are validated. Map malformed, inaccessible, collision, reparse, or ACL failures to one secret-free `SynchronizationMetadataException`.

`SynchronizationMetadataStore.ResolveExisting(identity)` never creates. `ResolveOrCreateForValidatedStorage(identity)` validates existing metadata against the supplied identity, preserves a valid record, and never rotates it. Neither `setup` nor `reset` deletes valid synchronization metadata.

- [ ] **Step 4: Re-run focused tests**

Run the command from Step 2.

Expected: all metadata tests pass. The serialized test data must never contain a derived semaphore name.

### Task 2: Derive and validate private Windows semaphore objects

**Files:**
- Create: `src/BackupPolicyTrigger/NamedSemaphoreFactory.cs`
- Create: `tests/BackupPolicyTrigger.Tests/NamedSemaphoreFactoryTests.cs`
- Modify: `src/BackupPolicyTrigger/BackupPolicyTrigger.csproj`

**Interfaces:**

```csharp
internal sealed class UntrustedNamedSemaphoreException : Exception;

internal sealed class NamedSemaphoreFactory(INamedSemaphoreApi api)
{
    public Semaphore OpenTrusted(
        SynchronizationMetadata metadata,
        SynchronizationLockPurpose purpose);
}

internal enum SynchronizationLockPurpose { MachineRun, AuditLog }
```

- [ ] **Step 1: Write failing lock-name and descriptor tests**

Add tests proving:

```csharp
[Fact]
public void OpenTrusted_derives_distinct_machine_and_log_names_from_one_identifier();

[Fact]
public void OpenTrusted_is_stable_for_the_same_metadata_across_restarts();

[Fact]
public void OpenTrusted_uses_a_protected_system_and_stored_administrator_dacl();

[Fact]
public void OpenTrusted_rejects_a_preexisting_different_or_unreadable_descriptor();
```

A fake `INamedSemaphoreApi` records only a one-way test representation of the requested name; production test output must not write names to console/logs. Assert each name is globally scoped, names differ by purpose and by deployment identity, and names are not the old literal `Global\BackupPolicyTrigger` or `Global\BackupPolicyTrigger.Log`. Assert at least the two required full-control allow ACEs with a protected DACL; reject extra, inherited, deny, or mismatched ACEs.

- [ ] **Step 2: Run focused tests and observe failure**

```bash
dotnet test tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj --filter "FullyQualifiedName~NamedSemaphoreFactoryTests"
```

Expected: compilation failure because the private-name factory, purpose enum, and untrusted-object exception do not exist.

- [ ] **Step 3: Implement derivation and atomic ACL creation**

Derive each name exactly as:

```csharp
var domainLabel = purpose == SynchronizationLockPurpose.MachineRun
    ? "BackupPolicyTrigger/machine/v1"
    : "BackupPolicyTrigger/audit/v1";
var digest = HMACSHA256.HashData(metadata.Identifier.Bytes, Encoding.UTF8.GetBytes(domainLabel));
var name = $"Global\\{Base64Url.Encode(digest)}";
```

`Base64Url.Encode` emits no padding. Tests must assert both fixed labels derive different names from one deployment identity and the same label derives different names from different deployment identities. The identifier and resulting name remain in local variables only; exception text refers only to the lock purpose.

Build a `SemaphoreSecurity` with DACL protection and only non-inherited `SemaphoreRights.FullControl` allow rules for `SYSTEM` and `metadata.AdministratorSid`. Use `SemaphoreAcl.Create(1, 1, name, out createdNew, security)` so ACLs apply during creation. If `createdNew` is false, read access control with `ThreadingAclExtensions.GetAccessControl`, require exact protected-DACL equivalence, and dispose/reject any mismatch. Do not call `SetAccessControl` to repair a pre-existing object.

Convert access/open/type/descriptor failures into `UntrustedNamedSemaphoreException` without including the private name. Retain unnamed, process-local semaphores outside Windows for deterministic tests.

- [ ] **Step 4: Re-run focused tests**

Run the command from Step 2.

Expected: all factory tests pass without exposing names in captured test output.

### Task 3: Wire fail-closed execution and best-effort audit behavior

**Files:**
- Modify: `src/BackupPolicyTrigger/Program.cs:4-88`
- Modify: `src/BackupPolicyTrigger/RotatingLog.cs:10-103`
- Modify: `tests/BackupPolicyTrigger.Tests/RotatingLogTests.cs:89-125`
- Create or modify: `tests/BackupPolicyTrigger.Tests/SynchronizationExecutionTests.cs`

**Interfaces:**
- `Program.cs` resolves existing-or-validated legacy metadata, then opens the private machine semaphore before it constructs `HttpClient`, `CommandHost`, `HttpAcronisTransport`, or `Trigger`.
- `RotatingLog` lazily resolves metadata and opens the private audit semaphore through the same factory. Its `Func<Semaphore>` test seam remains.

- [ ] **Step 1: Write failing caller behavior tests**

Add deterministic tests proving:

```csharp
[Fact]
public async Task Invalid_metadata_returns_internal_error_without_transport_or_pending_marker_work();

[Fact]
public async Task A_valid_held_machine_semaphore_returns_already_running();

[Fact]
public void Invalid_audit_metadata_skips_the_record_without_writing_identifier_material();
```

Factor only the pre-dispatch synchronization gate needed to inject metadata/lock outcomes; do not move command parsing, outcome mapping, or transport behavior into a new general host abstraction. The failure test uses factories that throw if a transport, trigger, or pending-marker operation is attempted.

- [ ] **Step 2: Run focused tests and observe failure**

```bash
dotnet test tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj --filter "FullyQualifiedName~SynchronizationExecutionTests|FullyQualifiedName~RotatingLogTests"
```

Expected: the synchronization gate/caller contract does not exist and the metadata failure path is not yet observable.

- [ ] **Step 3: Wire the production boundary**

Keep the current static help return before all new work. On Windows after that guard:

1. Resolve validated metadata or atomically create it only under the validated legacy configuration-storage rules.
2. Open the private machine lock; on `SynchronizationMetadataException`, `UntrustedNamedSemaphoreException`, documented access/open/type errors, or invalid metadata, write exactly one secret-free error:

   ```text
   Machine synchronization security could not be validated. No backup was requested.
   ```

   Return `ExitCodes.InternalError` (8). Do not create `HttpClient`, `CommandHost`, `HttpAcronisTransport`, `Trigger`, or mutate the pending marker on this branch.
3. Preserve the existing 20-second valid-lock wait and `ExitCodes.AlreadyRunning` (11). Release only if `WaitOne` succeeded.

`RotatingLog` resolves the audit lock lazily. Add metadata/untrusted-lock failures to its existing best-effort failure boundary, producing no directory creation, file append, console output, or identifier material. Valid held/audit failure behavior remains unchanged.

- [ ] **Step 4: Run focused regression tests**

Run the command from Step 2.

Expected: all caller/log tests pass; a valid held machine lock still reports 11, while invalid metadata reports 8 before any external work.

### Task 4: Replace destructive ACL inspection and correct publication evidence

**Files:**
- Modify: `.scratch/lab-acl-test.ps1`
- Modify: `docs/adr/0002-verified-unsigned-executable.md`
- Modify: `docs/security/2026-08-30-publication-readiness-review.md`
- Create: `docs/security/2026-08-30-publication-readiness-review-addendum.md`
- Modify: `.scratch/backup-policy-trigger/issues/06-private-deployment-identity.md`

- [ ] **Step 1: Maintain the canonical tracker record**

Keep the `.scratch` issue `Status: ready-for-agent` while the approved source work is unclaimed. Use the defined `Deployment identity` term, acceptance criteria for private random names, atomic metadata publication, protected-storage identity preservation, no-request failure, and the ADR/review/script work. Link the design and plan. Change its status to `done` only after source and Windows-lab evidence are complete.


- [ ] **Step 2: Replace the lab script with read-only inspection**

Replace every hard-coded `AcronisBackupTrigger` path and all copy/setup/restore/delete behavior in `.scratch/lab-acl-test.ps1`. The new script:

1. Locates `%ProgramData%\BackupPolicyTrigger`, `configuration.dat`, and the synchronization metadata file.
2. Fails clearly when any required item is absent.
3. Prints owner/DACL information only; it never prints configuration, metadata bytes, random identifiers, derived names, or a caller-provided sentinel.
4. If a sentinel is supplied, reports only a Boolean indicating whether its UTF-8 bytes occur in encrypted configuration bytes.
5. Never invokes the executable or copies, moves, decrypts, overwrites, deletes, or restores files.

- [ ] **Step 3: Align the unsigned-artifact policy**

Update ADR-0002 so an authenticated release attestation is the publisher-authentication boundary and binds source commit, executable SHA-256, `SHA256SUMS.txt`, and `PROVENANCE.txt`. A local digest check detects corruption only after authenticating the release; an adjacent checksum cannot establish publisher identity. Preserve the unsigned/single-file decision and the README’s existing attestation prerequisite.

- [ ] **Step 4: Preserve historical review; append corrected evidence**

Add a review addendum linked from the original report. It must state:

- The stale configuration-copy workflow is removed by the read-only replacement.
- The adjacent-checksum finding is controlled by the pre-existing authenticated-attestation policy, now aligned in ADR-0002.
- Fixed-name ACL validation was intentionally superseded because it cannot prove origin; private random names plus DACL validation address named-object precreation, subject to Windows lab evidence.
- The sanitized public-data-disclosure finding was not reproduced.

Do not rewrite historical scan evidence/severity in place, and never name or reproduce the private metadata/derived semaphore values.

- [ ] **Step 5: Review the documentation/script diff**

Read the five outputs. Verify the tracker uses the domain glossary, the script has no mutation command, publication instructions always require attestation before digest comparison, and all review text remains secret-free.

### Task 5: Verify source, artifact, and Windows ACL behavior

**Files:**
- Verify: all listed source, test, script, tracker, and documentation files
- Verify: `build/publish.sh`

- [ ] **Step 1: Run the full test suite**

```bash
dotnet test tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj
```

Expected: all tests pass.

- [ ] **Step 2: Publish and verify the complete manifest-covered artifact set**

The active checkout is intentionally dirty with user-owned rename work. Create a temporary clean clone/worktree at the security-repair commit and run:

```bash
./build/publish.sh
```

Expected: the release directory contains the complete manifest-covered artifact set: executable, `SHA256SUMS.txt`, `PROVENANCE.txt`, and every required license or notice. Verify every entry in `SHA256SUMS.txt` against its corresponding file; confirm no required release file is omitted from the manifest; then confirm `PROVENANCE.txt` records the repair commit. Do not publish from the dirty checkout.

- [ ] **Step 3: Windows Server lab—no backup request**

After release-attestation verification and deployment of the complete manifest-covered artifact set:

1. Run `help` and verify it still requires no metadata/configuration/lock access.
2. Run the revised ACL script as the Configuration administrator and verify it reports ACLs without file mutation or metadata disclosure.
3. Inspect the metadata file with an Administrator-created helper: verify protected owner/DACL, correct stored administrator SID, and an identifier length of at least 16 bytes without printing it.
4. Inspect both derived semaphores only through a helper that receives metadata locally; verify protected DACLs contain exactly `SYSTEM` and the stored administrator full-control allow rules. Do not print names.
5. Hold a valid machine semaphore with the helper, invoke a harmless permitted command, confirm bounded contention exits 11, then release/dispose it.
6. As a standard user, verify metadata and configuration remain inaccessible and neither semaphore can be opened or created from the unknown name.

Do not invoke `setup`, `reset`, `select-target`, `list-policies`, `list-resources`, or a no-argument backup run without separate approval.

- [ ] **Step 4: Commit only repair-owned paths**

Use explicit pathspec commits. Do not stage user-owned rename files:

```bash
git add src/BackupPolicyTrigger/ConfigurationStore.cs \
        src/BackupPolicyTrigger/SynchronizationMetadataStore.cs \
        src/BackupPolicyTrigger/NamedSemaphoreFactory.cs \
        src/BackupPolicyTrigger/Program.cs \
        src/BackupPolicyTrigger/RotatingLog.cs \
        src/BackupPolicyTrigger/BackupPolicyTrigger.csproj \
        tests/BackupPolicyTrigger.Tests/SynchronizationMetadataStoreTests.cs \
        tests/BackupPolicyTrigger.Tests/NamedSemaphoreFactoryTests.cs \
        tests/BackupPolicyTrigger.Tests/SynchronizationExecutionTests.cs \
        tests/BackupPolicyTrigger.Tests/RotatingLogTests.cs
git commit --only -m "fix: use private validated synchronization names" -- <same source/test paths>

git add .scratch/lab-acl-test.ps1 docs/adr/0002-verified-unsigned-executable.md \
        docs/security/2026-08-30-publication-readiness-review.md \
        docs/security/2026-08-30-publication-readiness-review-addendum.md
git commit --only -m "docs: record publication security controls" -- <same documentation paths>
```

Do not merge, push, tag, or release.
