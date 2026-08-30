# Publication Security Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` only if the approved work can be split without shared-file overlap; otherwise implement the ordered tasks in this plan directly.

**Status:** superseded — fixed-name ACL validation cannot prevent same-DACL object squatting; do not execute.

**Goal:** Eliminate untrusted Windows named-semaphore use, remove the destructive ACL lab workflow, and align publication policy/review evidence without issuing an Acronis request or disturbing the user-owned `BackupPolicyTrigger` rename.

**Architecture:** A small `NamedSemaphoreFactory` owns Windows ACL creation and validation. It returns a semaphore only when its protected DACL exactly grants `SYSTEM` and the configured Configuration administrator full control. `Program.cs` treats a factory failure as a fail-closed machine-run error before transport/configuration work. `RotatingLog` treats the same failure as a best-effort skipped audit. The source-review record is corrected by an addendum, rather than overwriting historical findings.

**Tech Stack:** C# 12/.NET 8, `System.Threading.AccessControl` 8.0.0, xUnit, Bash, Windows Server PowerShell.

## Global Constraints

- Work on the existing `repair/release-hardening` checkout. Its 33 staged and 37 unstaged rename changes are user-owned; stage and commit only named security-repair files with `git commit --only`.
- Do not merge, push, release, reset, or invoke a no-argument backup run.
- `help` remains static and bypasses locking, configuration, logging, transport, and elevation.
- Machine-run semaphore validation fails closed with the existing internal-error exit code 8; it must precede `HttpClient`, `CommandHost`, and `ITrigger` construction.
- Audit logging remains best effort: an unavailable or untrusted log semaphore skips only that audit record.
- Standard users must not create, read, or alter either named semaphore.
- Follow red/green/refactor: run each new focused test before implementation and again after the change.

---

### Task 1: Add a validated named-semaphore boundary

**Files:**
- Create: `src/BackupPolicyTrigger/NamedSemaphoreFactory.cs`
- Modify: `src/BackupPolicyTrigger/BackupPolicyTrigger.csproj`
- Create: `tests/BackupPolicyTrigger.Tests/NamedSemaphoreFactoryTests.cs`

**Interfaces:**

```csharp
public sealed class UntrustedNamedSemaphoreException : Exception;

public interface INamedSemaphoreApi
{
    Semaphore Create(string name, SemaphoreSecurity security, out bool createdNew);
    SemaphoreSecurity GetSecurity(Semaphore semaphore);
}

public sealed class NamedSemaphoreFactory(INamedSemaphoreApi api)
{
    public Semaphore OpenTrusted(string name, SecurityIdentifier administratorSid);
}
```

The production `INamedSemaphoreApi` calls `SemaphoreAcl.Create(1, 1, name, out createdNew, security)` and `semaphore.GetAccessControl()`. Its use remains behind `OperatingSystem.IsWindows()`; callers supply process-local `new Semaphore(1, 1)` outside Windows.

- [ ] **Step 1: Write failing descriptor and rejection tests**

Add tests covering these observable contracts:

```csharp
[Fact]
public void OpenTrusted_creates_a_protected_dacl_for_system_and_configuration_administrator();

[Fact]
public void OpenTrusted_rejects_an_existing_semaphore_with_a_different_dacl();

[Fact]
public void OpenTrusted_rejects_an_existing_semaphore_when_its_dacl_cannot_be_read();
```

Use a fake `INamedSemaphoreApi` that records the requested `SemaphoreSecurity`, returns a controlled `createdNew` value, and supplies a synthetic `SemaphoreSecurity` for existing objects. Assert the expected access-section SDDL has a protected DACL (`P`) and exactly two allow ACEs, each with `SemaphoreRights.FullControl`: built-in `SYSTEM` (`S-1-5-18`) and the supplied Configuration administrator SID. Do not assert ACE ordering.

- [ ] **Step 2: Run the focused tests and observe failure**

Run:

```bash
dotnet test tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj --filter "FullyQualifiedName~NamedSemaphoreFactoryTests"
```

Expected: compilation failure because the factory/API/exception do not exist.

- [ ] **Step 3: Implement atomic creation and exact existing-descriptor validation**

Add `System.Threading.AccessControl` version `8.0.0` to the executable project. In `NamedSemaphoreFactory`:

1. Construct a `SemaphoreSecurity`; enable DACL protection; add only non-inherited full-control `SemaphoreAccessRule`s for `LocalSystemSid` and the configured Configuration administrator SID.
2. Use `SemaphoreAcl.Create` so the descriptor is installed at object creation—never create then call `SetAccessControl`.
3. If `createdNew` is false, read the existing descriptor with `ThreadingAclExtensions.GetAccessControl`; reject if its protected access-section DACL differs from the expected descriptor. Treat `UnauthorizedAccessException`, `IOException`, `WaitHandleCannotBeOpenedException`, or malformed descriptor data as `UntrustedNamedSemaphoreException`; dispose the acquired handle before throwing.
4. Return the handle only after validation. Do not repair an existing object’s ACL: an attacker-created object is unsafe even if it could be overwritten.

Keep the API seam internal to the executable and expose it to the test assembly through the project’s existing `InternalsVisibleTo` convention if one exists; otherwise add one narrow assembly attribute. Do not introduce a general-purpose security abstraction.

- [ ] **Step 4: Re-run focused tests**

Run the command from Step 2.

Expected: all named-semaphore factory tests pass on macOS because the tests exercise fake ACL API objects, not Windows kernel objects.

### Task 2: Fail closed for runs and preserve best-effort audit logging

**Files:**
- Modify: `src/BackupPolicyTrigger/Program.cs:21-88`
- Modify: `src/BackupPolicyTrigger/RotatingLog.cs:10-103`
- Modify: `tests/BackupPolicyTrigger.Tests/RotatingLogTests.cs:89-125`
- Create or modify: `tests/BackupPolicyTrigger.Tests/NamedSemaphoreFactoryTests.cs`

**Interfaces:**
- `Program.cs` uses `NamedSemaphoreFactory.OpenTrusted("Global\\BackupPolicyTrigger", configuredAdministratorSid)` only after the Windows platform guard and before it creates `HttpClient`/`CommandHost`.
- `RotatingLog.CreateDefaultLock` delegates to the same factory with `"Global\\BackupPolicyTrigger.Log"`; its injectable `Func<Semaphore>` test seam remains.

- [ ] **Step 1: Add failing machine-lock and audit failure tests**

Add a factory test that an untrusted existing machine semaphore produces `UntrustedNamedSemaphoreException`, not a usable `Semaphore`.

Add this log regression test:

```csharp
[Fact]
public void Write_skips_the_audit_line_when_the_named_semaphore_is_untrusted()
{
    var log = new RotatingLog(directory,
        lockFactory: () => throw new UntrustedNamedSemaphoreException("descriptor mismatch"));

    log.Write("run: exit=0 outcome=ObservedRunning");

    Assert.False(File.Exists(Path.Combine(directory, "trigger.log")));
}
```

- [ ] **Step 2: Run the focused tests and observe failure**

Run:

```bash
dotnet test tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj --filter "FullyQualifiedName~NamedSemaphoreFactoryTests|FullyQualifiedName~RotatingLogTests"
```

Expected: the new exception type and factory behavior are absent; the log test cannot compile or does not skip.

- [ ] **Step 3: Wire production callers**

In `Program.cs`, derive the Configuration administrator SID with `WindowsIdentity.GetCurrent().User` only for the elevated Configuration user. If the security factory cannot create or validate the machine semaphore, write exactly one secret-free error to `Console.Error` such as:

```
Machine synchronization security could not be validated. No backup was requested.
```

Return `ExitCodes.InternalError` (8). Do not instantiate `HttpClient`, `CommandHost`, `HttpAcronisTransport`, or `Trigger` on this branch; do not write a log record.

Use a `lockAcquired` flag so `Release()` occurs only after a successful `WaitOne`; retain the existing 20-second contention behavior and exit 11. Catch only the named-security exception and documented named-object access/open errors; do not turn unrelated programming errors into a false success.

In `RotatingLog`, add `UntrustedNamedSemaphoreException` to the existing factory-failure catch filter. Its default factory must obtain the same Configuration administrator SID and use the shared factory on Windows; retain the local unnamed semaphore on non-Windows. A rejected log semaphore returns without creating a directory or writing an audit line.

- [ ] **Step 4: Run focused regression tests**

Run the command from Step 2.

Expected: factory tests and all rotating-log tests pass; held valid semaphores continue to skip promptly and concurrent valid writers remain serialized.

### Task 3: Replace destructive ACL inspection and align publication evidence

**Files:**
- Modify: `.scratch/lab-acl-test.ps1`
- Modify: `docs/adr/0002-verified-unsigned-executable.md`
- Modify: `docs/security/2026-08-30-publication-readiness-review.md`
- Create: `docs/security/2026-08-30-publication-readiness-review-addendum.md`

- [ ] **Step 1: Write the non-destructive lab inspector**

Replace every hard-coded `AcronisBackupTrigger` path and the copy/setup/restore/delete workflow in `.scratch/lab-acl-test.ps1`. The replacement:

1. Computes `%ProgramData%\\BackupPolicyTrigger` and `configuration.dat`.
2. Fails clearly if the directory/configuration file is absent.
3. Prints only the directory/file owner and access rules from `Get-Acl`—never file contents.
4. Accepts an optional sentinel string and, when supplied, reports only whether its UTF-8 bytes appear in the encrypted file; it must not print the sentinel or ciphertext.
5. Does not call the executable, copy, move, decrypt, overwrite, delete, or restore any file.

- [ ] **Step 2: Reconcile the authenticated-publication policy**

Update ADR-0002 to distinguish the controls:

- The release attestation obtained from the authenticated project release page authenticates the publisher and binds source commit, executable SHA-256, `SHA256SUMS.txt`, and `PROVENANCE.txt`.
- Local checksum comparison detects post-authentication corruption only; an adjacent `SHA256SUMS.txt` cannot authenticate an attacker-controlled directory.
- The project remains unsigned; code signing is explicitly out of scope for this release.

Do not weaken the existing README’s attestation requirement or add a bare checksum-only installation path.

- [ ] **Step 3: Append evidence; preserve historical record**

Create the addendum with references to the reviewed revision and this repair’s commit. Record:

- The old configuration-copy finding was tied to the stale `AcronisBackupTrigger` lab script and is removed by the read-only replacement.
- The original adjacent-checksum finding is mitigated by the existing authenticated-attestation policy; ADR-0002 now states the same boundary.
- The named-semaphore finding is remediated in code, but final closure requires the Windows lab checks in Task 5.
- The public-data-disclosure finding was not reproduced in the sanitized repository.

Modify the original review only to add a prominent pointer to the addendum; do not revise its original evidence or severity claims in place.

- [ ] **Step 4: Review documentation and script diff**

Read the four resulting files. Confirm no script operation mutates `configuration.dat`, no credential/ciphertext material is emitted, and every publication-verification statement requires authenticated attestation before digest comparison.

### Task 4: Verify source, artifact, and Windows ACL behavior

**Files:**
- Verify: all security-repair files above
- Verify: `build/publish.sh`

- [ ] **Step 1: Run the full test suite**

Run:

```bash
dotnet test tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj
```

Expected: all tests pass.

- [ ] **Step 2: Publish from a clean archived source revision**

Because the active checkout intentionally contains user-owned changes, create a temporary clean clone/worktree at the security-repair commit and run:

```bash
./build/publish.sh
```

Expected: `BackupPolicyTrigger.exe`, `SHA256SUMS.txt`, and `PROVENANCE.txt` are emitted; the script reports the archived source revision. Verify the executable digest against `SHA256SUMS.txt` and ensure `PROVENANCE.txt` names the security-repair commit. Do not publish from the dirty active checkout.

- [ ] **Step 3: Windows Server lab, no backup run**

After copying only the verified three-file artifact set to the Windows lab:

1. Verify the authenticated release attestation before relying on the digest.
2. Run `help` and `diagnose`; do not invoke a no-argument command.
3. Run the revised `.scratch/lab-acl-test.ps1` as the Configuration administrator and verify it performs no configuration mutation.
4. Inspect `Global\\BackupPolicyTrigger` and `Global\\BackupPolicyTrigger.Log` with an Administrator-created helper only; verify each DACL contains only `SYSTEM` and the Configuration administrator full-control allow rules and is protected.
5. Hold the valid machine semaphore in a helper, run a harmless interactive command, and confirm bounded lock contention returns 11. Release and dispose the helper semaphore.
6. As a standard user, confirm opening/creating either named semaphore fails and the configuration/log paths remain inaccessible.

Do not invoke `setup`, `select-target`, `list-policies`, `list-resources`, or a backup start unless separately approved.

- [ ] **Step 4: Commit only owned files**

Use explicit pathspec commits so the concurrent rename changes remain untouched:

```bash
git add src/BackupPolicyTrigger/NamedSemaphoreFactory.cs \
        src/BackupPolicyTrigger/Program.cs \
        src/BackupPolicyTrigger/RotatingLog.cs \
        src/BackupPolicyTrigger/BackupPolicyTrigger.csproj \
        tests/BackupPolicyTrigger.Tests/NamedSemaphoreFactoryTests.cs \
        tests/BackupPolicyTrigger.Tests/RotatingLogTests.cs
git commit --only -m "fix: validate named semaphore ACLs" -- <same source/test paths>

git add .scratch/lab-acl-test.ps1 docs/adr/0002-verified-unsigned-executable.md \
        docs/security/2026-08-30-publication-readiness-review.md \
        docs/security/2026-08-30-publication-readiness-review-addendum.md
git commit --only -m "docs: record publication security controls" -- <same documentation paths>
```

Do not merge, push, tag, or release.
