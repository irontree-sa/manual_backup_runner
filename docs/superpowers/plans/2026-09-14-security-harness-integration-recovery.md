# Security Harness Integration Recovery Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce one clean `BackupPolicyTrigger` branch containing the private deployment-identity security work, the Windows verification harness, and a passing release pipeline, without modifying the dirty `repair/release-hardening` checkout.

**Architecture:** Start from `verify/windows-harness`, which contains the committed security and harness work. Complete the unfinished project migration by making `BackupPolicyTrigger` the sole application/test project and merging the retained legacy application surface with the committed synchronization implementations. Treat the dirty `repair/release-hardening` tree only as a read-only source for the independent `DeploymentIdentity` value object and its tests; never stage, reset, or edit it.

**Tech Stack:** C# 12/.NET 8, xUnit, Windows ACL APIs, `dotnet test`, Bash, GitHub Actions.

## Global Constraints

- Work only in an isolated recovery worktree; preserve the dirty `repair/release-hardening` checkout unchanged.
- `help` remains before startup synchronization and succeeds without Windows, configuration, transport, or locks.
- Unelevated `setup` returns `ExitCodes.AdministratorRequired` before protected-storage, metadata, semaphore, or dispatch work.
- Synchronization validation failure returns secret-free exit 8 before dispatch; valid contention returns exit 11 without dispatch.
- The deployment identity is a stable, private 128-bit random value that is never logged, diagnosed, or exposed through the harness.
- The Windows harness uses only randomized children below its own temporary root and never touches production storage, Acronis, credentials, pending markers, or installed binaries.
- Do not invoke a no-argument backup run or any live Acronis operation.
- Do not push, merge, or release before the complete test/review gate passes.

---

## Recovery inputs

- Committed security/harness source: `verify/windows-harness` at `6a76c685811596fd8328330d7fb3db65851d1b01`.
- Original dirty source: `repair/release-hardening` at `1922673a1f9e8e5f200c29d46b8b2c224992c1df`.
- Original checkout preservation proof: the pre- and post-recovery `git status --porcelain=v2 --branch` SHA-256 values are both `e28ad7474b7f4fea63fe5e30e241b53ace48d1f3e416e4488e2ce1b3c6065822`.

### Task 1: Create the canonical recovery branch and record the two inputs

**Files:**
- Create: `docs/superpowers/plans/2026-09-14-security-harness-integration-recovery.md`
- Preserve unchanged: the original dirty `repair/release-hardening` worktree

**Interfaces:**
- Consumes: `verify/windows-harness` as the committed security/harness input.
- Consumes read-only: `repair/release-hardening` for `DeploymentIdentity.cs` and `DeploymentIdentityTests.cs`.
- Produces: `recovery/security-harness-integration`, the only branch edited by this plan.

- [ ] **Step 1: Create the recovery branch from the committed harness branch**

```bash
git switch -c recovery/security-harness-integration verify/windows-harness
```

Expected: `git status --porcelain=v2 --branch` reports `branch.head recovery/security-harness-integration` and no dirty entries before the plan file is added.

- [ ] **Step 2: Record exact input commits and prove the old dirty tree is untouched**

```bash
git rev-parse verify/windows-harness
git -C /Users/nicholaskeene/Documents/Work/Code/acronis_start_backup_script status --porcelain=v2 --branch
```

Expected: the input commit is `6a76c685811596fd8328330d7fb3db65851d1b01`; the original checkout retains its existing dirty staged/untracked state.

- [ ] **Step 3: Commit the recovery plan before production changes**

```bash
git add docs/superpowers/plans/2026-09-14-security-harness-integration-recovery.md
git commit -m "docs: plan security harness integration recovery"
```

### Task 2: Complete the project migration without duplicating application code

**Files:**
- Move: `src/AcronisBackupTrigger/` → `src/BackupPolicyTrigger/`
- Move: `tests/AcronisBackupTrigger.Tests/` → `tests/BackupPolicyTrigger.Tests/`
- Modify: `BackupPolicyTrigger.sln`
- Delete after migration: `AcronisBackupTrigger.sln`, `src/AcronisBackupTrigger/`, `tests/AcronisBackupTrigger.Tests/`
- Preserve: committed security/harness files already under `src/BackupPolicyTrigger/`, `tests/BackupPolicyTrigger.Tests/`, and `tools/BackupPolicyTrigger.WindowsVerification/`

**Interfaces:**
- Produces: exactly one application project, `src/BackupPolicyTrigger/BackupPolicyTrigger.csproj`.
- Produces: exactly one xUnit project, `tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj`.
- Produces: application namespace `BackupPolicyTrigger` and test namespace `BackupPolicyTrigger.Tests`.
- Consumes: `BackupPolicyTrigger.WindowsVerification.csproj` from the existing `tools/` directory.

- [ ] **Step 1: Inventory overlap before moving files**

```bash
git ls-files src/AcronisBackupTrigger tests/AcronisBackupTrigger.Tests
git ls-files src/BackupPolicyTrigger tests/BackupPolicyTrigger.Tests tools/BackupPolicyTrigger.WindowsVerification
```

Expected: `Program.cs`, `AdministratorGate.cs`, and `ConfigurationStore.cs` are intentional source overlaps; security implementations already in the destination remain authoritative.

- [ ] **Step 2: Move only legacy files that do not have an authoritative security replacement**

Move the legacy project file, application files such as `BackupTrigger.cs`, `CommandHost.cs`, `Diagnostics.cs`, `Discovery.cs`, `HelpContent.cs`, `HttpAcronisTransport.cs`, `PendingStartStore.cs`, `RotatingLog.cs`, and `Trigger.cs`, plus their non-overlapping test counterparts, into the new project directories. The verified pre-move listing and all reachable history contain no `src/AcronisBackupTrigger/packages.lock.json` or `Properties/**`; do not fabricate replacements. Do not overwrite destination `Program.cs`, `AdministratorGate.cs`, `ConfigurationStore.cs`, `SynchronizationMetadataStore.cs`, `NamedSemaphoreFactory.cs`, or `StartupSynchronizationGate.cs`.

- [ ] **Step 3: Rename the root application namespace with the C# language server**

After the moves, target the root `AcronisBackupTrigger` namespace identifier in `BackupTrigger.cs` (line 3, as required by the 1-indexed `xd://lsp` schema). Inspect the single project-aware preview and require it to include the nested test namespace edits before applying it:

```text
write xd://lsp {"action":"rename","file":"src/BackupPolicyTrigger/BackupTrigger.cs","line":3,"symbol":"AcronisBackupTrigger","new_name":"BackupPolicyTrigger","apply":false}
write xd://lsp {"action":"rename","file":"src/BackupPolicyTrigger/BackupTrigger.cs","line":3,"symbol":"AcronisBackupTrigger","new_name":"BackupPolicyTrigger","apply":true}
```

If `xd://lsp` is unavailable, either operation fails, or the preview or applied edit omits any source, test, or project reference, use the deterministic fallback. First enumerate every legacy source, test, and project reference in deterministic path-and-line order with the harness built-in `grep` tool. Set `gitignore:false` so the scan includes untracked moved destination files:

```text
grep {"i":"Enumerating legacy references","pattern":"\\bAcronisBackupTrigger(\\.Tests)?\\b","path":"src;tests;**/*.csproj;**/*.sln","case":true,"gitignore":false,"skip":0}
```

Rename every emitted C# namespace declaration, `using` directive, and qualified reference; every `.csproj` assembly name, root namespace, project reference, and path; and every `.sln` project display name and path. Re-run the enumeration and require no output, then run:

```bash
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo
```

Use the language-server route only when its preview and applied edits are complete; otherwise use the fallback.

- [ ] **Step 4: Repair the solution membership**

`BackupPolicyTrigger.sln` must list exactly these projects and real paths:

```text
src/BackupPolicyTrigger/BackupPolicyTrigger.csproj
tests/BackupPolicyTrigger.Tests/BackupPolicyTrigger.Tests.csproj
tools/BackupPolicyTrigger.WindowsVerification/BackupPolicyTrigger.WindowsVerification.csproj
```

Remove all configuration and nested-project entries for GUIDs that are not declared by a `Project(...)` block. Delete `AcronisBackupTrigger.sln` once the new solution is the canonical entry point.

- [ ] **Step 5: Run the migrated baseline suite**

```bash
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo
```

Expected: compilation succeeds far enough to expose only missing deployment-identity integration, not missing paths, namespaces, malformed solution entries, or duplicate source declarations.

- [ ] **Step 6: Commit the coherent project migration**

Before the final `git add`, scan the working-tree destination directories (including untracked moved files) and require no legacy namespace references:

```text
grep {"i":"Checking moved namespaces","pattern":"\\bAcronisBackupTrigger(\\.Tests)?\\b","path":"src/BackupPolicyTrigger;tests/BackupPolicyTrigger.Tests","case":true,"gitignore":false,"skip":0}
```

Then stage and commit the coherent migration:

```bash
git add BackupPolicyTrigger.sln src tests tools
git commit -m "refactor: unify backup trigger project layout"
```

### Task 3: Integrate the private deployment identity and startup synchronization contract

**Files:**
- Create: `src/BackupPolicyTrigger/DeploymentIdentity.cs`
- Create: `tests/BackupPolicyTrigger.Tests/DeploymentIdentityTests.cs`
- Modify only as compiler-guided integration requires: `src/BackupPolicyTrigger/SynchronizationMetadataStore.cs`, `src/BackupPolicyTrigger/NamedSemaphoreFactory.cs`, `src/BackupPolicyTrigger/StartupSynchronizationGate.cs`, `src/BackupPolicyTrigger/Program.cs`
- Test: `tests/BackupPolicyTrigger.Tests/SynchronizationMetadataStoreTests.cs`, `tests/BackupPolicyTrigger.Tests/NamedSemaphoreFactoryTests.cs`, `tests/BackupPolicyTrigger.Tests/StartupSynchronizationGateTests.cs`

**Interfaces:**
- Produces: `DeploymentIdentity.CreateRandom()` with exactly 16 random bytes.
- Produces: `DeploymentIdentity.FromBytes(ReadOnlySpan<byte>)`, rejecting every length except 16.
- Consumes: `SynchronizationMetadata.Identifier` and `NamedSemaphoreFactory.DeriveName(DeploymentIdentity, SynchronizationLockPurpose)`.
- Preserves: the committed `StartupSynchronizationGate` as the single dispatch/lock authority; do not reintroduce the obsolete `MachineRunCoordinator` design from the dirty checkout.

- [ ] **Step 1: Bring in the existing regression test before the production type**

Copy only the independent deployment-identity tests from the dirty checkout into the recovery test project. Run:

```bash
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo --filter "FullyQualifiedName~DeploymentIdentityTests"
```

Expected: compilation fails because `DeploymentIdentity` is undefined in the recovered project. The expected failure proves the test exercises the intended missing contract.

- [ ] **Step 2: Add the minimal immutable identity value object**

Implement the value object with the exact 16-byte invariant, `RandomNumberGenerator.GetBytes(16)`, and defensive copying in `FromBytes`. Expose bytes only as `ReadOnlySpan<byte>` and never add string conversion, logging, diagnostic output, or public mutable storage.

- [ ] **Step 3: Run focused identity and synchronization tests**

```bash
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo --filter "FullyQualifiedName~DeploymentIdentityTests|FullyQualifiedName~SynchronizationMetadataStoreTests|FullyQualifiedName~NamedSemaphoreFactoryTests|FullyQualifiedName~StartupSynchronizationGateTests"
```

Expected: all focused tests pass; an invalid metadata or semaphore path proves exit 8 before dispatch, while a valid held semaphore proves exit 11.

- [ ] **Step 4: Reconcile integration compiler errors at their source**

For every compile error after the identity test is green, retain the committed `verify/windows-harness` startup/metadata/semaphore architecture. Port only the legacy application dependency required by that compiler error. Do not copy `SynchronizationMetadataStore.cs` or `build/publish.sh` from the dirty checkout: they are known-corrupt partial files.

- [ ] **Step 5: Commit the security integration**

```bash
git add src/BackupPolicyTrigger tests/BackupPolicyTrigger.Tests
git commit -m "feat: integrate private deployment synchronization"
```

### Task 4: Restore CI and release-artifact coherence

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/build-release-artifact.yml`
- Modify: `build/publish.sh`
- Create or modify as required: `build/publish-windows-verification.sh`
- Modify: `README.md`, `docs/adr/0002-verified-unsigned-executable.md`, `docs/security/2026-08-30-publication-readiness-review-addendum.md`

**Interfaces:**
- CI restores and tests `BackupPolicyTrigger.sln` on Linux and Windows.
- The production publisher builds only `src/BackupPolicyTrigger/BackupPolicyTrigger.csproj` from `git archive HEAD` and rejects a dirty tree.
- The Windows harness publishes separately and is not present in `artifacts/win-x64/`.
- Production and harness manifests/checksums never contain deployment identities, derived semaphore names, credentials, or sensitive fixture paths.

- [ ] **Step 1: Add a failing clean-tree publish test**

In a disposable clone, create an untracked C# input file and invoke `./build/publish.sh`. Assert non-zero exit and exact text `Refusing to publish from a dirty worktree.` before repairing the publisher.

- [ ] **Step 2: Remove only duplicated/partial publisher blocks**

Keep one production-harness exclusion check and one final publication summary. The script must have a single success path and must build from an archived committed source tree. Do not copy the known duplicated block from the dirty checkout.

- [ ] **Step 3: Run formatting and CI-equivalent tests**

```bash
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo
dotnet format BackupPolicyTrigger.sln --verify-no-changes --no-restore
```

Expected: both commands exit 0.

- [ ] **Step 4: Commit release-pipeline repair**

```bash
git add .github build README.md docs
git commit -m "build: restore verified release pipeline"
```

### Task 5: Review, clean-tree publish, and Windows evidence

**Files:**
- Modify only with actual results: `.scratch/backup-policy-trigger/issues/06-private-deployment-identity.md`
- Modify only with actual results: `docs/security/2026-08-30-publication-readiness-review-addendum.md`

**Interfaces:**
- A clean recovery branch passes `dotnet test BackupPolicyTrigger.sln --configuration Release --nologo`.
- `build/publish.sh` rejects every dirty state and publishes a reproducible production artifact from clean `HEAD`.
- The Windows harness is built separately; its actual Windows lab checks are not claimed complete until run on Windows.

- [ ] **Step 1: Perform a task-scoped review, then a whole-branch review**

Run the applicable code-review workflow against the recovery branch merge base. Resolve every Critical or Important finding before release verification.

- [ ] **Step 2: Verify from a clean worktree**

```bash
git status --porcelain=v2 --branch
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo
./build/publish.sh
```

Expected: status has no entries after branch metadata; tests pass; publisher exits 0 and produces `artifacts/win-x64/BackupPolicyTrigger.exe`, `SHA256SUMS.txt`, and `PROVENANCE.txt`.

- [ ] **Step 3: Record boundaries honestly**

Mark ticket 06 done only after the deterministic suite and a Windows lab verification prove its acceptance criteria. On macOS, record only the completed deterministic checks and cross-platform build evidence; leave the Windows lab requirement explicitly outstanding.

- [ ] **Step 4: Commit verified status updates**

```bash
git add .scratch/backup-policy-trigger/issues/06-private-deployment-identity.md docs/security
git commit -m "docs: record security verification evidence"
```
