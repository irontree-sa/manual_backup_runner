# Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the audit-log ACL, Trigger seam, tracker, and artifact-provenance release blockers without merging, pushing, releasing, or starting another Acronis backup.

**Architecture:** `ConfiguredTarget` replaces the policy/resource execution tuple and a storage DTO migrates existing encrypted JSON while writing only the new shape. `ITrigger` is the deep run module: it returns a typed `TriggerExecutionResult`, owns outcome-to-exit translation, console result emission, and audit logging. The publisher compiles a temporary `git archive HEAD` source tree so provenance records the complete input revision rather than a mutable workspace.

**Tech Stack:** C# 12/.NET 8, xUnit, Bash, Windows Server PowerShell verification.

## Global Constraints

- Work only on `repair/release-hardening`; do not merge, push, or release.
- `help` remains static and must not access configuration, logging, transport, locking, or elevation.
- Standard users must not create or read the configuration directory or audit log.
- No live Acronis backup invocation without separate explicit approval.
- The publisher must reject any tracked or untracked workspace state and compile only archived `HEAD` inputs.
- New behavior follows test-first red/green/refactor cycles.

---

### Task 1: Model the configured execution target

**Files:**
- Modify: `src/AcronisBackupTrigger/ConfigurationStore.cs:9-16,35-44,75-104`
- Modify: `src/AcronisBackupTrigger/Diagnostics.cs:14-36`
- Modify: `src/AcronisBackupTrigger/HttpAcronisTransport.cs:36-104`
- Modify: `src/AcronisBackupTrigger/BackupTrigger.cs:90-206`
- Modify: `src/AcronisBackupTrigger/CommandHost.cs:135-216,252-291`
- Modify: `tests/AcronisBackupTrigger.Tests/FakeAcronisTransport.cs`
- Modify: `tests/AcronisBackupTrigger.Tests/{BackupTriggerTests,CommandHostTests,DiscoveryTests,HelpCommandTests,HttpAcronisTransportTests,RunCommandTests,TargetSelectionTests}.cs`
- Test: `tests/AcronisBackupTrigger.Tests/ConfigurationStoreTests.cs`

**Interfaces:**
- Produces: `ConfiguredTarget(string PolicyId, string PolicyName, string ResourceId, string ResourceName)`.
- Produces: `TriggerConfiguration(..., ConfiguredTarget? Target = null)`.
- Produces: `IAcronisTransport.GetExecutionStateAsync(TriggerConfiguration, ConfiguredTarget, CancellationToken)` and `StartPolicyAsync(TriggerConfiguration, ConfiguredTarget, CancellationToken, Action?, Action?)`.
- Consumes: existing discovery `ListResourcesAsync(TriggerConfiguration, string policyId, CancellationToken)` remains unchanged.

- [ ] **Step 1: Write failing legacy-migration and target-persistence tests**

```csharp
[Fact]
public void Load_migrates_legacy_policy_and_resource_fields_to_target()
{
    var legacy = """{"DataCenterUrl":"https://eu2.acronis.cloud","ClientId":"id","ClientSecret":"secret","PolicyId":"policy-1","PolicyName":"Daily","ResourceId":"resource-1","ResourceName":"SERVER-01"}""";
    var store = new ConfigurationStore(directory, new ReversingProtector());
    Directory.CreateDirectory(directory);
    File.WriteAllBytes(Path.Combine(directory, "configuration.dat"),
        System.Text.Encoding.UTF8.GetBytes(legacy).Reverse().ToArray());

    Assert.Equal(new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01"), store.Load()!.Target);
}

[Fact]
public void Save_writes_target_without_legacy_policy_resource_fields()
{
    var store = new ConfigurationStore(directory, new ReversingProtector());
    store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "id", "secret",
        new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));

    var stored = System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(directory, "configuration.dat")).Reverse().ToArray());
    using var document = System.Text.Json.JsonDocument.Parse(stored);
    var root = document.RootElement;
    Assert.Equal("policy-1", root.GetProperty("Target").GetProperty("PolicyId").GetString());
    Assert.Equal("resource-1", root.GetProperty("Target").GetProperty("ResourceId").GetString());
    Assert.False(root.TryGetProperty("PolicyId", out _));
    Assert.False(root.TryGetProperty("ResourceId", out _));
}
```

- [ ] **Step 2: Run the two tests and verify they fail because no `ConfiguredTarget`/migration exists**

Run: `dotnet test tests/AcronisBackupTrigger.Tests/AcronisBackupTrigger.Tests.csproj --filter "FullyQualifiedName~ConfigurationStoreTests"`

Expected: compilation failure naming missing `ConfiguredTarget` or failed assertions against the old serialized shape.

- [ ] **Step 3: Add the target value object and storage migration**

Replace the positional selected-target fields with:

```csharp
public sealed record ConfiguredTarget(string PolicyId, string PolicyName, string ResourceId, string ResourceName);
public sealed record TriggerConfiguration(string DataCenterUrl, string ClientId, string ClientSecret, ConfiguredTarget? Target = null);
```

Deserialize a private `StoredConfiguration` DTO containing `Target` plus nullable legacy `PolicyId`, `PolicyName`, `ResourceId`, and `ResourceName`; convert a complete legacy tuple to `ConfiguredTarget` when `Target` is absent. Mark each legacy DTO property `JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)` and have `Save` serialize a DTO with those properties null.

- [ ] **Step 4: Change execution APIs and all callers to pass `ConfiguredTarget`**

Use the exact signatures:

```csharp
Task<ExecutionState> GetExecutionStateAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken);
Task<StartOutcome> StartPolicyAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken, Action? onSend = null, Action? onPreSendFailure = null);
```

Construct the selected value in `ChooseAndSaveTargetAsync`:

```csharp
Target = new ConfiguredTarget(policy.Id, policy.Name, resource.Id, resource.Name),
```

Use `configuration.Target` for target display and execution; leave list-resource discovery’s policy-ID parameter unchanged.

- [ ] **Step 5: Run target, transport, and full tests**

Run: `dotnet test tests/AcronisBackupTrigger.Tests/AcronisBackupTrigger.Tests.csproj --filter "FullyQualifiedName~ConfigurationStoreTests|FullyQualifiedName~TargetSelectionTests|FullyQualifiedName~BackupTriggerTests|FullyQualifiedName~HttpAcronisTransportTests"`

Expected: all selected tests pass.

Run: `dotnet test tests/AcronisBackupTrigger.Tests/AcronisBackupTrigger.Tests.csproj`

Expected: all tests pass.

- [ ] **Step 6: Commit the model cutover**

```bash
git add src/AcronisBackupTrigger tests/AcronisBackupTrigger.Tests
git commit -m "refactor: model configured backup target"
```

### Task 2: Deepen the Trigger module and make logging safe

**Files:**
- Create: `src/AcronisBackupTrigger/Trigger.cs`
- Modify: `src/AcronisBackupTrigger/CommandHost.cs:28-62,309-359`
- Modify: `src/AcronisBackupTrigger/Program.cs:30-85`
- Modify: `src/AcronisBackupTrigger/RotatingLog.cs:10-132`
- Modify: `tests/AcronisBackupTrigger.Tests/CommandHostTests.cs`
- Modify: `tests/AcronisBackupTrigger.Tests/RunCommandTests.cs`
- Modify: `tests/AcronisBackupTrigger.Tests/RotatingLogTests.cs`
- Create: `tests/AcronisBackupTrigger.Tests/TriggerTests.cs`
- Modify: `README.md:132-136`

**Interfaces:**
- Produces: `ITrigger.RunAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) -> Task<TriggerExecutionResult>`.
- Produces: `TriggerExecutionResult(TriggerOutcome Outcome, int ExitCode, string Detail)`.
- Consumes: `BackupTrigger.RunAsync` for Acronis decisions, `RotatingLog.Write` for best-effort configured-run audit output.
- `CommandHost` may load configuration and return `result.ExitCode`, but must not instantiate `BackupTrigger`, translate `TriggerOutcome`, emit a run result, or audit the run.

- [ ] **Step 1: Write failing Trigger-boundary tests**

```csharp
[Fact]
public async Task Run_returns_typed_outcome_and_translated_exit_code()
{
    var result = await TriggerFor(StartOutcome.CompletedSynchronously).RunAsync(Configured, CancellationToken.None);

    Assert.Equal(TriggerOutcome.CompletedSynchronously, result.Outcome);
    Assert.Equal(ExitCodes.Success, result.ExitCode);
}

[Fact]
public async Task Run_writes_sanitized_audit_record_after_a_configured_result()
{
    var entries = new List<string>();
    var result = await TriggerFor(StartOutcome.Accepted, entries.Add).RunAsync(Configured, CancellationToken.None);

    Assert.Equal(ExitCodes.AcceptedNotObserved, result.ExitCode);
    Assert.Single(entries);
    Assert.DoesNotContain("secret", entries[0], StringComparison.OrdinalIgnoreCase);
}

[Fact]
public async Task Run_command_returns_the_trigger_exit_code_without_mapping_outcome()
{
    var host = Host(trigger: new StubTrigger(new TriggerExecutionResult(TriggerOutcome.AcronisRejected, ExitCodes.AcronisRejected, "rejected")));

    Assert.Equal(ExitCodes.AcronisRejected, await host.RunAsync([]));
}
```

- [ ] **Step 2: Run the Trigger and command tests and verify failure**

Run: `dotnet test tests/AcronisBackupTrigger.Tests/AcronisBackupTrigger.Tests.csproj --filter "FullyQualifiedName~TriggerTests|FullyQualifiedName~RunCommandTests"`

Expected: compilation failure because `ITrigger`, `TriggerExecutionResult`, and `StubTrigger` do not exist, or the existing host still owns mapping.

- [ ] **Step 3: Implement the narrow `ITrigger` module**

Create `Trigger.cs` with:

```csharp
public interface ITrigger
{
    Task<TriggerExecutionResult> RunAsync(TriggerConfiguration configuration, CancellationToken cancellationToken);
}

public sealed record TriggerExecutionResult(TriggerOutcome Outcome, int ExitCode, string Detail);
```

Its concrete implementation creates `BackupTrigger`, catches its run budget cancellation, maps every `TriggerOutcome` to the existing `ExitCodes`, writes `"{Outcome}: {Detail}"` to the appropriate stream inside the existing IOException/UnauthorizedAccessException best-effort boundary, and logs only the safe `run: exit=<code> outcome=<outcome>` record.

Inject a concrete `ITrigger` into `CommandHost`; delete `triggerFactory`, generic command audit logging, and `TriggerBackupAsync`’s `BackupTrigger` construction, mapping, and result output. `TriggerBackupAsync` only loads configuration, calls the injected module, and returns `result.ExitCode`.

Construct the production module in `Program.cs`; remove its direct log writes for machine-lock contention and pre-dispatch budget exhaustion.

- [ ] **Step 4: Prevent initial audit-log creation and remove the production test hook**

Change `RotatingLog` to accept only `directory`, `maxBytes`, and `lockFactory`. Delete `postAcquire`, its field, invocation, and synthetic tests. Delete `Directory.CreateDirectory(directory)` from `WriteCore`; `DirectoryNotFoundException` remains inside the existing `IOException` best-effort catch.

Add this regression test:

```csharp
[Fact]
public void Write_without_existing_protected_storage_does_not_create_a_log()
{
    new RotatingLog(directory, lockFactory: () => logLock).Write("run: exit=0 outcome=ObservedRunning");

    Assert.False(Directory.Exists(directory));
    Assert.False(File.Exists(Path.Combine(directory, "trigger.log")));
}
```

Replace the timestamp-layout assertion with payload behavior:

```csharp
Assert.Equal(8 * 50, lines.Length);
foreach (var expected in Enumerable.Range(0, 8).SelectMany(i => Enumerable.Range(0, 50).Select(n => $"writer {i} entry {n}")))
    Assert.Contains(lines, line => line.EndsWith(expected, StringComparison.Ordinal));
```

Change README’s log contract to: “Each configured run that reaches the Trigger module has one best-effort outcome record. Early failures before protected configuration exists are console-only.”

- [ ] **Step 5: Run focused and full tests**

Run: `dotnet test tests/AcronisBackupTrigger.Tests/AcronisBackupTrigger.Tests.csproj --filter "FullyQualifiedName~TriggerTests|FullyQualifiedName~RunCommandTests|FullyQualifiedName~RotatingLogTests|FullyQualifiedName~CommandHostTests"`

Expected: all selected tests pass.

Run: `dotnet test tests/AcronisBackupTrigger.Tests/AcronisBackupTrigger.Tests.csproj`

Expected: all tests pass.

- [ ] **Step 6: Commit the deep-module repair**

```bash
git add README.md src/AcronisBackupTrigger tests/AcronisBackupTrigger.Tests
git commit -m "refactor: isolate trigger execution boundary"
```

### Task 3: Make published artifacts provenance-safe and reconcile tracker state

**Files:**
- Modify: `build/publish.sh:1-25`
- Modify: `README.md:24-36,138-145`
- Modify: `docs/agents/triage-labels.md:3-15`
- Modify: `.scratch/acronis-backup-trigger/spec.md:1-4`
- Modify: `.scratch/acronis-backup-trigger/issues/04-package-and-smoke-verify.md:15-22`
- Delete: `.superpowers/sdd/final-fix-report-2.md`

**Interfaces:**
- Produces: `artifacts/win-x64/SHA256SUMS.txt` and `artifacts/win-x64/PROVENANCE.txt`.
- `PROVENANCE.txt` has exactly `source_commit`, `file`, and `sha256` lines for the executable emitted in the same directory.
- Tracker status `done` means implemented and verified.

- [ ] **Step 1: Write a failing isolated-publish check**

In a disposable clone of the repository, create `src/AcronisBackupTrigger/UntrackedInput.cs` containing `internal static class UntrackedInput { }`, then invoke `./build/publish.sh`.

Expected: non-zero exit and the exact diagnostic `Refusing to publish from a dirty worktree.` The current publisher will instead build the untracked file.

- [ ] **Step 2: Implement archived-HEAD publication**

Replace the workspace build setup with this control flow:

```bash
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  printf '%s\n' 'Refusing to publish from a dirty worktree.' >&2
  exit 1
fi

root="$(git rev-parse --show-toplevel)"
revision="$(git rev-parse --verify HEAD)"
build_root="$(mktemp -d)"
trap 'rm -rf "$build_root"' EXIT
git archive "$revision" | tar -x -C "$build_root"

output="$root/artifacts/win-x64"
rm -rf "$output"
mkdir -p "$output"
dotnet publish "$build_root/src/AcronisBackupTrigger/AcronisBackupTrigger.csproj" \
  --configuration Release --runtime win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=none \
  --output "$output"
```

After calculating the SHA, write:

```bash
printf 'source_commit=%s\nfile=AcronisBackupTrigger.exe\nsha256=%s\n' "$revision" "$sha" > "$output/PROVENANCE.txt"
```

- [ ] **Step 3: Verify red becomes green**

Run the dirty disposable-clone check again; it must fail before publication with the expected diagnostic. In a clean disposable clone, run the publisher and verify:

```bash
shasum -a 256 artifacts/win-x64/AcronisBackupTrigger.exe
cat artifacts/win-x64/SHA256SUMS.txt
cat artifacts/win-x64/PROVENANCE.txt
```

Expected: the executable digest equals both manifest SHA values and `source_commit` is that clone’s `HEAD`.

- [ ] **Step 4: Update source documentation and tracker vocabulary**

Add this canonical row:

```markdown
| `done` | `done` | Implemented and verified |
```

Replace ticket 04’s static hash with a statement that the exact artifact’s `SHA256SUMS.txt` and `PROVENANCE.txt` are the only hash record; do not record a new hash in a tracked source file. Update README to explain `PROVENANCE.txt` and that the source commit and SHA must both match the delivered directory. Leave the primary spec status unchanged until Windows verification succeeds.

Remove the acknowledged stale untracked report before the clean publish check:

```bash
rm .superpowers/sdd/final-fix-report-2.md
```

- [ ] **Step 5: Commit provenance and tracker repair**

```bash
git add README.md build/publish.sh docs/agents/triage-labels.md .scratch/acronis-backup-trigger
git commit -m "build: record reproducible artifact provenance"
```

### Task 4: Verify and record the final exact package on Windows Server

**Files:**
- Modify: `.scratch/acronis-backup-trigger/spec.md:1-4` only after the first safe lab verification succeeds.

**Interfaces:**
- Consumes: one clean local publish directory containing `AcronisBackupTrigger.exe`, `SHA256SUMS.txt`, and `PROVENANCE.txt`.
- Produces: evidence that the lab executable hash equals both local manifests and safe commands work on the same executable.

- [ ] **Step 1: Publish the pre-record artifact from a clean branch**

Run:

```bash
git status --porcelain --untracked-files=all
./build/publish.sh
shasum -a 256 artifacts/win-x64/AcronisBackupTrigger.exe
cat artifacts/win-x64/SHA256SUMS.txt
cat artifacts/win-x64/PROVENANCE.txt
```

Expected: empty status before publish; the digest agrees with both manifest files and provenance names current `HEAD`.

- [ ] **Step 2: Deploy and verify that exact artifact directory**

Copy `AcronisBackupTrigger.exe`, `SHA256SUMS.txt`, and `PROVENANCE.txt` together. On the lab host, run `Get-FileHash .\AcronisBackupTrigger.exe -Algorithm SHA256` and verify it equals both files’ recorded SHA before executing the program.

- [ ] **Step 3: Exercise safe commands only**

Run the copied executable’s `help`, `diagnose`, and `list-policies` commands. Verify exit 0, static help output for `help`, the saved target state for `diagnose`, and policy discovery for `list-policies`. Do not invoke a no-argument run.

- [ ] **Step 4: Record the successful first verification**

Set `.scratch/acronis-backup-trigger/spec.md` to `Status: done`. Reference the exact packaged `PROVENANCE.txt`; do not copy a release hash into a tracked source document.

```bash
git add .scratch/acronis-backup-trigger/spec.md
git commit -m "docs: record release hardening verification"
```

- [ ] **Step 5: Publish and verify the final source revision**

The status commit changes `HEAD`, so it needs its own final artifact. From the clean branch, run `./build/publish.sh`, verify the local digest against both manifests, redeploy the three-file artifact directory, and repeat only `help`, `diagnose`, and `list-policies` on the Windows lab. Confirm that `PROVENANCE.txt` names the status-commit revision and that all three commands still exit 0. Do not invoke a no-argument run.
