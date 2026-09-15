# Public release continuation handoff

- **Date:** 2026-09-15
- **Repository:** [`irontree-sa/manual_backup_runner`](https://github.com/irontree-sa/manual_backup_runner)
- **Public release branch:** `recovery/security-harness-integration`
- **Current public commit:** `3a9180536706729025df1b89cdd365d564720330`
- **Current prerelease:** [`v0.1.0-rc.1`](https://github.com/irontree-sa/manual_backup_runner/releases/tag/v0.1.0-rc.1)

## Resume here

The repository is public and the current prerelease is published from the commit above. Start any future work from a fresh clone of the GitHub repository, not from a pre-cleanup local checkout:

```bash
git clone https://github.com/irontree-sa/manual_backup_runner.git
cd manual_backup_runner
git switch recovery/security-harness-integration
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo
```

Do not force-push an old local branch, tag, or clone without first confirming its history is based on `3a9180536706729025df1b89cdd365d564720330` or a descendant.

## Project purpose

`BackupPolicyTrigger.exe` is a self-contained Windows executable for invoking an already-configured Acronis Cyber Protect Cloud protection policy after another backup completes. It does not create or alter policies, and the Acronis console remains the source of truth for backup completion.

Operational contract:

- Requires Windows Server 2019+ and a local Administrator identity for configuration and execution.
- Persists data-centre URL, Acronis API client ID/secret, selected policy, and selected resource beneath `C:\ProgramData\BackupPolicyTrigger\`.
- Protects configuration with DPAPI `LocalMachine` plus an ACL for `SYSTEM` and the configuring Administrator.
- Bounds a normal invocation at 90 seconds, serializes local execution with a protected named semaphore, and latches ambiguous start outcomes until an administrator confirms Acronis state and runs `clear-pending`.
- Never starts a backup in automated tests.

Read [`README.md`](../../README.md) for operator setup, commands, exit codes, logging, download verification, and packaging. Read [`docs/adr/0001-localmachine-credential-protection.md`](../adr/0001-localmachine-credential-protection.md) before changing configuration storage or deployment identity behavior.

## Current release evidence

| Check | Result |
| --- | --- |
| Local unit test | `dotnet test BackupPolicyTrigger.sln --configuration Release --nologo` passed: 205/205 |
| GitHub CI | [run 34970149883](https://github.com/irontree-sa/manual_backup_runner/actions/runs/34970149883) passed on `3a9180536706729025df1b89cdd365d564720330` |
| Release build + provenance attestation | [run 34998782355](https://github.com/irontree-sa/manual_backup_runner/actions/runs/34998782355) passed |
| Downloaded release bundle | `shasum -a 256 -c SHA256SUMS.txt` passed for every delivered file |
| Executable attestation | `gh attestation verify BackupPolicyTrigger.exe --repo irontree-sa/manual_backup_runner` exited successfully |
| Published prerelease | `v0.1.0-rc.1`, prerelease flag set, 12 uploaded assets, target commit matches the stated release commit |

The release is intentionally unsigned. Consumers must authenticate the GitHub release and verify both the GitHub attestation and `SHA256SUMS.txt`; see [`README.md`](../../README.md#verify-the-download-before-running-it).

## Build, CI, and release procedure

### Local verification

```bash
dotnet test BackupPolicyTrigger.sln --configuration Release --nologo
./build/publish.sh
```

`build/publish.sh` rejects a dirty worktree and packages from `git archive HEAD`. It writes `artifacts/win-x64/` with the executable, project license and notice, required Microsoft/.NET notices, `SHA256SUMS.txt`, and `PROVENANCE.txt`.

The separate Windows verification package is built with:

```bash
./build/publish-windows-verification.sh
```

It is intentionally harness-only and must not appear in `artifacts/win-x64/`.

### GitHub workflows

- [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) restores dependencies and runs Release tests on `ubuntu-latest` and `windows-latest` for pushes and pull requests.
- [`.github/workflows/build-release-artifact.yml`](../../.github/workflows/build-release-artifact.yml) is manual. It builds `artifacts/win-x64/*`, attests every release file, and uploads the release bundle.

Dispatch and inspect an attested build:

```bash
gh workflow run "Build attested release artifact" \
  --repo irontree-sa/manual_backup_runner \
  --ref recovery/security-harness-integration

gh run watch RUN_ID --repo irontree-sa/manual_backup_runner --exit-status
gh api repos/irontree-sa/manual_backup_runner/actions/runs/RUN_ID/artifacts
```

The workflow currently declares an artifact name of `backup-policy-trigger-win-x64`, but run `34998782355` exposed it as `BackupPolicyTrigger-win-x64`. Query the run artifacts before download instead of assuming either spelling:

```bash
gh run download RUN_ID \
  --repo irontree-sa/manual_backup_runner \
  --name ARTIFACT_NAME \
  --dir RELEASE_DIR

(cd RELEASE_DIR && shasum -a 256 -c SHA256SUMS.txt)
(cd RELEASE_DIR && gh attestation verify BackupPolicyTrigger.exe \
  --repo irontree-sa/manual_backup_runner)
```

Only then create a prerelease targeted to the exact attested source commit:

```bash
gh release create vX.Y.Z-rc.N RELEASE_DIR/* \
  --repo irontree-sa/manual_backup_runner \
  --target COMMIT_SHA \
  --title "vX.Y.Z-rc.N" \
  --prerelease \
  --notes "Release built and attested from COMMIT_SHA."
```

Verify the result:

```bash
gh release view vX.Y.Z-rc.N \
  --repo irontree-sa/manual_backup_runner \
  --json tagName,targetCommitish,isPrerelease,url,assets
```

## Repository hygiene cleanup completed

The following repository-local agent/project-state directories were removed from the public source and ignored:

```text
.claude/
.superpowers/
.scratch/
```

This was a project-hygiene decision, not a sensitive-data incident. No GitHub Support or garbage-collection request was submitted.

Completed actions:

1. Removed the three directories from the published branch and added them to `.gitignore`.
2. Rewrote GitHub-reachable history with `git filter-repo --invert-paths` for the three paths.
3. Force-pushed the rewritten public branch.
4. Fresh-cloned the remote and confirmed no reachable commits, objects, or tree entries for the removed paths.
5. Rebuilt CI and the attested prerelease from the sanitized commit.

In a fresh clone, verify the current tree and ignore rules before publishing:

```bash
git show HEAD:.gitignore
git ls-tree -d --name-only HEAD -- .claude .superpowers .scratch
git check-ignore -v .claude/.probe .superpowers/.probe .scratch/.probe
```

The tree command must print nothing; `git check-ignore` must report an ignore rule for each probe.

### Important local-history warning

The original development checkout was intentionally left untouched because it had unrelated dirty work. It may still retain old local-only branches and objects containing these directories. That is acceptable because the files were non-sensitive, but it creates a release risk: pushing one of those old refs can reintroduce them to GitHub.

Use a fresh clone for release work. If an old clone must be retained, fetch the public branch and reset or delete obsolete local refs deliberately; do not mirror-push it.

## Known follow-ups

1. **README dead links.** `README.md` links to `CONTRIBUTING.md` and `docs/research/2026-08-30-open-source-licensing.md`, but neither path exists in the release commit. Add the documents or replace the links.
2. **GitHub Actions Node notice.** The successful attestation build emitted GitHub's Node.js 20 deprecation annotation for pinned action internals. This did not fail the run; update action revisions when their maintainers publish Node 24-compatible releases.
3. **Platform warnings.** CA1416 warnings occur on non-Windows builds because production code intentionally uses Windows ACL, DPAPI, and named-semaphore APIs. CI passed on both operating systems. Do not suppress them without preserving platform guards and tests.

## High-value code locations

| Concern | Location |
| --- | --- |
| Process composition, 90-second budget, secret input | `src/BackupPolicyTrigger/Program.cs` |
| Protected configuration and DPAPI protector | `src/BackupPolicyTrigger/ConfigurationStore.cs` |
| Pending-start safety latch | `src/BackupPolicyTrigger/PendingStartStore.cs` |
| Local execution coordination | `src/BackupPolicyTrigger/MachineRunCoordinator.cs` |
| Protected named semaphore | `src/BackupPolicyTrigger/NamedSemaphoreFactory.cs` |
| Synchronization metadata validation | `src/BackupPolicyTrigger/SynchronizationMetadataStore.cs` |
| Acronis HTTP API transport | `src/BackupPolicyTrigger/HttpAcronisTransport.cs` |
| Backup start orchestration and operator commands | `src/BackupPolicyTrigger/BackupTrigger.cs`, `src/BackupPolicyTrigger/Trigger.cs`, and `src/BackupPolicyTrigger/CommandHost.cs` |
| Test suite | `tests/BackupPolicyTrigger.Tests/` |
| Release packager | `build/publish.sh` |
| Windows verification packager | `build/publish-windows-verification.sh` |

## Safe next actions

1. Fix the README discrepancies above in a normal reviewed change.
2. Keep changes on a new branch based on `recovery/security-harness-integration`.
3. Let CI pass on Linux and Windows.
4. For a new release, dispatch a fresh attested artifact build; never reuse assets from a prior run.
5. Download, verify checksums and attestation, then publish a new prerelease tag targeted to that build's commit.
6. Do not add `.claude/`, `.superpowers/`, or `.scratch/` to a public commit.
