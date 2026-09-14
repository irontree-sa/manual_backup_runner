# Publication readiness review addendum

## Release-pipeline boundary

The CI workflow restores and tests `BackupPolicyTrigger.sln` on Linux and
Windows. The manual **Build attested release artifact** workflow invokes only
`build/publish.sh` and uploads `artifacts/win-x64/`.

`build/publish.sh` rejects every dirty worktree, extracts `git archive HEAD`,
and publishes only `src/BackupPolicyTrigger/BackupPolicyTrigger.csproj`. The
Windows verification harness is published only by
`build/publish-windows-verification.sh` into
`artifacts/windows-verification/`; it is not a production payload.

Production and harness package manifests and checksums contain package-member
filenames, revision-independent checksums, and dependency-version metadata only.
They must not include deployment identities, derived semaphore names,
credentials, or sensitive fixture paths.

## Regression check

`build/test-publish-dirty-worktree.sh` creates a disposable clone, adds an
untracked C# input, and asserts that `./build/publish.sh` exits non-zero with
exactly `Refusing to publish from a dirty worktree.` before any build work can
start.
