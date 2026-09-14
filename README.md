# Backup Policy Trigger for Acronis Cyber Protect Cloud

A single Windows executable that asks Acronis Cyber Protect Cloud to run an already
configured protection policy. Another application calls it as a post-backup command
once its own backup finishes.

This is an independent open-source project from IronTree. It is not affiliated with,
endorsed by, or sponsored by Acronis. Acronis and related marks belong to their
respective owner.

It does **not** create or change protection policies, and it never claims a backup
finished — the Acronis console remains the authority for completion.

## Requirements

- Windows Server 2019 or newer (verified on Windows Server 2025).
- A local Administrator account that both configures and runs the trigger.
- A dedicated Acronis API client for this server, not shared with another integration,
  with these documented permissions:
  - `urn:acronis.com::policy_manager::admin` — start a policy.
  - `urn:acronis.com::policy_management::read` — list policies and read execution state.
  - `urn:acronis.com::resource_management::read` — list protected resources.
- The tenant's data-centre URL, copied from Acronis when the API client is registered
  (for example `https://eu2.acronis.cloud`). Only `https` is accepted.

No .NET runtime, Python, or virtual environment is installed on the server.

## Verify the download before running it

The executable is **not code signed**. Download releases only through the
authenticated project release page and verify the release attestation before relying
on its checksum. Then verify the executable against `SHA256SUMS.txt` in an elevated
PowerShell window:

```powershell
Get-FileHash .\BackupPolicyTrigger.exe -Algorithm SHA256
Unblock-File .\BackupPolicyTrigger.exe
```

The hash must match exactly. `SHA256SUMS.txt` also covers the project license,
IronTree notice, Microsoft .NET Library License, and version-matched .NET runtime and
ProtectedData notices shipped beside the executable. This detects corruption only after the release channel
and its attestation have been authenticated: an adjacent checksum cannot by itself
prove who published the executable. The same directory also carries `PROVENANCE.txt`,
which records the `source_commit` the executable was built from and the
`sha256` of the delivered `BackupPolicyTrigger.exe`. Both the source commit
and the SHA must match the attested release. If endpoint security blocks or
quarantines the file, ask client IT for
an allow-list exception for this hash and path; do not instruct users to click
through security warnings.

GitHub-hosted release bundles are built by the manual **Build attested release
artifact** workflow. Verify each downloaded file with GitHub CLI before use:

```powershell
gh attestation verify .\BackupPolicyTrigger.exe --repo OWNER/REPOSITORY
```

Replace `OWNER/REPOSITORY` with the repository shown on the release page.

## Configure

Run once, elevated:

```powershell
.\BackupPolicyTrigger.exe setup
```

It prompts for the data-centre URL, API client ID, and client secret (masked, never
echoed), then lists the tenant's root protection policies and the protected resources
attached to the one you pick. Groups such as "All machines" are never offered: they
would fan the backup across every member.

Configuration is stored under `C:\ProgramData\BackupPolicyTrigger\`, encrypted with
DPAPI LocalMachine and restricted to `SYSTEM` and the configuring Administrator. That
ACL is the confidentiality boundary — see `docs/adr/0001-localmachine-credential-protection.md`.

Re-running `setup` shows the current configuration and changes nothing unless you type
`REPLACE`. To change only the target, use `select-target`.

## Use as a post-backup command

Point the calling application at the executable with no arguments:

```text
C:\Program Files\BackupPolicyTrigger\BackupPolicyTrigger.exe
```

It refuses to start a second backup while the configured policy is already running on
the configured resource, and it returns only after Acronis reports the policy running
or a bounded failure. One invocation is capped at 90 seconds.

## Commands

| Command | Purpose |
| --- | --- |
| *(no argument)* | Start the configured protection policy on the configured resource. |
| `help` | Print the static operator guide; works before configuration and without elevation. |
| `setup` | Store the data-centre URL, API client, protection policy, and resource. |
| `select-target` | Change only the protection policy and resource. |
| `list-policies` | List root protection policies. Read-only. |
| `list-resources` | List resources attached to the configured policy. Read-only. |
| `diagnose` | Check configuration, connectivity, authentication, and the saved target. |
| `clear-pending` | Clear an outstanding start request after checking the Acronis console. |
| `reset` | Remove local configuration. Revoke the API client in Acronis separately. |

`setup`, `select-target`, `clear-pending`, and `reset` require an elevated
Administrator session. Run them from an elevated PowerShell window; otherwise the
trigger exits with code 21.

`help` prints a static, secret-free operator guide. It does not display saved
configuration and does not contact Acronis; it works before configuration and
without elevation.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. For a run: observed running, or completed immediately. |
| 2 | Not running on Windows. |
| 3 | No configuration. Run `setup`. |
| 4 | Diagnostics failed; the printed outcome says why. |
| 5 | No protection policy and resource configured. |
| 6 | Configuration exists but this account may not read it. |
| 7 | Configuration cannot be decrypted or parsed. Re-run `setup`. |
| 8 | Configuration storage unavailable. |
| 9 | Acronis discovery failed; the printed status says why. |
| 10 | The selection offered was not chosen, or the policy has no attached resource. |
| 11 | The policy is already running, or another run holds the machine lock. |
| 12 | Acronis accepted the request but running was not observed in the window. Later runs are not blocked. |
| 13 | Acronis rejected the request. |
| 14 | The start request outcome is unknown. **Every later run returns 19 and starts nothing until an administrator runs `clear-pending`.** Check the console first. |
| 15 | Acronis rejected the API client credentials. |
| 16 | Acronis could not be reached. |
| 17 | Unknown command. |
| 18 | The invocation exceeded its 90 second budget. Applies to unattended runs; `setup` and `select-target` are not time limited. |
| 19 | A previous start request is still outstanding. Run `clear-pending`. |
| 20 | Acronis returned an unrecognised response. If it came after the start request was sent, a backup may be running: check the Acronis console before running `clear-pending`. |
| 21 | The command requires an elevated Administrator session. |

Codes 12, 14, 18, and 19 mean a backup may already be running: check the Acronis
console rather than re-running the trigger.

Exit 14 latches: the trigger records the ambiguous request and every later run returns
19 without starting anything until an administrator confirms the console state and runs
`clear-pending`. That is deliberate — it prevents a duplicate backup — but an unattended
post-backup hook stays blocked until someone intervenes, so alert on 14 and 19.

Exit 20 behaves the same way when the unrecognised response arrived after the start
request was sent: the trigger retains the pending marker, so later runs return 19 until
an administrator checks the Acronis console and runs `clear-pending`. When the
unrecognised response arrived before the request was sent (for example a malformed
token response), no request left the machine and no marker is retained.

## Logs

`C:\ProgramData\BackupPolicyTrigger\trigger.log` records one best-effort outcome
record per configured run that reaches the Trigger module. It rotates at 256 KiB
keeping one previous file, and never contains secrets, access tokens, authorization
headers, or raw command arguments. Early failures before protected configuration
exists are console-only.

## Build

```bash
./build/publish.sh
```

The CI workflow restores and tests `BackupPolicyTrigger.sln` on Linux and
Windows. The manually dispatched **Build attested release artifact** workflow
publishes only the production package.

Requires the .NET 8 SDK. The build is a cross-compile: it produces the `win-x64`
executable from any host, including macOS. It refuses to run from a dirty
worktree and instead builds from a clean `git archive HEAD` tree, so the
published artifact always corresponds to a committed revision. The output
directory carries `SHA256SUMS.txt`, `PROVENANCE.txt`, the Apache-2.0 project
license and notice, and the applicable Microsoft/.NET license and third-party
notices. `PROVENANCE.txt` records the `source_commit`, executable `sha256`, and
resolved runtime/dependency versions. The release workflow must add an independent
attestation before publishing these files.

### Windows verification harness

The Windows verification harness is packaged separately and is never part of
the production release:

```bash
./build/publish-windows-verification.sh
```

It builds the application verification binary and the self-contained
`BackupPolicyTrigger.WindowsVerification.exe` harness from the same clean
`git archive HEAD` tree, into `artifacts/windows-verification/`. That directory
carries a `MANIFEST.txt` enumerating every packaged payload — the two
executables (`BackupPolicyTrigger.exe` and
`BackupPolicyTrigger.WindowsVerification.exe`), the two lab-gate scripts
(`lab-standard-user-coordinator.ps1` and `lab-standard-user-security.ps1`),
the project `LICENSE` and `NOTICE`, the Microsoft .NET Library License, the
version-matched .NET runtime and ProtectedData license/notice companions, and
the package metadata files `MANIFEST.txt`, `PROVENANCE.txt`, and
`SHA256SUMS.txt` themselves. `SHA256SUMS.txt` covers every other package member
but not itself — the conventional self-coverage exception, since a checksum
file cannot contain its own hash. `PROVENANCE.txt` records the `source_commit`
and the SHA-256 of both executables. The production `artifacts/win-x64/`
package remains harness-free; `build/publish.sh` refuses to publish if the
harness executable is present.

The manifests and checksums use only package-member filenames and release
metadata; they do not disclose deployment identities, derived semaphore names,
credentials, or fixture paths.


The harness exercises protected-storage, metadata, named-semaphore, and startup
dispatch security against real Windows ACL and kernel-object behavior. It
touches only a randomized fixture under `%TEMP%`; it never reads or modifies
production storage, credentials, pending markers, or Acronis resources, and it
never starts a backup.

### Standard-user lab gate

Before a release is authorized, the standard-user security gate must pass under
an approved non-administrator account. The gate is a two-account procedure
driven by a privileged coordinator, both delivered in the verification package
as `lab-standard-user-coordinator.ps1` and `lab-standard-user-security.ps1`.
The coordinator is the only end-to-end entry point: it performs the privileged
setup, records the administrator side of traversal, and then launches the
standard-user gate itself. The gate script is never run directly — it is
invoked only by the coordinator, which supplies the ephemeral fixture token and
the ephemerally disclosed semaphore name over the child's standard input.

Run the coordinator once, elevated, as the Configuration administrator:

```powershell
.\lab-standard-user-coordinator.ps1
```

The coordinator prompts for the standard-user account and password (the
password is read as a `SecureString` and never echoed or persisted), then:

1. Creates the dedicated lab fixture parent
   `%ProgramData%\BackupPolicyTrigger.WindowsVerification` and grants traverse
   to both the Configuration administrator and the standard user.
2. Creates a protected child restricted to `SYSTEM` and the Configuration
   administrator, and writes placeholder configuration and synchronization
   metadata into it.
3. Creates and holds a live named semaphore with the production DACL.
4. Records the administrator side of traversal, then launches the standard-user
   gate under the non-administrator account, handing it the ephemeral fixture
   token and the ephemerally disclosed semaphore name over the child's standard
   input.
5. Collects the gate's fixed check identifiers, releases the semaphore, and
   removes the fixture.

The gate accepts no sensitive values in arguments. It reads the ephemeral
fixture token and the ephemerally disclosed semaphore name from standard input,
verifies the shared fixture parent is traversable to both accounts, and records
fixed check identifiers for protected-child directory/config/metadata read and
write denial, undisclosed-name non-derivability, and denial of opening an
ephemerally disclosed live semaphore. It contains no command that starts
Acronis, changes production storage, or logs sensitive data. The token and
semaphore name are never written to a file, placed in process arguments, or
echoed.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Automated tests must never contact
Acronis or start a backup; live verification always requires separate approval.

## License

Original source and documentation are licensed by IronTree under the
[Apache License 2.0](LICENSE). Third-party components retain their own licenses.
Public binary releases must include the accompanying Microsoft/.NET license and
third-party-notice files; see
[`docs/research/2026-08-30-open-source-licensing.md`](docs/research/2026-08-30-open-source-licensing.md).
