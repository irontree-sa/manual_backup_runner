# Acronis Backup Trigger

A single Windows executable that asks Acronis Cyber Protect Cloud to run an already
configured protection policy. Another application calls it as a post-backup command
once its own backup finishes.

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

The executable is **not code signed**. Verify it against the published hash in
`SHA256SUMS.txt`, in an elevated PowerShell window:

```powershell
Get-FileHash .\AcronisBackupTrigger.exe -Algorithm SHA256
Unblock-File .\AcronisBackupTrigger.exe
```

The hash must match exactly. If endpoint security blocks or quarantines the file,
ask client IT for an allow-list exception for this hash and path; do not instruct
users to click through security warnings.

## Configure

Run once, elevated:

```powershell
.\AcronisBackupTrigger.exe setup
```

It prompts for the data-centre URL, API client ID, and client secret (masked, never
echoed), then lists the tenant's root protection policies and the protected resources
attached to the one you pick. Groups such as "All machines" are never offered: they
would fan the backup across every member.

Configuration is stored under `C:\ProgramData\AcronisBackupTrigger\`, encrypted with
DPAPI LocalMachine and restricted to `SYSTEM` and the configuring Administrator. That
ACL is the confidentiality boundary — see `docs/adr/0001-localmachine-credential-protection.md`.

Re-running `setup` shows the current configuration and changes nothing unless you type
`REPLACE`. To change only the target, use `select-target`.

## Use as a post-backup command

Point the calling application at the executable with no arguments:

```text
C:\Program Files\AcronisBackupTrigger\AcronisBackupTrigger.exe
```

It refuses to start a second backup while the configured policy is already running on
the configured resource, and it returns only after Acronis reports the policy running
or a bounded failure. One invocation is capped at 90 seconds.

## Commands

| Command | Purpose |
| --- | --- |
| *(no argument)* | Start the configured protection policy and wait for it to be observed running. |
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
| 20 | Acronis returned an unrecognised response. |
| 21 | The command requires an elevated Administrator session. |

Codes 12, 14, 18, and 19 mean a backup may already be running: check the Acronis
console rather than re-running the trigger.

Exit 14 latches: the trigger records the ambiguous request and every later run returns
19 without starting anything until an administrator confirms the console state and runs
`clear-pending`. That is deliberate — it prevents a duplicate backup — but an unattended
post-backup hook stays blocked until someone intervenes, so alert on 14 and 19.

## Logs

`C:\ProgramData\AcronisBackupTrigger\trigger.log` records one line per invocation.
It rotates at 256 KiB keeping one previous file, and never contains secrets, access
tokens, authorization headers, or raw command arguments.

## Build

```bash
./build/publish.sh
```

Requires the .NET 8 SDK. The build is a cross-compile: it produces the `win-x64`
executable from any host, including macOS.
