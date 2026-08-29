# CLI Help Command Design

## Purpose

Add one `help` command to the Acronis Backup Trigger executable. It lets an Administrator understand how to run the trigger and complete common operational tasks without exposing configuration values, API-client credentials, saved IDs, or tenant-specific state.

## Interface

`AcronisBackupTrigger.exe help` prints a static, human-readable guide and exits `0`. It is available before Setup, does not contact Acronis, and does not read or modify local configuration.

The output covers:

- no-argument post-backup invocation;
- `setup`, `select-target`, `list-policies`, `list-resources`, `diagnose`, `clear-pending`, and `reset`;
- elevated-Administrator requirements for configuration-changing commands;
- hash verification, `Unblock-File`, and IT allow-list escalation for the unsigned executable;
- configuration and log locations;
- exit-code safety handling, especially exits `12`, `14`, and `19`;
- when to inspect the Acronis console rather than re-running the executable.

The help output must not display a saved policy/resource, data-centre URL, API client ID, secret, token, or any other mutable state.

## Design

Add `help` to the CommandHost's known-command dispatch. Its implementation returns a static multi-line string through the existing output writer and returns success. The source of truth for operational command text is one help-content module; README may describe installation and full release process but must not be duplicated by command dispatch code.

This is a pure command-host behavior. It adds no Acronis transport, configuration-store, log, privilege, or mutex dependency.

## Error Handling

The command never fails because setup is incomplete, configuration is unreadable, networking is unavailable, or the caller is non-elevated. It emits no error output and performs no logging beyond the existing sanitized command exit audit.

## Testing

Command-host tests verify that `help`:

- exits `0` on an unconfigured machine;
- writes the no-argument invocation, every supported command, exit 12/14/19 guidance, hash verification, and console escalation guidance;
- does not write stderr;
- does not contain a sentinel policy name, resource ID, data-centre URL, client ID, client secret, bearer token, or raw command input.

## Scope

The feature is one command only. It does not add a `guide` command, interactive wizard, GUI, dynamic configuration output, Acronis API call, README rewrite, or new administrator flow.
