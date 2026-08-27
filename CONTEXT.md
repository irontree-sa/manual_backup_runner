# Acronis Backup Trigger

A Windows integration that asks Acronis Cyber Protect Cloud to run an already configured backup after another application completes its own backup.

## Language

**Protection policy**:
An Acronis API policy object. Its root `policy.protection.total` policy represents the configured protection plan assigned to a protected device.
_Avoid_: Task

**API client**:
The dedicated Acronis tenant identity, consisting of a client ID and client secret, used only by this trigger to obtain access tokens.
_Avoid_: API key, shared API client

**Configured resource**:
The protected Acronis resource selected during setup from the resources assigned to the configured protection policy. It is identified by both its friendly name and immutable resource ID.
_Avoid_: Machine name alone

**Configuration administrator**:
The local Administrator account that performs setup, reset, and routine post-backup triggering on a server.
_Avoid_: Standard user, service account

**Backup request**:
The request to start a protection policy. Acronis accepting the request is distinct from the resulting backup finishing.
_Avoid_: Completed backup

**Setup**:
The repeatable local configuration operation that stores an API client, selected protection policy, and selected protected resource for future post-backup triggers.
_Avoid_: Installation

**Diagnostics**:
The tool operation that checks the configured Acronis connection, API-client authentication, and selected target after the tool has been installed.
_Avoid_: Health check

**Discovery**:
The read-only listing of available Acronis protection policies and protected resources. It does not change saved setup.
_Avoid_: Setup

**Start observation**:
Confirmation that Acronis reports the selected protection policy running on its selected protected resource. It is distinct from request acceptance and backup completion.
_Avoid_: Backup completed

**Post-backup trigger**:
The command launched by the source application after its own backup completes, which requests the Acronis protection policy to run.
_Avoid_: Backup script, callback
