# Distribute a verified unsigned executable

The trigger is delivered as a self-contained Windows executable without a code-signing certificate. Before use, a Configuration administrator verifies the published SHA-256 hash and unblocks the binary; client IT provides an allow-list exception where endpoint policy requires it. This preserves the single-binary, no-runtime requirement while making the unsigned-binary risk explicit rather than asking ordinary users to bypass security warnings.

Release production is a clean-tree operation: the publisher builds only
`src/BackupPolicyTrigger/BackupPolicyTrigger.csproj` extracted from
`git archive HEAD`. CI restores and tests `BackupPolicyTrigger.sln` on Linux
and Windows before the manually dispatched release workflow attests and uploads
the production package. The Windows verification harness is packaged separately
and is excluded from the production artifact.
