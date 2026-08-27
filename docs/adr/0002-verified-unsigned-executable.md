# Distribute a verified unsigned executable

The trigger is delivered as a self-contained Windows executable without a code-signing certificate. Before use, a Configuration administrator verifies the published SHA-256 hash and unblocks the binary; client IT provides an allow-list exception where endpoint policy requires it. This preserves the single-binary, no-runtime requirement while making the unsigned-binary risk explicit rather than asking ordinary users to bypass security warnings.
