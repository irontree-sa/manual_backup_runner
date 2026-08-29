#!/usr/bin/env bash
# Publishes the single-file, self-contained Windows executable and records its
# SHA-256 so an administrator can verify the binary before allowing it to run.
set -euo pipefail

cd "$(dirname "$0")/.."

output="artifacts/win-x64"
rm -rf "$output"

dotnet publish src/AcronisBackupTrigger/AcronisBackupTrigger.csproj \
  --configuration Release \
  --runtime win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:EnableCompressionInSingleFile=true \
  -p:DebugType=none \
  --output "$output"

exe="$output/AcronisBackupTrigger.exe"
sha="$(shasum -a 256 "$exe" | cut -d' ' -f1)"

printf '%s  AcronisBackupTrigger.exe\n' "$sha" > "$output/SHA256SUMS.txt"

printf '\nPublished %s\nSHA-256 %s\n' "$exe" "$sha"
