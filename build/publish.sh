#!/usr/bin/env bash
# Publishes the single-file, self-contained Windows executable from a clean
# `git archive HEAD` tree and records its SHA-256 and source commit so an
# administrator can verify the binary before allowing it to run.
set -euo pipefail

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

exe="$output/AcronisBackupTrigger.exe"
sha="$(shasum -a 256 "$exe" | cut -d' ' -f1)"

printf '%s  AcronisBackupTrigger.exe\n' "$sha" > "$output/SHA256SUMS.txt"
printf 'source_commit=%s\nfile=AcronisBackupTrigger.exe\nsha256=%s\n' "$revision" "$sha" > "$output/PROVENANCE.txt"

printf '\nPublished %s\nSHA-256 %s\n' "$exe" "$sha"
