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
project="$build_root/src/BackupPolicyTrigger/BackupPolicyTrigger.csproj"
rm -rf "$output"
mkdir -p "$output"
dotnet publish "$project" \
  --configuration Release --runtime win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=none \
  --output "$output"

exe="$output/BackupPolicyTrigger.exe"
sha="$(shasum -a 256 "$exe" | cut -d' ' -f1)"
runtime_version="$(dotnet msbuild "$project" -nologo -getProperty:RuntimeFrameworkVersion -p:RuntimeIdentifier=win-x64 | tr -d '\r')"
protected_data_version="$(dotnet msbuild "$project" -nologo -getProperty:ProtectedDataVersion | tr -d '\r')"
global_packages="$(dotnet nuget locals global-packages --list | sed 's/^[^:]*: //')"
runtime_package="$global_packages/microsoft.netcore.app.runtime.win-x64/$runtime_version"
protected_data_package="$global_packages/system.security.cryptography.protecteddata/$protected_data_version"

for required in \
  "$build_root/LICENSE" \
  "$build_root/NOTICE" \
  "$build_root/licenses/MICROSOFT-DOTNET-LIBRARY-LICENSE.txt" \
  "$runtime_package/LICENSE.TXT" \
  "$runtime_package/THIRD-PARTY-NOTICES.TXT" \
  "$protected_data_package/LICENSE.TXT" \
  "$protected_data_package/THIRD-PARTY-NOTICES.TXT"
do
  if [[ ! -f "$required" ]]; then
    printf 'Required release license file is missing: %s\n' "$required" >&2
    exit 1
  fi
done

cp "$build_root/LICENSE" "$output/LICENSE"
cp "$build_root/NOTICE" "$output/NOTICE"
cp "$build_root/licenses/MICROSOFT-DOTNET-LIBRARY-LICENSE.txt" \
  "$output/MICROSOFT-DOTNET-LIBRARY-LICENSE.txt"
cp "$runtime_package/LICENSE.TXT" "$output/DOTNET-RUNTIME-MIT-LICENSE.txt"
cp "$runtime_package/THIRD-PARTY-NOTICES.TXT" \
  "$output/DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt"
cp "$protected_data_package/LICENSE.TXT" \
  "$output/PROTECTEDDATA-MIT-LICENSE.txt"
cp "$protected_data_package/THIRD-PARTY-NOTICES.TXT" \
  "$output/PROTECTEDDATA-THIRD-PARTY-NOTICES.txt"

printf 'source_commit=%s\nfile=BackupPolicyTrigger.exe\nsha256=%s\nruntime_framework_version=%s\nprotected_data_version=%s\n' \
  "$revision" "$sha" "$runtime_version" "$protected_data_version" > "$output/PROVENANCE.txt"

(
  cd "$output"
  shasum -a 256 \
    BackupPolicyTrigger.exe \
    LICENSE \
    NOTICE \
    MICROSOFT-DOTNET-LIBRARY-LICENSE.txt \
    DOTNET-RUNTIME-MIT-LICENSE.txt \
    DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt \
    PROTECTEDDATA-MIT-LICENSE.txt \
    PROTECTEDDATA-THIRD-PARTY-NOTICES.txt \
    PROVENANCE.txt
) > "$output/SHA256SUMS.txt"

chmod 0644 \
  "$output/LICENSE" \
  "$output/NOTICE" \
  "$output/MICROSOFT-DOTNET-LIBRARY-LICENSE.txt" \
  "$output/DOTNET-RUNTIME-MIT-LICENSE.txt" \
  "$output/DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt" \
  "$output/PROTECTEDDATA-MIT-LICENSE.txt" \
  "$output/PROTECTEDDATA-THIRD-PARTY-NOTICES.txt" \
  "$output/PROVENANCE.txt" \
  "$output/SHA256SUMS.txt"

# The production package must never contain the verification harness. The
# harness is published separately by `build/publish-windows-verification.sh`.
if [[ -e "$output/BackupPolicyTrigger.WindowsVerification.exe" ]]; then
  printf '%s\n' 'Production package must not contain the verification harness.' >&2
  exit 1
fi

printf '\nPublished %s\nSHA-256 %s\n' "$exe" "$sha"
