#!/usr/bin/env bash
# Publishes the Windows verification harness package from a clean
# `git archive HEAD` tree. The package carries the self-contained application
# verification binary and the self-contained verification harness, both built
# from the same archived revision, together with a manifest, SHA-256 checksums,
# provenance, and every license/notice companion.
#
# The production `build/publish.sh` package remains harness-free: this script
# writes only to `artifacts/windows-verification/` and never touches
# `artifacts/win-x64/`.
set -euo pipefail

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  printf '%s\n' 'Refusing to publish from a dirty worktree.' >&2
  exit 1
fi

root="$(git rev-parse --show-toplevel)"
revision="$(git rev-parse --verify HEAD)"
build_root="$(mktemp -d)"
# Canonicalize the path: on macOS `mktemp -d` returns a `/var/folders/...`
# symlink path while `dotnet`/MSBuild resolve to `/private/var/folders/...`.
# The mismatch breaks the harness project's `ProjectReference` to the
# application project, so resolve the real path before extracting the archive.
build_root="$(cd "$build_root" && pwd -P)"
trap 'rm -rf "$build_root"' EXIT
git archive "$revision" | tar -x -C "$build_root"

output="$root/artifacts/windows-verification"
app_project="$build_root/src/BackupPolicyTrigger/BackupPolicyTrigger.csproj"
harness_project="$build_root/tools/BackupPolicyTrigger.WindowsVerification/BackupPolicyTrigger.WindowsVerification.csproj"
rm -rf "$output"
mkdir -p "$output"

# Publish each executable to its own staging directory so the harness project's
# dependency build of the application (a non-single-file side effect) can never
# overwrite the self-contained application verification binary.
app_stage="$(mktemp -d)"
harness_stage="$(mktemp -d)"
trap 'rm -rf "$build_root" "$app_stage" "$harness_stage"' EXIT

# Restore once, explicitly, before publishing. Two back-to-back `dotnet publish`
# calls can otherwise race the implicit restore (MSBuild node reuse) and drop the
# application's transitive `System.Threading.AccessControl` reference from the
# harness compile graph. Restoring the harness project restores the application
# project transitively; both publishes then use `--no-restore`.
dotnet restore "$harness_project" --runtime win-x64

dotnet publish "$app_project" \
  --configuration Release --runtime win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=none \
  --no-restore \
  --output "$app_stage"

dotnet publish "$harness_project" \
  --configuration Release --runtime win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=none \
  --no-restore \
  --output "$harness_stage"

app_exe="$output/BackupPolicyTrigger.exe"
harness_exe="$output/BackupPolicyTrigger.WindowsVerification.exe"
cp "$app_stage/BackupPolicyTrigger.exe" "$app_exe"
cp "$harness_stage/BackupPolicyTrigger.WindowsVerification.exe" "$harness_exe"

app_sha="$(shasum -a 256 "$app_exe" | cut -d' ' -f1)"
harness_sha="$(shasum -a 256 "$harness_exe" | cut -d' ' -f1)"

runtime_version="$(dotnet msbuild "$app_project" -nologo -getProperty:RuntimeFrameworkVersion -p:RuntimeIdentifier=win-x64 | tr -d '\r')"
protected_data_version="$(dotnet msbuild "$app_project" -nologo -getProperty:ProtectedDataVersion | tr -d '\r')"
threading_accesscontrol_version="$(dotnet msbuild "$app_project" -nologo -getProperty:ThreadingAccessControlVersion | tr -d '\r')"
global_packages="$(dotnet nuget locals global-packages --list | sed 's/^[^:]*: //')"
runtime_package="$global_packages/microsoft.netcore.app.runtime.win-x64/$runtime_version"
protected_data_package="$global_packages/system.security.cryptography.protecteddata/$protected_data_version"
threading_accesscontrol_package="$global_packages/system.threading.accesscontrol/$threading_accesscontrol_version"

for required in \
  "$build_root/LICENSE" \
  "$build_root/NOTICE" \
  "$build_root/licenses/MICROSOFT-DOTNET-LIBRARY-LICENSE.txt" \
  "$runtime_package/LICENSE.TXT" \
  "$runtime_package/THIRD-PARTY-NOTICES.TXT" \
  "$protected_data_package/LICENSE.TXT" \
  "$protected_data_package/THIRD-PARTY-NOTICES.TXT" \
  "$threading_accesscontrol_package/LICENSE.TXT" \
  "$threading_accesscontrol_package/THIRD-PARTY-NOTICES.TXT"
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
cp "$threading_accesscontrol_package/LICENSE.TXT" \
  "$output/THREADING-ACCESSCONTROL-MIT-LICENSE.txt"
cp "$threading_accesscontrol_package/THIRD-PARTY-NOTICES.TXT" \
  "$output/THREADING-ACCESSCONTROL-THIRD-PARTY-NOTICES.txt"
cp "$build_root/.scratch/lab-standard-user-security.ps1" \
  "$output/lab-standard-user-security.ps1"
cp "$build_root/.scratch/lab-standard-user-coordinator.ps1" \
  "$output/lab-standard-user-coordinator.ps1"

printf 'source_commit=%s\nfile=BackupPolicyTrigger.exe\nsha256=%s\nfile=BackupPolicyTrigger.WindowsVerification.exe\nsha256=%s\nruntime_framework_version=%s\nprotected_data_version=%s\nthreading_accesscontrol_version=%s\n' \
  "$revision" "$app_sha" "$harness_sha" "$runtime_version" \
  "$protected_data_version" "$threading_accesscontrol_version" > "$output/PROVENANCE.txt"

# The manifest enumerates every deliverable in the package, including the
# package metadata files and the two lab-gate scripts. SHA256SUMS.txt covers
# every package member except itself (the conventional self-coverage
# exception): a checksum file cannot contain its own hash.
{
  printf 'BackupPolicyTrigger.exe\n'
  printf 'BackupPolicyTrigger.WindowsVerification.exe\n'
  printf 'LICENSE\n'
  printf 'NOTICE\n'
  printf 'MICROSOFT-DOTNET-LIBRARY-LICENSE.txt\n'
  printf 'DOTNET-RUNTIME-MIT-LICENSE.txt\n'
  printf 'DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt\n'
  printf 'PROTECTEDDATA-MIT-LICENSE.txt\n'
  printf 'PROTECTEDDATA-THIRD-PARTY-NOTICES.txt\n'
  printf 'THREADING-ACCESSCONTROL-MIT-LICENSE.txt\n'
  printf 'THREADING-ACCESSCONTROL-THIRD-PARTY-NOTICES.txt\n'
  printf 'MANIFEST.txt\n'
  printf 'PROVENANCE.txt\n'
  printf 'SHA256SUMS.txt\n'
  printf 'lab-standard-user-security.ps1\n'
  printf 'lab-standard-user-coordinator.ps1\n'
} > "$output/MANIFEST.txt"

(
  cd "$output"
  shasum -a 256 \
    BackupPolicyTrigger.exe \
    BackupPolicyTrigger.WindowsVerification.exe \
    LICENSE \
    NOTICE \
    MICROSOFT-DOTNET-LIBRARY-LICENSE.txt \
    DOTNET-RUNTIME-MIT-LICENSE.txt \
    DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt \
    PROTECTEDDATA-MIT-LICENSE.txt \
    PROTECTEDDATA-THIRD-PARTY-NOTICES.txt \
    THREADING-ACCESSCONTROL-MIT-LICENSE.txt \
    THREADING-ACCESSCONTROL-THIRD-PARTY-NOTICES.txt \
    MANIFEST.txt \
    PROVENANCE.txt \
    lab-standard-user-security.ps1 \
    lab-standard-user-coordinator.ps1
) > "$output/SHA256SUMS.txt"

chmod 0644 \
  "$output/BackupPolicyTrigger.exe" \
  "$output/BackupPolicyTrigger.WindowsVerification.exe" \
  "$output/LICENSE" \
  "$output/NOTICE" \
  "$output/MICROSOFT-DOTNET-LIBRARY-LICENSE.txt" \
  "$output/DOTNET-RUNTIME-MIT-LICENSE.txt" \
  "$output/DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt" \
  "$output/PROTECTEDDATA-MIT-LICENSE.txt" \
  "$output/PROTECTEDDATA-THIRD-PARTY-NOTICES.txt" \
  "$output/THREADING-ACCESSCONTROL-MIT-LICENSE.txt" \
  "$output/THREADING-ACCESSCONTROL-THIRD-PARTY-NOTICES.txt" \
  "$output/MANIFEST.txt" \
  "$output/PROVENANCE.txt" \
  "$output/SHA256SUMS.txt" \
  "$output/lab-standard-user-security.ps1" \
  "$output/lab-standard-user-coordinator.ps1"

printf '\nPublished %s\nSHA-256 %s\nPublished %s\nSHA-256 %s\n' \
  "$app_exe" "$app_sha" "$harness_exe" "$harness_sha"
