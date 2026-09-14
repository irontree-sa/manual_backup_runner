#!/usr/bin/env bash
# Verifies that an untracked C# input prevents production publication before any
# build work can start. The disposable clone keeps the repository under test clean.
set -euo pipefail

repository="$(git rev-parse --show-toplevel)"
temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT

git clone --quiet --no-local "$repository" "$temporary_root/repository"
cd "$temporary_root/repository"
printf 'namespace BackupPolicyTrigger;\n' > src/BackupPolicyTrigger/UntrackedPublishRegression.cs

set +e
output="$(./build/publish.sh 2>&1)"
status=$?
set -e

if [[ $status -eq 0 || "$output" != 'Refusing to publish from a dirty worktree.' ]]; then
  printf 'Expected dirty publish rejection; status=%s output=%s\n' "$status" "$output" >&2
  exit 1
fi
