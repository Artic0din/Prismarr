#!/usr/bin/env bash
set -euo pipefail

source_root=${1:?Usage: build-repo-assist-compiler.sh SOURCE_CHECKOUT}
repository_root=$(cd "$(dirname "$0")/../.." && pwd)
patch_file="$repository_root/.github/patches/gh-aw-detection-prerequisites.patch"
source_commit=d534c311af32e1e3d26f2015d9b95d738633a2b5
patch_sha256=598ca1961f5704db23d09232abceaea46d2f3ff286490df125be5166c5fd98ed

python3 - "$patch_file" "$patch_sha256" <<'PY'
import hashlib
import sys
from pathlib import Path

actual = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit(f"Compiler patch digest mismatch: {actual}")
PY

if [ "$(git -C "$source_root" rev-parse HEAD)" != "$source_commit" ]; then
  echo 'Compiler source must be the reviewed v0.90.0 commit' >&2
  exit 1
fi
if [ -n "$(git -C "$source_root" status --porcelain --untracked-files=all)" ]; then
  echo 'Compiler source must be a clean checkout before patching' >&2
  exit 1
fi
export GOTOOLCHAIN=go1.27.0
if [ "$(go env GOVERSION)" != go1.27.0 ]; then
  echo 'Compiler build requires Go 1.27.0' >&2
  exit 1
fi

git -C "$source_root" apply --unidiff-zero --check "$patch_file"
git -C "$source_root" apply --unidiff-zero "$patch_file"
(
  cd "$source_root"
  go test -mod=readonly ./pkg/workflow \
    -run 'TestExternalDetectorRequiresSuccessfulPrerequisites|TestFailedDetectionPreparationRetainsDiagnosticsAndAgentFailureEntry' \
    -count=1
  # Keep the upstream version format so runtime blocked/minimum-version checks
  # stay active. The source commit and patch digest identify this local build.
  go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags '-s -w -X main.version=v0.90.0 -X main.isRelease=true' \
    -o "${RUNNER_TEMP:?RUNNER_TEMP must name a writable build directory}/gh-aw-repo-assist" ./cmd/gh-aw
)
printf 'Built gh-aw v0.90.0 with prerequisite patch %s from %s\n' "$patch_sha256" "$source_commit"
