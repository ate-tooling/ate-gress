#!/usr/bin/env bash
# Builds the ategressctl binaries a release publishes, one per platform:
#
#   <output dir>/ategressctl-<version>-<os>-<arch>
#
# with the flags the server image is built with, so that the same commit
# yields the same bytes.
#
#   hack/build-ategressctl.sh <version> <output dir>
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <output dir>" >&2
  exit 2
fi
version="$1" out="$2"

root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "${out}"
out="$(cd "${out}" && pwd)"

# hack/verify-release.sh expects exactly these.
platforms=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)

cd "${root}"
for platform in "${platforms[@]}"; do
  os="${platform%/*}" arch="${platform#*/}"
  CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" \
    go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=${version}" \
    -o "${out}/ategressctl-${version}-${os}-${arch}" ./cmd/ategressctl
  echo "${out}/ategressctl-${version}-${os}-${arch}"
done
