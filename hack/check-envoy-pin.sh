#!/usr/bin/env bash
# Checks that ENVOY_IMAGE in the Makefile, the Envoy `make test-envoy` runs
# against, is the Envoy a Substrate checkout builds its egress gateway on.
#
#   hack/check-envoy-pin.sh <upstream substrate checkout>
#
# The scheduled end-to-end workflow runs it against the pinned Substrate
# release, where a difference means the Makefile was not updated with the pin,
# and against Substrate's main branch, where it means Substrate has moved to
# an Envoy that test/envoy does not cover yet.

set -o errexit -o nounset -o pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <upstream substrate checkout>" >&2
  exit 2
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="$1/cmd/dataplane/envoy/Dockerfile"

ours="$(sed -n 's/^ENVOY_IMAGE ?= //p' "${root}/Makefile")"
# The gateway image is the Dockerfile's last stage.
theirs="$(sed -n 's/^FROM \(envoyproxy\/envoy:[^ ]*\).*/\1/p' "${dockerfile}" | tail -n 1)"

if [[ -z "${ours}" || -z "${theirs}" ]]; then
  echo "could not read the Envoy image from the Makefile ('${ours}') or ${dockerfile} ('${theirs}')" >&2
  exit 1
fi
if [[ "${ours}" != "${theirs}" ]]; then
  echo "Substrate's gateway is built on ${theirs}" >&2
  echo "make test-envoy runs against  ${ours}" >&2
  echo "Set ENVOY_IMAGE in the Makefile, and the default in test/envoy/envoy_test.go, to Substrate's." >&2
  exit 1
fi
echo "ENVOY_IMAGE matches Substrate's gateway: ${ours}"
