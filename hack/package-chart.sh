#!/usr/bin/env bash
# Packages the chart for a release: chart version and appVersion set to the
# release version, and the image pinned to the digest that was built and
# signed for it.
#
#   hack/package-chart.sh <version> <image digest> <output dir>
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <sha256:digest> <output dir>" >&2
  exit 2
fi
version="$1" digest="$2" out="$3"
if ! [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "not a sha256 digest: ${digest}" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cp -R "${root}/charts/ate-gress" "${work}/"
values="${work}/ate-gress/values.yaml"
grep -q '^  digest: ""$' "${values}" || {
  echo "values.yaml has no empty image.digest to pin" >&2
  exit 1
}
sed -i.bak "s|^  digest: \"\"\$|  digest: \"${digest}\"|" "${values}"
rm "${values}.bak"

mkdir -p "${out}"
helm lint "${work}/ate-gress"
helm package "${work}/ate-gress" --version "${version}" --app-version "${version}" --destination "${out}"

# The rendered Deployment must reference exactly this image.
repository="$(sed -n 's/^  repository: //p' "${values}")"
want="${repository}:${version}@${digest}"
got="$(helm template ate-gress "${out}/ate-gress-${version}.tgz" | sed -n 's/^ *image: "\(.*\)"$/\1/p')"
if [[ "${got}" != "${want}" ]]; then
  echo "packaged chart renders image ${got}, want ${want}" >&2
  exit 1
fi
