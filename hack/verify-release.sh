#!/usr/bin/env bash
# Verifies a published release the way docs/releasing.md asks consumers to:
# every signature and attestation must come from this repository's release
# workflow, run on a GitHub-hosted runner for the release tag.
#
#   hack/verify-release.sh <version> [image] [charts repository] [owner/repo]
#
# Needs cosign, gh (authenticated), helm, docker buildx, and sha256sum or
# shasum. IMAGE_DIGEST and CHART_DIGEST, when set, are checked instead of
# resolving the version tags.
set -euo pipefail

version="${1:?usage: $0 <version> [image] [charts] [owner/repo]}"
version="${version#v}"
image="${2:-ghcr.io/samueltorres/ate-gress}"
charts="${3:-ghcr.io/samueltorres/charts}"
repo="${4:-samueltorres/ate-gress}"
tag="v${version}"

workflow="${repo}/.github/workflows/release.yaml"
identity="https://github.com/${workflow}@refs/tags/${tag}"
issuer="https://token.actions.githubusercontent.com"
attest=(--repo "${repo}" --signer-workflow "github.com/${workflow}"
  --source-ref "refs/tags/${tag}" --deny-self-hosted-runners)

step() { printf '\n== %s\n' "$*"; }

digest_of() {
  # Resolves a tag to its digest, so everything below checks one immutable
  # artifact, not whatever the tag points to later.
  docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$1" 2>/dev/null
}

image_digest="${IMAGE_DIGEST:-$(digest_of "${image}:${version}")}"
chart_digest="${CHART_DIGEST:-$(digest_of "${charts}/ate-gress:${version}")}"
for d in "${image_digest}" "${chart_digest}"; do
  [[ "${d}" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "could not resolve a digest: '${d}'" >&2; exit 1; }
done

step "image ${image}@${image_digest}: signature"
cosign verify "${image}@${image_digest}" \
  --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" >/dev/null

step "image: build provenance"
gh attestation verify "oci://${image}@${image_digest}" "${attest[@]}" --bundle-from-oci >/dev/null

step "image: SBOM"
gh attestation verify "oci://${image}@${image_digest}" "${attest[@]}" --bundle-from-oci \
  --predicate-type https://spdx.dev/Document/v2.3 >/dev/null

step "chart ${charts}/ate-gress@${chart_digest}: signature"
cosign verify "${charts}/ate-gress@${chart_digest}" \
  --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" >/dev/null

step "chart: build provenance"
gh attestation verify "oci://${charts}/ate-gress@${chart_digest}" "${attest[@]}" --bundle-from-oci >/dev/null

step "chart: pins the verified image"
rendered="$(helm template ate-gress "oci://${charts}/ate-gress@${chart_digest}" | sed -n 's/^ *image: "\(.*\)"$/\1/p')"
if [[ "${rendered}" != "${image}:${version}@${image_digest}" ]]; then
  echo "chart renders ${rendered}, want ${image}:${version}@${image_digest}" >&2
  exit 1
fi

step "release files: checksums and provenance"
dir="$(mktemp -d)"
trap 'rm -rf "${dir}"' EXIT
gh release download "${tag}" --repo "${repo}" --dir "${dir}"
if command -v sha256sum >/dev/null; then
  (cd "${dir}" && sha256sum --check --strict checksums.txt)
else
  (cd "${dir}" && shasum -a 256 --check --strict checksums.txt)
fi
while read -r _ file; do
  gh attestation verify "${dir}/${file}" "${attest[@]}" >/dev/null
  echo "${file}: provenance OK"
done <"${dir}/checksums.txt"

printf '\nrelease %s verified\n' "${tag}"
