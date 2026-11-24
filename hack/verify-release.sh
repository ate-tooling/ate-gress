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
#
# The ategressctl binaries are release files, checked with the rest: their
# checksums, their provenance, their SBOM attestation, and, for the one built
# for this machine, that it runs and reports the release's version.
set -euo pipefail

version="${1:?usage: $0 <version> [image] [charts] [owner/repo]}"
version="${version#v}"
image="${2:-ghcr.io/ate-tooling/ate-gress}"
charts="${3:-ghcr.io/ate-tooling/charts}"
repo="${4:-ate-tooling/ate-gress}"
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

step "ategressctl: every platform is published, with an SBOM"
# The platforms hack/build-ategressctl.sh builds.
for platform in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
  file="ategressctl-${version}-${platform}"
  # Listed in checksums.txt, so the checksum and provenance checks above
  # covered it.
  if ! awk -v f="${file}" '$2 == f { found = 1 } END { exit !found }' "${dir}/checksums.txt"; then
    echo "the release has no ${file}" >&2
    exit 1
  fi
  gh attestation verify "${dir}/${file}" "${attest[@]}" \
    --predicate-type https://spdx.dev/Document/v2.3 >/dev/null
  echo "${file}: SBOM OK"
done

step "ategressctl: runs and reports its version"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) arch="" ;;
esac
bin="${dir}/ategressctl-${version}-${os}-${arch}"
if [[ -f "${bin}" ]]; then
  chmod +x "${bin}"
  got="$("${bin}" version)"
  if [[ "${got}" != "${version}" ]]; then
    echo "${bin##*/} reports version '${got}', want '${version}'" >&2
    exit 1
  fi
  echo "${bin##*/}: version ${got}"
else
  echo "no binary for ${os}/${arch}; skipped"
fi

printf '\nrelease %s verified\n' "${tag}"
