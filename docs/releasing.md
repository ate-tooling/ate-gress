# Releasing

## What a release is

A `vX.Y.Z` tag (or `vX.Y.Z-rc.N` for a prerelease) on a commit of `main`
runs [`release.yaml`](../.github/workflows/release.yaml). It publishes:

| Artifact | Where | Signed | Attestations |
|---|---|---|---|
| Image, `linux/amd64` and `linux/arm64` | `ghcr.io/ate-tooling/ate-gress:X.Y.Z` (and `:X.Y` for full releases) | cosign, keyless | SLSA build provenance, SPDX SBOM |
| Helm chart, pinned to the image digest | `oci://ghcr.io/ate-tooling/charts/ate-gress`, version `X.Y.Z` | cosign, keyless | SLSA build provenance |
| CRD, chart archive, SBOM, `checksums.txt` | the GitHub release | | SLSA build provenance for each file |
| `ategressctl`, for `linux` and `darwin` on `amd64` and `arm64`, and its SBOM | the GitHub release, as `ategressctl-X.Y.Z-<os>-<arch>` | | SLSA build provenance for each file, SPDX SBOM for each binary |

Release files are not signed with cosign. Their attestations are Sigstore
bundles all the same: signed with a certificate Fulcio issued to this
workflow, and recorded in Rekor. `gh attestation verify` checks them.

There is no `latest` tag. Deployments pin a version, and the chart pins the
image by digest.

## The pipeline

```
tag vX.Y.Z
  ├─ ci            the full CI workflow: lint, unit, race, envtest, fuzz, real Envoy, image build,
  │                chart upgrade from the last published version, and rollback to it
  ├─ plan          version from the tag; refuses a version whose image already exists
  ├─ image         buildx multi-arch → push → cosign sign → provenance → syft SBOM → SBOM attestation
  ├─ chart         package with image.digest set → push → cosign sign → provenance
  ├─ cli           ategressctl for four platforms → run it → syft SBOM → SBOM attestation
  ├─ github-release CRD + chart + SBOMs + ategressctl + checksums, provenance over the checksums
  └─ verify        hack/verify-release.sh, the same checks a consumer runs
```

Some properties the pipeline guarantees:

- **Gated.** Nothing is published unless the tagged commit passes all of
  `ci`. The nightly workflows in [ci.md](ci.md) (Substrate end to end,
  Envoy's `main`, long fuzzing) gate nothing; check that they are green
  before tagging.
- **Immutable.** Image tags are never overwritten, and neither are release
  versions: `gh release create` refuses a tag that already has a release.
- **Least privilege.** The workflow token is read-only. Each job is granted
  only the write scopes it uses, and each scope is commented with the reason.
- **Pinned.** Every action is pinned to a commit SHA, and both base images are
  pinned by digest. Dependabot proposes updates, each one at least a week
  after its release.
- **Reproducible inputs.** Image timestamps come from the commit time
  (`SOURCE_DATE_EPOCH`). The binaries are built with `-trimpath`, and
  `ategressctl` without the Go build cache.
- **Audited.** `zizmor` (pedantic) and `actionlint` check the workflows in CI.

Signing is keyless. There is no long-lived key to leak. Each signature is
issued by Sigstore's Fulcio to the workflow's GitHub OIDC identity, and is
recorded in the Rekor transparency log.

## Cutting a release

```sh
git switch main && git pull
git tag -s v0.1.0 -m v0.1.0      # or v0.1.0-rc.1
git push origin v0.1.0
```

Watch the run: `gh run watch`. A release is done when its `Verify release`
job is green.

**The first time only:** GHCR creates packages as private. After the first
run, make `ate-gress` and `charts/ate-gress` public. Do this under the
package settings at github.com/orgs/ate-tooling/packages, or anonymous
users can't pull or verify them.

**If a run fails** before `github-release`, delete the tag and push it again
once the cause is fixed. If the image was already pushed, use the next patch
version instead: published versions are never reused.

## Verifying a release

Every check below pins the signer to this repository's release workflow,
running on a GitHub-hosted runner for that exact tag. A valid signature from
any other workflow, branch or fork is rejected.

The short way, which runs every check below:

```sh
hack/verify-release.sh 0.1.0
```

By hand, for the image:

```sh
VERSION=0.1.0
IMAGE=ghcr.io/ate-tooling/ate-gress:$VERSION

cosign verify "$IMAGE" \
  --certificate-identity "https://github.com/ate-tooling/ate-gress/.github/workflows/release.yaml@refs/tags/v$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Build provenance: which commit, which workflow, which runner.
gh attestation verify "oci://$IMAGE" --repo ate-tooling/ate-gress \
  --signer-workflow github.com/ate-tooling/ate-gress/.github/workflows/release.yaml \
  --source-ref "refs/tags/v$VERSION" --deny-self-hosted-runners

# The SBOM, verified and printed.
gh attestation verify "oci://$IMAGE" --repo ate-tooling/ate-gress \
  --predicate-type https://spdx.dev/Document/v2.3 --format json \
  | jq '.[0].verificationResult.statement.predicate'
```

The chart is verified the same way, using
`ghcr.io/ate-tooling/charts/ate-gress:$VERSION`. It renders the image by
digest, so verifying the chart pins the image:

```sh
helm template ate-gress oci://ghcr.io/ate-tooling/charts/ate-gress --version "$VERSION" | grep image:
```

For a release file:

```sh
gh release download "v$VERSION" --repo ate-tooling/ate-gress
sha256sum --check checksums.txt
gh attestation verify ate-gress-$VERSION-crds.yaml --repo ate-tooling/ate-gress
```

For `ategressctl`, the same, pinned to the workflow and tag as the image is.
The binary is a release file, so `checksums.txt` lists it and its provenance
is verified like the CRD's:

```sh
BIN=ategressctl-$VERSION-linux-amd64   # or linux-arm64, darwin-amd64, darwin-arm64

gh attestation verify "$BIN" --repo ate-tooling/ate-gress \
  --signer-workflow github.com/ate-tooling/ate-gress/.github/workflows/release.yaml \
  --source-ref "refs/tags/v$VERSION" --deny-self-hosted-runners

# Its SBOM: the Go modules compiled into it.
gh attestation verify "$BIN" --repo ate-tooling/ate-gress \
  --predicate-type https://spdx.dev/Document/v2.3 --format json \
  | jq '.[0].verificationResult.statement.predicate'

chmod +x "$BIN" && "./$BIN" version   # prints $VERSION
```

GitHub does not keep a file's mode, so the downloaded binary needs the
`chmod`.

### Enforcing it in the cluster

To have the cluster refuse unsigned images, use an admission policy, such as a
[Sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/)
`ClusterImagePolicy` or a Kyverno `verifyImages` rule. Match on the same
issuer, plus a subject regular expression:
`^https://github.com/ate-tooling/ate-gress/.github/workflows/release.yaml@refs/tags/v`.
