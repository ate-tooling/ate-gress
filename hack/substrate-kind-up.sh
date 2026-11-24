#!/usr/bin/env bash
# Creates a kind cluster and installs Agent Substrate on it, ready for
# hack/e2e-kind.sh. The nightly end-to-end workflow runs this; so can you.
#
#   hack/substrate-kind-up.sh <upstream substrate checkout>
#   hack/e2e-kind.sh <upstream substrate checkout>
#
# The cluster comes from the checkout's own hack/create-kind-cluster.sh, which
# knows the Kubernetes version and the feature gates that Substrate needs and
# starts a registry on localhost:5001. Substrate is then installed one of two
# ways (SUBSTRATE_INSTALL):
#
#   operator   The agent-substrate-operator chart, version OPERATOR_VERSION,
#              and a SubstrateInstall. The operator installs the Substrate
#              release it embeds from published images, whatever the checkout
#              holds; the checkout should be that release
#              (hack/substrate-pins.env), because e2e-kind.sh builds the demo
#              actor and kubectl-ate from it.
#   ate-setup  Substrate's own installer, run from the checkout, so the
#              manifests are the checkout's. The images are built from the
#              checkout too, unless SUBSTRATE_IMAGE_REPO and
#              SUBSTRATE_IMAGE_TAG name published ones. This is the way to
#              install a Substrate that has no release, such as its main
#              branch.
#
# Only the gVisor sandbox class is installed: micro-VM sandboxes need KVM,
# and nothing in the end-to-end test uses them.
#
# Environment:
#   KIND_CLUSTER_NAME    cluster to create (default substrate)
#   RECREATE             1 replaces the cluster if it exists; otherwise an
#                        existing cluster is an error
#   SUBSTRATE_INSTALL    operator (default) or ate-setup
#   OPERATOR_VERSION     operator chart version (default: hack/substrate-pins.env)
#   SUBSTRATE_IMAGE_REPO, SUBSTRATE_IMAGE_TAG
#                        with ate-setup, install these images instead of
#                        building them
#   ATE_RECORD_DIR       where ate-setup records the install for e2e-kind.sh
#                        (default bin/ate-setup in this repository)

set -o errexit -o nounset -o pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <upstream substrate checkout>" >&2
  exit 2
fi
upstream="$(cd "$1" && pwd)"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cluster="${KIND_CLUSTER_NAME:-substrate}"
context="kind-${cluster}"
install="${SUBSTRATE_INSTALL:-operator}"
registry="localhost:5001"
arch="$(go env GOARCH)"
kubectl=(kubectl --context "${context}")
# kubectl ate proxy, which e2e-kind.sh reaches the actors through, dials the
# ingress router as this service account. The router admits no other client.
proxy_client="spiffe://cluster.local/ns/ate-system/sa/atenet-client"

# The defaults for the pinned Substrate; the environment overrides them.
operator_version="${OPERATOR_VERSION:-$(sed -n 's/^OPERATOR_VERSION=//p' "${root}/hack/substrate-pins.env")}"

step() { printf '\n==> %s\n' "$*"; }

case "${install}" in
operator | ate-setup) ;;
*)
  echo "SUBSTRATE_INSTALL must be operator or ate-setup, got '${install}'" >&2
  exit 2
  ;;
esac
if [[ -n "${SUBSTRATE_IMAGE_REPO:-}" && -z "${SUBSTRATE_IMAGE_TAG:-}" || -z "${SUBSTRATE_IMAGE_REPO:-}" && -n "${SUBSTRATE_IMAGE_TAG:-}" ]]; then
  echo "SUBSTRATE_IMAGE_REPO and SUBSTRATE_IMAGE_TAG are set together or not at all" >&2
  exit 2
fi

# The upstream script replaces a cluster of the same name without asking.
if docker container inspect "${cluster}-control-plane" >/dev/null 2>&1 && [[ "${RECREATE:-}" != "1" ]]; then
  echo "kind cluster '${cluster}' exists. Set RECREATE=1 to replace it, or KIND_CLUSTER_NAME to use another name." >&2
  exit 1
fi

diagnostics() {
  step "diagnostics"
  "${kubectl[@]}" get substrateinstall substrate -o yaml 2>/dev/null || true
  "${kubectl[@]}" get pods -A -o wide || true
  "${kubectl[@]}" get events -A --field-selector type!=Normal --sort-by=.lastTimestamp | tail -n 40 || true
  "${kubectl[@]}" -n substrate-operator logs deploy/substrate-operator --tail=100 2>/dev/null || true
}
on_exit() {
  status=$?
  if [[ ${status} -ne 0 ]]; then diagnostics || true; fi
  exit "${status}"
}
trap on_exit EXIT

step "creating kind cluster ${cluster} from $(git -C "${upstream}" describe --tags --always)"
# Upstream's scripts find their tools from the git root of the directory they
# run in.
(cd "${upstream}" && KIND_CLUSTER_NAME="${cluster}" hack/create-kind-cluster.sh)

if [[ "${install}" == operator ]]; then
  step "installing agent-substrate-operator ${operator_version}"
  values="$(mktemp)"
  cat >"${values}" <<EOF
substrateInstall:
  enabled: true
  spec:
    platform: kind
    atenet:
      credentialProvider:
        name: k8s.io
      ingressAllowedSPIFFEIDs:
      - ${proxy_client}
    deletionPolicy: Delete
EOF
  helm --kube-context "${context}" upgrade --install substrate-operator \
    oci://ghcr.io/ate-tooling/charts/agent-substrate-operator --version "${operator_version}" \
    --namespace substrate-operator --create-namespace --values "${values}" --wait --timeout 5m
  rm -f "${values}"

  step "waiting for the SubstrateInstall to become Ready"
  "${kubectl[@]}" wait substrateinstall/substrate --for=condition=Ready --timeout=20m
  "${kubectl[@]}" get substrateinstall substrate
else
  flags=(--no-dev-env --kind --kind-cluster-name "${cluster}"
    --record-dir "${ATE_RECORD_DIR:-${root}/bin/ate-setup}"
    --rollout-timeout 10m
    --credential-provider '{"name":"k8s.io"}'
    --ingress-allowed-spiffe-ids "${proxy_client}")
  if [[ -n "${SUBSTRATE_IMAGE_REPO:-}" ]]; then
    step "installing Substrate with ate-setup, from ${SUBSTRATE_IMAGE_REPO} at ${SUBSTRATE_IMAGE_TAG}"
    flags+=(--image-repo "${SUBSTRATE_IMAGE_REPO}" --image-tag "${SUBSTRATE_IMAGE_TAG}")
  else
    step "installing Substrate with ate-setup, building the checkout"
    flags+=(--ko-docker-repo "${registry}/substrate" --ko-default-platforms "linux/${arch}")
    # ate-setup builds the gateway image with docker buildx. A
    # docker-container builder cannot push to the registry on the host's
    # localhost; the docker driver's builder, named after the context, can.
    BUILDX_BUILDER="${BUILDX_BUILDER:-$(docker context show)}"
    export BUILDX_BUILDER
  fi
  (cd "${upstream}" && go run ./cmd/ate-setup "${flags[@]}" deploy ate-system --sandbox-classes=gvisor)
fi

step "Substrate is up on ${context}"
"${kubectl[@]}" -n ate-system get pods
echo
echo "Next: KIND_CLUSTER_NAME=${cluster} hack/e2e-kind.sh ${upstream}"
