#!/usr/bin/env bash
# Upgrade test on a throwaway kind cluster: installs a published chart,
# upgrades it to the chart in the working tree, and checks that the upgrade
# brought the EgressRoutePolicy CRD with it.
#
#   hack/upgrade-kind.sh [published chart version | latest]
#
# Without a version, or with "latest", it starts from the newest published
# chart, prereleases included. Charts up to 0.1.0-rc.4 shipped the CRD in crds/, which Helm never
# upgrades and does not own, so the test adopts the CRD into the release first,
# as the README tells users of those charts to.
#
# It does not need Substrate. Without it the pods never start, because they
# mount pod certificates, so nothing here waits for them: the test is about
# the CRD.
#
# Needs docker, kind, kubectl, helm and jq.
#
# Environment:
#   KIND_CLUSTER_NAME  cluster to create (default ate-gress-upgrade)
#   CHART              published chart (default oci://ghcr.io/ate-tooling/charts/ate-gress)
#   KEEP               1 leaves the cluster in place

set -o errexit -o nounset -o pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [published chart version | latest]" >&2
  exit 2
fi
from="${1:-latest}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cluster="${KIND_CLUSTER_NAME:-ate-gress-upgrade}"
context="kind-${cluster}"
chart="${CHART:-oci://ghcr.io/ate-tooling/charts/ate-gress}"
release="ate-gress"
namespace="ate-gress"
crd="egressroutepolicies.ategress.ate-tooling.github.io"
kubectl=(kubectl --context "${context}")
helm=(helm --kube-context "${context}")

work="$(mktemp -d)"
# A kubeconfig of its own: kind would otherwise switch the caller's current
# context to the new cluster, and unset it when the cluster is deleted.
export KUBECONFIG="${work}/kubeconfig"
cleanup() {
  status=$?
  if [[ ${status} -ne 0 ]]; then diagnostics || true; fi
  if [[ "${KEEP:-}" == "1" ]]; then
    echo "kept cluster ${cluster}; \`kind export kubeconfig --name ${cluster}\` adds it to your kubeconfig"
  else
    kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
  fi
  rm -rf "${work}"
  exit "${status}"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

diagnostics() {
  step "diagnostics"
  "${helm[@]}" list --all-namespaces || true
  "${kubectl[@]}" get crd "${crd}" -o jsonpath='{.metadata.labels}{"\n"}{.metadata.annotations}{"\n"}' || true
  "${kubectl[@]}" get egressroutepolicies -o yaml || true
}

# schema FILE prints what a CRD manifest says about its versions, in a form
# that compares.
schema() { "${kubectl[@]}" create --dry-run=client -o json -f "$1" | jq -S '.spec.versions'; }
live_schema() { "${kubectl[@]}" get crd "${crd}" -o json | jq -S '.spec.versions'; }
policy_spec() { "${kubectl[@]}" get egressroutepolicy "$1" -o json | jq -S '.spec'; }

step "creating kind cluster ${cluster}"
kind create cluster --name "${cluster}" --wait 2m

step "installing the published chart"
version=(--devel)
if [[ "${from}" != "latest" ]]; then version=(--version "${from#v}"); fi
mkdir "${work}/from"
helm pull "${chart}" "${version[@]}" --destination "${work}/from"
previous="$(find "${work}/from" -name '*.tgz')"
echo "from: $(basename "${previous}")"
"${helm[@]}" install "${release}" "${previous}" --namespace "${namespace}" --create-namespace
"${kubectl[@]}" wait crd "${crd}" --for=condition=Established --timeout=1m

# A policy the old schema accepts. It must survive the upgrade untouched.
cat >"${work}/before.yaml" <<'EOF'
apiVersion: ategress.ate-tooling.github.io/v1alpha1
kind: EgressRoutePolicy
metadata:
  name: upgrade-before
spec:
  enforcementMode: Audit
  hosts:
  - host: api.github.com
    routes:
    - methods: [GET]
      paths: [/repos/acme/*]
EOF
"${kubectl[@]}" create -f "${work}/before.yaml"
before="$(policy_spec upgrade-before)"

want_schema="$(schema "${root}/config/crd/ategress.ate-tooling.github.io_egressroutepolicies.yaml")"
if [[ "$(live_schema)" == "${want_schema}" ]]; then
  echo "the published chart already has the working tree's schema; the upgrade has nothing to change in it"
else
  echo "the published chart's schema differs from the working tree's; the upgrade must replace it"
fi

step "adopting the CRD into the release"
# The same commands as in the README. They change nothing on a CRD that a
# chart with a templated CRD installed, which the release owns already.
"${kubectl[@]}" label crd "${crd}" --overwrite app.kubernetes.io/managed-by=Helm
"${kubectl[@]}" annotate crd "${crd}" --overwrite \
  "meta.helm.sh/release-name=${release}" "meta.helm.sh/release-namespace=${namespace}"

step "upgrading to the working tree's chart"
"${helm[@]}" upgrade "${release}" "${root}/charts/ate-gress" --namespace "${namespace}"

step "checking the CRD"
if [[ "$(live_schema)" != "${want_schema}" ]]; then
  diff <(echo "${want_schema}") <(live_schema) || true
  fail "the cluster's CRD schema is not the working tree's after the upgrade"
fi
echo "ok    the cluster's CRD schema is the working tree's"
"${kubectl[@]}" wait crd "${crd}" --for=condition=Established --timeout=1m >/dev/null
if [[ "$(policy_spec upgrade-before)" != "${before}" ]]; then
  fail "the policy created before the upgrade changed"
fi
echo "ok    the policy created before the upgrade is unchanged"

step "checking a policy that uses the newest fields"
# Every field is set, so the API server defaults nothing and what it stores
# must be exactly this.
cat >"${work}/after.yaml" <<'EOF'
apiVersion: ategress.ate-tooling.github.io/v1alpha1
kind: EgressRoutePolicy
metadata:
  name: upgrade-after
spec:
  actorSelector:
    atespaces: [research]
  enforcementMode: Enforce
  logAllowed: true
  hosts:
  - host: registry.example.com
    routes:
    - methods: [GET, HEAD]
      paths: [/v2/, /v2/acme/*/]
      caseInsensitive: false
EOF
# Strict validation fails on a field the schema does not know, where the
# default would be to drop it with a warning.
"${kubectl[@]}" create --validate=strict -f "${work}/after.yaml"
want_spec="$("${kubectl[@]}" create --dry-run=client -o json -f "${work}/after.yaml" | jq -S '.spec')"
got_spec="$(policy_spec upgrade-after)"
if [[ "${got_spec}" != "${want_spec}" ]]; then
  diff <(echo "${want_spec}") <(echo "${got_spec}") || true
  fail "the policy did not round-trip unchanged"
fi
echo "ok    logAllowed and a trailing-slash template round-trip unchanged"

step "uninstalling"
# helm.sh/resource-policy: keep. Deleting the CRD would delete every policy.
"${helm[@]}" uninstall "${release}" --namespace "${namespace}"
for p in upgrade-before upgrade-after; do
  "${kubectl[@]}" get egressroutepolicy "${p}" >/dev/null || fail "uninstall deleted policy ${p}"
done
echo "ok    the CRD and both policies outlive the release"

step "upgrade test passed"
