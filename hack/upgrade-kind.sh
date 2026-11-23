#!/usr/bin/env bash
# Upgrade and rollback test on a throwaway kind cluster. It installs an
# earlier chart and upgrades it to the chart in the working tree, then checks
# that the upgrade brought the EgressRoutePolicy CRD with it: existing
# policies are unchanged and readable as every version the CRD now serves,
# and new ones are accepted. Then it rolls back, checks that the cluster has
# the earlier chart's CRD again with every policy still there, and upgrades
# once more.
#
#   hack/upgrade-kind.sh [published chart version | latest | chart directory or .tgz]
#
# Without an argument, or with "latest", it starts from the newest published
# chart, prereleases included. A path starts from a chart that is not
# published, such as another branch's.
#
# Charts up to 0.1.0-rc.4 shipped the CRD in crds/, which Helm never upgrades
# and does not own, so the test adopts the CRD into the release first, as the
# README tells users of those charts to. `helm rollback` to such a chart
# leaves the CRD as it is for the same reason, so the test then applies that
# chart's CRD itself, as the README says.
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
  echo "usage: $0 [published chart version | latest | chart directory or .tgz]" >&2
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
group="${crd#*.}"

# The cleanup below deletes the cluster, so it must be one this run created.
if kind get clusters 2>/dev/null | grep -qxF "${cluster}"; then
  echo "kind cluster ${cluster} already exists; delete it, or set KIND_CLUSTER_NAME" >&2
  exit 2
fi

work="$(mktemp -d)"
# A kubeconfig of its own: kind would otherwise switch the caller's current
# context to the new cluster, and unset it when the cluster is deleted.
export KUBECONFIG="${work}/kubeconfig"
# And a discovery cache of its own. kubectl's default is shared, under
# ~/.kube/cache, and a kind cluster's address is reused by the next one.
kubectl=(kubectl --context "${context}" --cache-dir "${work}/kube-cache")
helm=(helm --kube-context "${context}")
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
  "${helm[@]}" history "${release}" --namespace "${namespace}" || true
  "${kubectl[@]}" get crd "${crd}" -o jsonpath='{.metadata.labels}{"\n"}{.metadata.annotations}{"\n"}{.spec.versions[*].name}{"\n"}{.status.storedVersions}{"\n"}' || true
  "${kubectl[@]}" get egressroutepolicies -o yaml || true
}

# schema FILE prints what a CRD manifest says about its versions, in a form
# that compares.
schema() { "${kubectl[@]}" create --dry-run=client -o json -f "$1" | jq -S '.spec.versions'; }
live_schema() { "${kubectl[@]}" get crd "${crd}" -o json | jq -S '.spec.versions'; }
served_versions() { "${kubectl[@]}" get crd "${crd}" -o json | jq -r '[.spec.versions[] | select(.served) | .name] | join(" ")'; }
stored_versions() { "${kubectl[@]}" get crd "${crd}" -o json | jq -r '.status.storedVersions | join(" ")'; }
# policy NAME [VERSION] prints a policy read as VERSION, or as the version the
# API server prefers.
policy() { "${kubectl[@]}" get "egressroutepolicies${2:+.$2.${group}}" "$1" -o json; }
policy_spec() { policy "$@" | jq -S '.spec'; }
manifest_spec() { "${kubectl[@]}" create --dry-run=client -o json -f "$1" | jq -S '.spec'; }

# expect_schema WANT WHAT fails unless the cluster's CRD has the schema WANT.
expect_schema() {
  if [[ "$(live_schema)" != "$1" ]]; then
    diff <(echo "$1") <(live_schema) || true
    fail "the cluster's CRD schema is not $2"
  fi
  "${kubectl[@]}" wait crd "${crd}" --for=condition=Established --timeout=1m >/dev/null
  echo "ok    the cluster's CRD schema is $2"
}

# expect_policy NAME WANT_SPEC fails unless the policy has that spec under
# every version the CRD serves.
expect_policy() {
  local v got
  for v in $(served_versions); do
    got="$(policy_spec "$1" "${v}")"
    if [[ "${got}" != "$2" ]]; then
      diff <(echo "$2") <(echo "${got}") || true
      fail "policy $1, read as ${v}, is not what was written"
    fi
    if [[ "$(policy "$1" "${v}" | jq -r '.apiVersion')" != "${group}/${v}" ]]; then
      fail "policy $1, read as ${v}, has another apiVersion"
    fi
  done
  echo "ok    policy $1 is unchanged, read as: $(served_versions)"
}

# The README's commands for a CRD that a chart shipped in crds/.
adopt_crd() {
  "${kubectl[@]}" label crd "${crd}" --overwrite app.kubernetes.io/managed-by=Helm
  "${kubectl[@]}" annotate crd "${crd}" --overwrite \
    "meta.helm.sh/release-name=${release}" "meta.helm.sh/release-namespace=${namespace}"
}

step "creating kind cluster ${cluster}"
kind create cluster --name "${cluster}" --wait 2m

step "installing the earlier chart"
if [[ -e "${from}" ]]; then
  previous="${from}"
else
  version=(--devel)
  if [[ "${from}" != "latest" ]]; then version=(--version "${from#v}"); fi
  mkdir "${work}/from"
  helm pull "${chart}" "${version[@]}" --destination "${work}/from"
  previous="$(find "${work}/from" -name '*.tgz')"
fi
echo "from: $(basename "${previous}")"
"${helm[@]}" install "${release}" "${previous}" --namespace "${namespace}" --create-namespace
"${kubectl[@]}" wait crd "${crd}" --for=condition=Established --timeout=1m

# The earlier chart's CRD: what the rollback must bring back.
previous_crd="${work}/previous-crd.yaml"
helm show crds "${previous}" >"${previous_crd}"
if grep -q CustomResourceDefinition "${previous_crd}"; then
  crd_in_release=false
  echo "the earlier chart ships the CRD in crds/, outside the release"
else
  crd_in_release=true
  helm template "${release}" "${previous}" --namespace "${namespace}" --show-only templates/crds.yaml >"${previous_crd}"
  echo "the earlier chart ships the CRD in the release"
fi
previous_schema="$(schema "${previous_crd}")"
previous_versions="$(jq -r '[.[].name] | join(" ")' <<<"${previous_schema}")"
echo "the earlier chart's CRD has: ${previous_versions}"

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
  echo "the earlier chart already has the working tree's schema; the upgrade has nothing to change in it"
else
  echo "the earlier chart's schema differs from the working tree's; the upgrade must replace it"
fi

step "adopting the CRD into the release"
# They change nothing on a CRD that a chart with a templated CRD installed,
# which the release owns already.
adopt_crd

step "upgrading to the working tree's chart"
"${helm[@]}" upgrade "${release}" "${root}/charts/ate-gress" --namespace "${namespace}"

step "checking the CRD"
expect_schema "${want_schema}" "the working tree's"
echo "served: $(served_versions); stored: $(stored_versions)"
# The API server refuses a CRD that lacks a version objects were ever stored
# in. So a chart that changes the storage version cannot be rolled back, and
# may only do so once every chart a user might roll back to has that version.
for v in $(stored_versions); do
  if [[ " ${previous_versions} " != *" ${v} "* ]]; then
    fail "objects are now stored as ${v}, which the earlier chart's CRD lacks: a rollback would be refused"
  fi
done
echo "ok    every stored version is one the earlier chart has, so it can be rolled back to"
expect_policy upgrade-before "${before}"

step "checking what kubectl shows"
# With no version named, kubectl uses the one the API server prefers: the
# most mature that is served, whichever is stored.
preferred="$("${kubectl[@]}" get egressroutepolicy upgrade-before -o jsonpath='{.apiVersion}')"
if [[ "${preferred}" != "${group}/v1beta1" ]]; then
  fail "kubectl get returns ${preferred}, not v1beta1"
fi
echo "ok    kubectl get returns ${preferred}"
header="$("${kubectl[@]}" get erp upgrade-before | head -n 1 | xargs)"
if [[ "${header}" != "NAME MODE ACCEPTED AGE" ]]; then
  fail "kubectl get erp prints the columns: ${header}"
fi
echo "ok    kubectl get erp prints: ${header}"

step "checking a policy that uses the newest fields"
# Every field is set, so the API server defaults nothing and what it stores
# must be exactly this. It is still written as v1alpha1, as manifests that
# predate v1beta1 are.
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
expect_policy upgrade-after "$(manifest_spec "${work}/after.yaml")"

step "checking a policy written as v1beta1"
# Only fields every published chart has, so that it reads back unchanged
# after the rollback too.
cat >"${work}/beta.yaml" <<'EOF'
apiVersion: ategress.ate-tooling.github.io/v1beta1
kind: EgressRoutePolicy
metadata:
  name: upgrade-beta
spec:
  actorSelector:
    atespaces: [research]
    names: [agent-*]
  enforcementMode: Enforce
  hosts:
  - host: api.github.com
    routes:
    - methods: [GET, HEAD]
      paths: [/orgs/acme, /orgs/acme/**]
      caseInsensitive: true
EOF
"${kubectl[@]}" create --validate=strict -f "${work}/beta.yaml"
beta="$(manifest_spec "${work}/beta.yaml")"
expect_policy upgrade-beta "${beta}"
"${kubectl[@]}" apply --dry-run=server --validate=strict -f "${root}/examples" >/dev/null
echo "ok    the API server accepts examples/"

step "re-applying a v1alpha1 manifest"
# What a GitOps tool does on every sync with manifests that still say
# v1alpha1. The first apply only records kubectl as an owner of the fields;
# after it, an apply must change nothing and a diff must be empty.
"${kubectl[@]}" apply --server-side -f "${work}/before.yaml"
applied="$(policy upgrade-before | jq -r '.metadata.resourceVersion')"
"${kubectl[@]}" apply --server-side -f "${work}/before.yaml"
"${kubectl[@]}" diff --server-side -f "${work}/before.yaml" || fail "kubectl diff of an unchanged v1alpha1 manifest is not empty"
if [[ "$(policy upgrade-before | jq -r '.metadata.resourceVersion')" != "${applied}" ]]; then
  fail "re-applying an unchanged v1alpha1 manifest wrote to the policy"
fi
if [[ "$(policy upgrade-before | jq -r '.metadata.generation')" != "1" ]]; then
  fail "re-applying a v1alpha1 manifest changed the policy's spec"
fi
echo "ok    re-applying an unchanged v1alpha1 manifest writes nothing and shows no diff"

step "rolling back to the earlier chart"
"${helm[@]}" rollback "${release}" 1 --namespace "${namespace}"
if [[ "${crd_in_release}" == "false" ]]; then
  # The earlier release never held the CRD, so Helm has nothing to roll it
  # back to, and helm.sh/resource-policy: keep stops it deleting what the
  # release no longer has.
  expect_schema "${want_schema}" "still the working tree's after helm rollback"
  # --force-conflicts: Helm owns .spec.versions since the upgrade.
  "${kubectl[@]}" apply --server-side --force-conflicts -f "${previous_crd}"
fi
expect_schema "${previous_schema}" "the earlier chart's"
echo "served: $(served_versions); stored: $(stored_versions)"
# A policy with fields the earlier schema lacks is still stored with them,
# and reads back without them until the CRD has them again. So only policies
# the earlier schema holds in full are compared.
expect_policy upgrade-before "${before}"
expect_policy upgrade-beta "${beta}"
# kubectl has cached v1beta1 as the version to ask for when none is named,
# and would get a 404 for it now.
rm -rf "${work}/kube-cache"
"${kubectl[@]}" get egressroutepolicy upgrade-after >/dev/null || fail "the rollback deleted policy upgrade-after"
echo "ok    all three policies outlive the rollback"

step "upgrading again"
upgrade=(upgrade "${release}" "${root}/charts/ate-gress" --namespace "${namespace}")
if [[ "${crd_in_release}" == "false" ]]; then
  # kubectl owns .spec.versions since it applied the earlier CRD, and Helm 4
  # stops at the conflict unless told to take the field back.
  upgrade+=(--force-conflicts)
fi
"${helm[@]}" "${upgrade[@]}"
expect_schema "${want_schema}" "the working tree's"
expect_policy upgrade-before "${before}"
expect_policy upgrade-beta "${beta}"
expect_policy upgrade-after "$(manifest_spec "${work}/after.yaml")"

step "uninstalling"
# helm.sh/resource-policy: keep. Deleting the CRD would delete every policy.
"${helm[@]}" uninstall "${release}" --namespace "${namespace}"
for p in upgrade-before upgrade-after upgrade-beta; do
  "${kubectl[@]}" get egressroutepolicy "${p}" >/dev/null || fail "uninstall deleted policy ${p}"
done
echo "ok    the CRD and the policies outlive the release"

step "upgrade test passed"
