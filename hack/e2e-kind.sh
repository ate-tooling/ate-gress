#!/usr/bin/env bash
# End-to-end test on a kind cluster that runs Agent Substrate, installed by
# the agent-substrate-operator or by Substrate's own ate-setup
# (hack/substrate-kind-up.sh does either). It installs ate-gress from its
# chart, points the Substrate egress gateway at it, and drives real actor
# traffic through the gateway and ate-gress:
#
#   - cleartext HTTP to an in-cluster target, which needs nothing outside the
#     cluster;
#   - HTTPS to api.github.com, through the gateway's TLS MITM leg, unless
#     E2E_GITHUB=0.
#
#   hack/e2e-kind.sh <upstream substrate checkout>
#
# The checkout should be the Substrate the cluster runs. kubectl-ate is built
# from it, and so is the upstream egress demo actor, into the kind registry,
# if the ate-demo-egress/egress actor template does not exist yet. On a
# cluster ate-setup installed, the checkout's ate-setup also redeploys the
# gateway.
#
# Environment:
#   KIND_CLUSTER_NAME  cluster to use (default substrate)
#   E2E_GITHUB         0 skips the api.github.com checks
#   KEEP               1 leaves the actors and policies in place
#   ATE_RECORD_DIR     where ate-setup recorded the install, if it made it
#                      (default bin/ate-setup in this repository)

set -o errexit -o nounset -o pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <upstream substrate checkout>" >&2
  exit 2
fi
upstream="$(cd "$1" && pwd)"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cluster="${KIND_CLUSTER_NAME:-substrate}"
context="kind-${cluster}"
registry="localhost:5001"
image="${registry}/ate-gress:e2e"
arch="$(go env GOARCH)"
atespace="ate-demo-egress"
kubectl=(kubectl --context "${context}")
target="whoami.ate-gress-e2e.svc.cluster.local"
extproc="ate-gress/ate-gress:9443"
record_dir="${ATE_RECORD_DIR:-${root}/bin/ate-setup}"

BUILDX_BUILDER="${BUILDX_BUILDER:-$(docker context show)}"
export BUILDX_BUILDER

work="$(mktemp -d)"
# Built from the checkout below, so it is the client of the Substrate under
# test and not whichever kubectl-ate is on PATH.
kubectl_ate=("${work}/kubectl-ate" --context "${context}")
proxies=()
failures=0
cleanup() {
  status=$?
  for p in "${proxies[@]}"; do kill "${p}" 2>/dev/null && wait "${p}" 2>/dev/null || true; done
  if [[ ${status} -ne 0 ]]; then diagnostics || true; fi
  if [[ "${KEEP:-}" != "1" ]]; then
    for a in e2e-research e2e-other; do "${kubectl_ate[@]}" delete actor "${a}" -a "${atespace}" >/dev/null 2>&1 || true; done
    "${kubectl[@]}" delete egressroutepolicy -l e2e.ategress.ate-tooling.github.io/suite=kind --ignore-not-found >/dev/null 2>&1 || true
  fi
  rm -rf "${work}"
  exit "${status}"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }

diagnostics() {
  step "diagnostics"
  "${kubectl[@]}" get egressroutepolicies -o wide || true
  "${kubectl[@]}" -n ate-gress get pods -o wide || true
  "${kubectl[@]}" -n ate-gress logs -l app.kubernetes.io/name=ate-gress --tail=50 --prefix || true
  "${kubectl[@]}" -n ate-system logs deploy/atenet-egress -c envoy --tail=30 || true
  "${kubectl[@]}" -n ate-system get pods -o wide || true
  "${kubectl[@]}" -n "${atespace}" get pods -o wide || true
}

# ate_setup runs the checkout's installer against the cluster.
ate_setup() {
  (cd "${upstream}" && go run ./cmd/ate-setup --no-dev-env "$@")
}

step "building kubectl-ate from $(git -C "${upstream}" describe --tags --always)"
(cd "${upstream}" && go build -o "${work}/kubectl-ate" ./cmd/kubectl-ate)

step "building ate-gress into the kind registry"
docker buildx build --platform "linux/${arch}" --load -t "${image}" "${root}" >/dev/null
docker push -q "${image}"

step "installing ate-gress"
"${kubectl[@]}" apply --server-side -f "${root}/config/crd/"
helm --kube-context "${context}" upgrade --install ate-gress "${root}/charts/ate-gress" \
  --namespace ate-gress --create-namespace --wait --timeout 5m \
  --set image.repository="${image%:*}" --set image.tag="${image##*:}" --set image.pullPolicy=Always
"${kubectl[@]}" -n ate-gress rollout restart deploy/ate-gress
"${kubectl[@]}" -n ate-gress rollout status deploy/ate-gress --timeout=5m

step "pointing Substrate's egress gateway at ate-gress"
if "${kubectl[@]}" get substrateinstall substrate >/dev/null 2>&1; then
  "${kubectl[@]}" patch substrateinstall substrate --type merge \
    -p "{\"spec\":{\"atenet\":{\"additionalEgressExtprocService\":\"${extproc}\"}}}"
  "${kubectl[@]}" wait substrateinstall/substrate --for=condition=Ready --timeout=10m
else
  # No operator: ate-setup installed this cluster. Its flag is the extension
  # point itself, and takes effect by redeploying the gateway with the
  # settings the install recorded.
  record="${record_dir}/installs/${context}.yaml"
  if [[ ! -f "${record}" ]]; then
    echo "The cluster has no SubstrateInstall, and ate-setup recorded no install of it at ${record}." >&2
    echo "Install Substrate with hack/substrate-kind-up.sh, or set ATE_RECORD_DIR." >&2
    exit 1
  fi
  ate_setup --config "${record}" --record-dir "${record_dir}" \
    --experimental-additional-egress-extproc-service="${extproc}" deploy atenet
fi
"${kubectl[@]}" -n ate-system rollout status deploy/atenet-egress --timeout=5m

if ! "${kubectl_ate[@]}" get actor-template egress -a "${atespace}" >/dev/null 2>&1; then
  step "deploying the upstream egress demo"
  ate_setup --kind --kind-cluster-name "${cluster}" \
    --ko-docker-repo "${registry}/substrate" --ko-default-platforms "linux/${arch}" \
    --rollout-timeout 5m deploy demo egress
fi

step "deploying an in-cluster target"
"${kubectl[@]}" apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: ate-gress-e2e
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: whoami
  namespace: ate-gress-e2e
spec:
  selector:
    matchLabels: {app: whoami}
  template:
    metadata:
      labels: {app: whoami}
    spec:
      containers:
      - name: whoami
        image: docker.io/traefik/whoami:v1.11
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: whoami
  namespace: ate-gress-e2e
spec:
  selector: {app: whoami}
  ports:
  - port: 80
EOF
"${kubectl[@]}" -n ate-gress-e2e rollout status deploy/whoami --timeout=3m

step "applying EgressRoutePolicies"
"${kubectl[@]}" apply -f - <<EOF
# Nobody reaches the target or api.github.com except as a later policy allows.
apiVersion: ategress.ate-tooling.github.io/v1alpha1
kind: EgressRoutePolicy
metadata:
  name: e2e-lockdown
  labels: {e2e.ategress.ate-tooling.github.io/suite: kind}
spec:
  hosts:
  - host: ${target}
  - host: api.github.com
---
# e2e-research may read the acme "org" on the target, and the kubernetes org on
# GitHub.
apiVersion: ategress.ate-tooling.github.io/v1alpha1
kind: EgressRoutePolicy
metadata:
  name: e2e-research
  labels: {e2e.ategress.ate-tooling.github.io/suite: kind}
spec:
  actorSelector:
    atespaces: [${atespace}]
    names: [e2e-research]
  hosts:
  - host: ${target}
    routes:
    - methods: [GET]
      paths: [/repos/acme/*, /repos/acme/*/**]
      caseInsensitive: true
  - host: api.github.com
    routes:
    - methods: [GET, HEAD]
      paths: [/repos/kubernetes/*, /repos/kubernetes/*/**, /orgs/kubernetes]
      caseInsensitive: true
EOF
"${kubectl[@]}" wait egressroutepolicy -l e2e.ategress.ate-tooling.github.io/suite=kind \
  --for=condition=Accepted --timeout=1m

step "creating actors"
port=18000
for a in e2e-research e2e-other; do
  "${kubectl_ate[@]}" get actor "${a}" -a "${atespace}" >/dev/null 2>&1 ||
    "${kubectl_ate[@]}" create actor "${a}" -a "${atespace}" --template egress
  # Substrate's own EgressPolicy allows both hosts; ate-gress narrows them.
  "${kubectl_ate[@]}" delete egress-policy "${a}" -a "${atespace}" >/dev/null 2>&1 || true
  "${kubectl_ate[@]}" create egress-policy "${a}" -a "${atespace}" -f - <<EOF
rules:
- http: {hostnames: ["${target}"], ports: {numbers: [80]}}
- https: {hostnames: ["api.github.com"]}
EOF
  "${kubectl_ate[@]}" proxy actor "${a}" "${port}:80" -a "${atespace}" >"${work}/proxy-${a}.log" 2>&1 &
  proxies+=($!)
  port=$((port + 1))
done
# The gateway caches each actor's EgressPolicy for 10s.
sleep 12

# fetch ACTOR_PORT URL prints the status the actor saw and the body.
fetch() {
  curl -sS -m 60 -X POST "http://localhost:$1/" -H 'Content-Type: application/json' \
    -d "{\"url\":\"$2\"}"
}

denied="egress route denied"

# expect ACTOR PORT URL STATUS [BODY_SUBSTRING]
expect() {
  local actor=$1 port=$2 url=$3 want=$4 body=${5:-} got
  got="$(fetch "${port}" "${url}" || true)"
  local status
  status="$(printf '%s' "${got}" | sed -n 's/.*"statusCode":\([0-9]*\).*/\1/p')"
  if [[ "${status}" == "${want}" && ( -z "${body}" || "${got}" == *"${body}"* ) ]]; then
    printf 'ok    %-12s %s -> %s\n' "${actor}" "${url}" "${status}"
  elif [[ "${want}" == 200 && "${url}" == https://api.github.com/* && "${status}" =~ ^(403|429)$ &&
    "${got}" == *"rate limit"* && "${got}" != *"${denied}"* ]]; then
    # GitHub limits unauthenticated callers by address, and CI runners share
    # theirs. Its refusal still shows what this check is for: the gateway and
    # ate-gress let the request through to GitHub.
    printf 'ok    %-12s %s -> %s (rate limited by GitHub, so allowed by ate-gress)\n' "${actor}" "${url}" "${status}"
  else
    printf 'FAIL  %-12s %s -> %s, want %s %s\n      %s\n' "${actor}" "${url}" "${status:-none}" "${want}" "${body}" "${got:0:300}"
    failures=$((failures + 1))
  fi
}

step "waiting for the actors to answer"
for p in 18000 18001; do
  for i in $(seq 60); do
    fetch "${p}" "http://${target}/repos/acme/x" 2>/dev/null | grep -q statusCode && break
    if [[ ${i} -eq 60 ]]; then
      echo "the actor behind localhost:${p} never answered; proxy log:" >&2
      cat "${work}"/proxy-*.log >&2
      exit 1
    fi
    sleep 2
  done
done

step "cleartext HTTP through the gateway"
expect e2e-research 18000 "http://${target}/repos/acme/widget" 200 "GET /repos/acme/widget"
expect e2e-research 18000 "http://${target}/repos/ACME/widget/pulls?state=open" 200
expect e2e-research 18000 "http://${target}/repos/other/widget" 403 "${denied}"
expect e2e-research 18000 "http://${target}/repos/acme-evil/widget" 403 "${denied}"
expect e2e-research 18000 "http://${target}/repos/acme/x/..%2F..%2Fother/y" 403 "${denied}"
expect e2e-research 18000 "http://${target}/repos//acme/widget" 403 "${denied}"
expect e2e-research 18000 "http://${target}/" 403 "${denied}"
expect e2e-other 18001 "http://${target}/repos/acme/widget" 403 "${denied}"

if [[ "${E2E_GITHUB:-1}" != "0" ]]; then
  step "HTTPS to api.github.com through the gateway's MITM leg"
  expect e2e-research 18000 "https://api.github.com/repos/kubernetes/kubernetes" 200 'full_name\":\"kubernetes/kubernetes'
  expect e2e-research 18000 "https://api.github.com/orgs/Kubernetes" 200
  expect e2e-research 18000 "https://api.github.com/repos/torvalds/linux" 403 "${denied}"
  expect e2e-research 18000 "https://api.github.com/repositories/2325298" 403 "${denied}"
  expect e2e-research 18000 "https://api.github.com/search/repositories?q=org:torvalds" 403 "${denied}"
  expect e2e-research 18000 "https://api.github.com/repos/kubernetes/x/..%2F..%2Ftorvalds/linux" 403 "${denied}"
  expect e2e-other 18001 "https://api.github.com/repos/kubernetes/kubernetes" 403 "${denied}"
fi

step "rolling ate-gress under load"
# The gateway fails closed, so a rollout that dropped streams would fail actor
# requests. Each replica drains before it stops; no request may fail.
"${kubectl[@]}" -n ate-gress rollout restart deploy/ate-gress
"${kubectl[@]}" -n ate-gress rollout status deploy/ate-gress --timeout=5m >/dev/null 2>&1 &
rollout=$!
rollout_failures=0
rollout_requests=0
# Keep the load on for the whole rollout, and at least long enough to cover
# both replicas draining (--drain-delay plus the stop).
deadline=$((SECONDS + 40))
while kill -0 "${rollout}" 2>/dev/null || [[ ${SECONDS} -lt ${deadline} ]]; do
  got="$(fetch 18000 "http://${target}/repos/acme/widget" 2>/dev/null || true)"
  rollout_requests=$((rollout_requests + 1))
  [[ "${got}" == *'"statusCode":200'* ]] || rollout_failures=$((rollout_failures + 1))
  sleep 0.2
done
wait "${rollout}"
if [[ ${rollout_failures} -eq 0 ]]; then
  printf 'ok    %d requests during the rollout, none failed\n' "${rollout_requests}"
else
  printf 'FAIL  %d of %d requests failed during the rollout\n' "${rollout_failures}" "${rollout_requests}"
  failures=$((failures + 1))
fi

step "checking ate-gress metrics"
pod="$("${kubectl[@]}" -n ate-gress get pods -l app.kubernetes.io/name=ate-gress -o jsonpath='{.items[0].metadata.name}')"
"${kubectl[@]}" -n ate-gress port-forward "pod/${pod}" 18080:8080 >/dev/null 2>&1 &
proxies+=($!)
sleep 2
curl -sS http://localhost:18080/metrics | grep -E '^ategress_(decisions_total|snapshot_generation|policies)' || true

if [[ ${failures} -ne 0 ]]; then
  step "${failures} check(s) failed"
  exit 1
fi
step "e2e passed"
