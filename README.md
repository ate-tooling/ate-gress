# ate-gress

L7 egress route policy for [Agent Substrate](https://github.com/agent-substrate/substrate).

Substrate's `EgressPolicy` decides egress by hostname and port. ate-gress adds
method and path: "actors in `research` may `GET` `/repos/acme/**` on
`api.github.com`, and nothing else there". It is an Envoy `ext_proc` service
that Substrate's egress gateway calls through its
[additional egress ext_proc](https://github.com/agent-substrate/substrate/blob/main/docs/security/extensibility.md)
extension point. Rules are `EgressRoutePolicy` objects.

```
actor ──atunnel/mTLS──▶ atenet-egress (Envoy)
                         ├─ Substrate egress policy: actor authenticated, host allowed, credential injected
                         ├─ ate-gress ext_proc:      method + path allowed for this actor?   ◀── EgressRoutePolicy
                         └─ upstream
```

The gateway calls ate-gress on every HTTP request on its cleartext and TLS
MITM legs, after its own policy has allowed the request, with the request
headers and the actor's SPIFFE ID. The filter fails closed: if ate-gress
denies, errors, times out, or is unreachable, the request is denied.

## Install

Substrate must use the Envoy dataplane. Install the chart, then point the
gateway at it:

```sh
helm install ate-gress oci://ghcr.io/ate-tooling/charts/ate-gress --version <version> \
  -n ate-gress --create-namespace

# With the agent-substrate-operator:
kubectl patch substrateinstall substrate --type merge \
  -p '{"spec":{"atenet":{"additionalEgressExtprocService":"ate-gress/ate-gress:9443"}}}'
# With ate-setup:
#   ate-setup deploy ate-system --experimental-additional-egress-extproc-service=ate-gress/ate-gress:9443
```

Install ate-gress first and wait for it to be ready: once the gateway points
at it, the gateway's HTTP egress depends on it.

Releases are signed with Sigstore and carry SLSA build provenance and an
SBOM, and the chart pins the image by digest. Check them before installing:
`hack/verify-release.sh <version>`. [docs/releasing.md](docs/releasing.md)
covers the pipeline and the manual checks.

## Policies

```yaml
apiVersion: ategress.ate-tooling.github.io/v1alpha1
kind: EgressRoutePolicy
metadata:
  name: github-acme-readonly
spec:
  actorSelector:
    atespaces: [research]       # globs; empty selects every actor
  hosts:
  - host: api.github.com
    routes:
    - methods: [GET, HEAD]
      paths: [/repos/acme/*, /repos/acme/*/**, /orgs/acme]
      caseInsensitive: true
```

- **A policy claims the hosts it lists, for the actors it selects.** A request
  to a host no selecting policy claims is left alone: Substrate's
  `EgressPolicy` already allowed it.
- **A request to a claimed host must match a route** in some `Enforce` policy
  that claims it, or it is denied with `403` and an `x-ate-gress-reason`
  header.
- **Policies only allow.** A host listed with no routes denies everything on
  it, so a lockdown policy that selects every actor, plus narrower policies
  that allow, gives default-deny for that host.
- **`enforcementMode: Audit`** allows the request and records the would-be
  denial (log and `ategress_decisions_total{decision="audit"}`), so you can
  roll out before you enforce. An `Enforce` policy on the same host always
  takes precedence. [Per-policy decisions](#per-policy-decisions) says when
  an `Audit` policy is safe to switch.
- **Paths** are templates: literal segments, `*` for one segment, `**` for one
  or more trailing segments. A template ending in `/` matches that one
  trailing slash, as in a registry's `GET /v2/`; `*` and `**` never match the
  empty segment it leaves, so `/**` does not match `/v2/`. The query string is
  not matched.
- **`logAllowed: true`** logs the allowed requests of the actors and hosts the
  policy selects at `INFO`, with the same fields as a denial, so you have a
  record of what each actor fetched without running at `DEBUG`.

Requests whose path an upstream could read differently from ate-gress are
denied on claimed hosts instead of being normalized. That covers encoded
`/`, `\` or `.`, dot segments, empty segments other than one trailing
`/`, and non-ASCII. See
[the threat model](docs/threat-model.md).

A single trailing slash, as in `/repos/acme/widget/`, is not such a path: it
is matched like any other, and a request no template allows is denied with
reason `no_route`, not `path`. Before trailing-slash templates were
supported it was denied with `path`, so alerts on `reason=path` no longer
see it.

[`examples/github-single-org.yaml`](examples/github-single-org.yaml) is a
complete single-organization GitHub setup, covering the REST API, git
clone/fetch, archives and raw content. It explains what cannot be filtered
by path; `POST /graphql` is the main case.

`kubectl get egressroutepolicies` shows whether each policy is `Accepted`.

## Operations

| | |
|---|---|
| Ports | `9443` ext_proc (gRPC, mTLS), `8080` metrics, `8081` `/healthz` `/readyz` |
| Readiness | Not ready until the first policy snapshot is built from a synced cache |
| Metrics | Prometheus, on `/metrics`; listed under [Metrics](#metrics) |
| Logs | JSON. Denials, audits, and the allowed requests of `logAllowed` policies at `INFO`; every decision at `DEBUG`. Header values are never logged, because they may hold an injected credential |
| Shutdown | On SIGTERM it goes NOT_SERVING, serves for `--drain-delay` while the gateway's DNS moves on, then drains streams |
| Scaling | Stateless; every replica serves from its own informer cache. The headless Service lets the gateway balance across replicas |

### Metrics

Requests:

- `ategress_decisions_total{decision,reason}`: requests decided, by outcome
  (`allow`, `deny`, `audit`) and reason.
- `ategress_decision_duration_seconds`: time to decide a request.
- `ategress_policy_decisions_total{policy,decision}`: requests counted against
  each policy, described [below](#per-policy-decisions).

Policies:

- `ategress_snapshot_generation`: snapshots built since the process started.
- `ategress_policies{state}`: policies in the snapshot in effect, `accepted`
  or `rejected`.

No metric carries an actor, a host, a path or a header value; those are in
the decision log.

### Per-policy decisions

`ategress_policy_decisions_total{policy,decision}` counts requests to claimed
hosts against the policies involved. It is the only metric with a policy
label. Every policy in the snapshot in effect has all three series, from
zero.

- `allow`: the policy's route allowed the request.
- `deny`: the request was denied, and this is an `Enforce` policy that
  claimed its host for its actor. A denial means no such policy had a route
  for the request, so each of them counts it. This is not the `policy` field
  of the decision log, which names only the first policy by name that claimed
  the host, and that one may be an `Audit` policy.
- `audit`: the request was allowed, and it would have been denied had this
  `Audit` policy, alone, been in `Enforce`. That is every request to a host
  the policy claims for the actor that it has no route for, unless an
  `Enforce` policy claims the host as well, because then switching this one
  can only allow more.

One request can count against several policies, so the series do not add up
to `ategress_decisions_total`. In particular, a request that one `Audit`
policy allows and another has no route for is an `allow` for the first and an
`audit` for the second, while `ategress_decisions_total` and the decision log
record a plain `allow`.

An `Audit` policy is safe to switch to `Enforce` when its `audit` series has
stopped growing on every replica over a period that covers the traffic you
expect:

```promql
sum by (policy) (increase(ategress_policy_decisions_total{decision="audit"}[7d])) == 0
```

Switching several policies at once is safe when that holds for each of them.

The counts are per replica and start again from zero when the replica
restarts. They follow the policy's name: a policy that is edited, or switched
between `Audit` and `Enforce`, keeps its counts. A policy that is deleted or
rejected loses its series at the next snapshot, and starts from zero if it
comes back.

## Development

```sh
make test         # unit, race, and envtest controller tests
make fuzz         # each fuzz target for FUZZTIME (default 10s)
make bench        # request-path benchmarks
make test-envoy   # behind a real Envoy configured like Substrate's gateway (Docker)
make lint
make lint-workflows   # zizmor audit of the GitHub workflows (Docker)
hack/e2e-kind.sh <substrate checkout>   # against a kind cluster running Substrate
```

The design is in [docs/design.md](docs/design.md).
