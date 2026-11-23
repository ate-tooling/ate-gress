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

## Upgrade

```sh
helm upgrade ate-gress oci://ghcr.io/ate-tooling/charts/ate-gress --version <version> -n ate-gress
```

The `EgressRoutePolicy` CRD is part of the release, so an upgrade brings the
new schema with it. `helm uninstall` keeps the CRD, because deleting it would
delete every policy. To apply the CRD yourself, from the release's
`ate-gress-<version>-crds.yaml`, set `crds.install=false`.

**Once, when upgrading from `0.1.0-rc.4` or earlier:** those charts shipped
the CRD in `crds/`, which Helm installs but never upgrades, and does not
count as part of the release. Hand the CRD to the release before the
upgrade, with the release's name and namespace:

```sh
crd=egressroutepolicies.ategress.ate-tooling.github.io
kubectl label crd $crd app.kubernetes.io/managed-by=Helm
kubectl annotate crd $crd meta.helm.sh/release-name=ate-gress meta.helm.sh/release-namespace=ate-gress
```

Without this the upgrade stops with `invalid ownership metadata` before it
changes anything. Policies are not touched either way. If you applied the CRD
with `kubectl apply --server-side`, Helm 4 also reports a conflict with
`kubectl` on `.spec.versions`; add `--force-conflicts` to that one upgrade.

### Rollback

```sh
helm rollback ate-gress <revision> -n ate-gress
```

A rollback puts back the earlier chart's CRD, and keeps every policy. This
holds across the release that added `v1beta1`, because policies are still
stored as `v1alpha1`; [API versions](#api-versions) has the details. After
it:

- **`kubectl` may answer `the server could not find the requested resource`**
  for `kubectl get egressroutepolicies`. It has cached `v1beta1` as the
  version to ask for, and the earlier CRD does not serve it. `kubectl
  api-resources` refreshes the cache.
- **Manifests that say `v1beta1` no longer apply** until you upgrade again.
  The policies they created are still there, served as `v1alpha1`.
- **Fields the earlier CRD lacks are not served.** A policy that uses one
  keeps it in storage and shows it again after the next upgrade, but an
  earlier ate-gress does not act on it.

A rollback to `0.1.0-rc.4` or earlier leaves the CRD as it is, because those
releases never held it. That is safe: the newer CRD still serves `v1alpha1`,
which is all an earlier ate-gress reads. To put the earlier CRD back as well,
apply that release's `ate-gress-<version>-crds.yaml` with `kubectl apply
--server-side --force-conflicts`, and add `--force-conflicts` to the next
`helm upgrade`.

## Policies

```yaml
apiVersion: ategress.ate-tooling.github.io/v1beta1
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
by path; `POST /graphql` is the main case. [`examples/`](examples/README.md)
has more: PyPI, npm, `ghcr.io`, S3 and the Claude API, each with the limits
of what a method-and-path policy can do for that upstream.

`kubectl get egressroutepolicies` shows whether each policy is `Accepted`.

A policy that is not `Accepted` got past the CRD schema and was rejected by
ate-gress itself: the cluster's CRD is older than the binary, or the chart
was rolled back to a version that does not know something the policy uses.
**A rejected policy fails closed.** It allows nothing, and it still claims
its hosts for the actors it selects, so they are denied rather than released
to whatever Substrate allows. Routes in other `Enforce` policies on those
hosts go on allowing. In detail:

- None of its routes allow, including the valid ones.
- An `enforcementMode` that is not `Audit` is treated as `Enforce`. A
  rejected `Audit` policy stays in `Audit`, and denies nothing.
- A selector list with an invalid glob selects everything; the other list
  still applies.
- A host is claimed as a request would name it (`Example.com:443` claims
  `example.com`). One that is not a hostname at all, such as `*.example.com`,
  cannot be claimed.

The condition's message says what is wrong and what the policy still claims,
and every replica logs it at `WARN`. A request denied on a host that only
rejected policies claim carries the reason `invalid_policy`; if an accepted
`Enforce` policy claims the host too, the reason is `no_route` or `path` as
it would be without the rejected one. Alert on either of:

```promql
ategress_policies{state="rejected"} > 0
increase(ategress_decisions_total{reason="invalid_policy"}[5m]) > 0
```

Fix or delete the policy to lift the denial.

### API versions

`EgressRoutePolicy` is served as `v1beta1` and as `v1alpha1`. The two have
the same schema, and every policy can be read and written as either,
whichever it was created as.

- **`v1alpha1` manifests keep working**, unchanged. `kubectl apply` and
  GitOps tools that re-apply them see no diff. `v1alpha1` is not deprecated.
- **`kubectl get egressroutepolicies -o yaml` prints `v1beta1`** for every
  policy, because `kubectl` asks for the most mature version served.
- **Charts up to `0.1.0-rc.4` serve only `v1alpha1`.** Keep manifests at
  `v1alpha1` for as long as you might run, or roll back to, one of them.

[docs/design.md](docs/design.md#api-versions) says why policies are still
stored as `v1alpha1`, and what changes that.

## Testing policies

`ategressctl` checks policy files before they reach a cluster, so they can
live in git and be gated in CI. It compiles and decides with the code
ate-gress runs, and validates against the CRD's schema as the API server
does, so its answers are the cluster's.

```sh
# Run a table of requests through the policies: what must be allowed, denied, audited.
ategressctl test examples/github-single-org.tests.yaml

# Why is this request allowed or denied, and which policies claim the host?
ategressctl explain -f examples/ -a research/agent POST https://api.github.com/graphql

# Policies the API server or compiler would reject, Audit policies an Enforce
# policy overrides, redundant paths; and, given the actor's Substrate
# EgressPolicy, claimed hosts on tls_passthrough, which ate-gress never sees.
ategressctl lint -f examples/ --egress-policy research/agent=egress-policy.yaml
```

A test file lists requests per actor:

```yaml
policies: [github-single-org.yaml]
tests:
- actor: research/agent
  allow:
  - GET https://api.github.com/repos/acme/widget
  deny:
  - POST https://github.com/acme/widget.git/git-receive-pack
  - request: POST https://api.github.com/graphql
    reason: no_route
```

Binaries for Linux and macOS are attached to each release, and `make
build-ategressctl` builds one. [docs/ategressctl.md](docs/ategressctl.md) has
the test-file format, the lint codes, the JSON output and the exit codes.

## Operations

| | |
|---|---|
| Ports | `9443` ext_proc (gRPC, mTLS), `8080` metrics, `8081` `/healthz` `/readyz` |
| Readiness | Not ready until the first policy snapshot is built from a synced cache |
| Metrics | Prometheus, on `/metrics`; listed under [Metrics](#metrics) |
| Logs | JSON. Denials, audits, and the allowed requests of `logAllowed` policies at `INFO`; every decision at `DEBUG`. Header values are never logged, because they may hold an injected credential. At `INFO`, denials and audits are rate-limited for each actor, reason and policy: `--deny-log-burst` lines (default 10), then `--deny-log-rate` lines a second (default 1; `0` disables the limit). The next line logged carries the number dropped as `suppressed`, and `ategress_decision_logs_suppressed_total` counts them. `logAllowed` records are never dropped, and `ategress_decisions_total` counts every decision |
| Shutdown | On SIGTERM it goes NOT_SERVING, serves for `--drain-delay` while the gateway's DNS moves on, then drains streams |
| Scaling | Stateless; every replica serves from its own informer cache. The headless Service lets the gateway balance across replicas |

[docs/compatibility.md](docs/compatibility.md) says which Substrate and Envoy
versions ate-gress is tested against, what an upgrade of either can break,
and which metrics, log fields and deny reasons are stable.
[CHANGELOG.md](CHANGELOG.md) marks the changes operators have to act on.

### Metrics

Requests:

- `ategress_decisions_total{decision,reason}`: requests decided, by outcome
  (`allow`, `deny`, `audit`) and reason.
- `ategress_decision_duration_seconds`: time to decide a request.
- `ategress_policy_decisions_total{policy,decision}`: requests counted against
  each policy, described [below](#per-policy-decisions).
- `ategress_decision_logs_suppressed_total`: denial and audit log records
  dropped by the rate limit.
- `ategress_active_streams`: ext_proc streams open. The gateway opens one for
  each HTTP request.

Policies:

- `ategress_snapshot_generation`: snapshots built since the process started.
- `ategress_policies{state}`: policies in the snapshot in effect, `accepted`
  or `rejected`. A rejected policy allows nothing and still claims its hosts,
  as [Policies](#policies) describes, so anything above zero for `rejected`
  may be denying requests.
- `ategress_snapshot_last_build_timestamp_seconds`: when the snapshot in
  effect was built; `0` before the first. A replica builds one when it starts
  and on every policy change, so this is old wherever policies are stable.
- `ategress_snapshot_policies_hash`: a hash of the names, UIDs and generations
  of the policies the snapshot was built from. Replicas serving the same
  policies report the same value, whenever each of them built its snapshot.

TLS:

- `ategress_tls_certificate_expiry_timestamp_seconds`: not-after time of the
  serving certificate in the credential bundle. It is read from the file at
  each scrape, so it follows a rotation even if no new connection has used
  the certificate yet, and it is absent while the bundle cannot be loaded.
- `ategress_tls_reload_failures_total{file}`: handshakes refused because the
  `credential_bundle` or the `client_ca_bundle` could not be loaded.
- `ategress_tls_handshake_failures_total{reason}`: connections refused in the
  TLS handshake. `client_identity` is a client whose certificate verified but
  is not the gateway's. `client_certificate` is a certificate that did not
  verify against the client CA bundle. `other` is everything else: no
  certificate, not TLS 1.3, a timeout, or TLS material ate-gress could not
  load. A connection closed before it sent anything is not counted.

Build:

- `ategress_build_info{version,goversion}`: always `1`.

No metric carries an actor, a host, a path or a header value; those are in
the decision log.

The gateway fails closed, so these are worth alerting on before they become
denied egress:

```promql
# The serving certificate is not being rotated. Pick a threshold shorter
# than the time the kubelet rotates ahead of expiry.
ategress_tls_certificate_expiry_timestamp_seconds - time() < 3600
# The gateway cannot connect.
increase(ategress_tls_reload_failures_total[5m]) > 0
increase(ategress_tls_handshake_failures_total{reason="client_certificate"}[5m]) > 0
# A replica is serving policies the others are not.
max(ategress_snapshot_policies_hash) != min(ategress_snapshot_policies_hash)
```

Give the last one a `for:` of a few minutes: replicas disagree for a moment
on every policy change. The build timestamp cannot stand in for it, because a
replica that restarts builds a new snapshot from unchanged policies.

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
  the host, and that one may be an `Audit` policy. A rejected policy counts
  here like the lockdown it is treated as, so its `deny` series shows what
  the rejection is costing even where the deny reason is not
  `invalid_policy`.
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
between `Audit` and `Enforce`, or rejected, keeps its counts. A policy that
is deleted loses its series at the next snapshot, and starts from zero if it
comes back.

## Development

```sh
make test         # unit, race, and envtest controller tests
make build-ategressctl   # the policy testing CLI, into bin/
make fuzz         # each fuzz target for FUZZTIME (default 10s)
make bench        # request-path benchmarks
make test-envoy   # behind a real Envoy configured like Substrate's gateway (Docker)
make test-envoy-stable test-envoy-dev   # the same, on the newest stable Envoy and on Envoy's main
make lint
make lint-workflows   # zizmor audit of the GitHub workflows (Docker)
hack/upgrade-kind.sh   # helm upgrade from the last published chart, and rollback, on a throwaway kind cluster

# End to end, on a kind cluster running Substrate:
hack/substrate-kind-up.sh <substrate checkout>   # create the cluster and install Substrate
hack/e2e-kind.sh <substrate checkout>            # install ate-gress and drive actor traffic
```

CI runs the first group on every pull request. Nightly, it runs the
end-to-end test against a pinned Substrate release and Substrate's `main`,
the Envoy test against Envoy's `main`, and the fuzzers with a saved corpus.
[docs/ci.md](docs/ci.md) says what runs when, and what to do when a nightly
run fails.

The design is in [docs/design.md](docs/design.md), and
[CONTRIBUTING.md](CONTRIBUTING.md) says what a change has to bring with it.
[docs/adr/](docs/adr/0001-policy-delegation.md) holds design proposals.
