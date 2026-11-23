# Compatibility

What you can rely on across ate-gress releases, and what ate-gress relies on
in Substrate and Envoy.

ate-gress has not had a stable release. Every version so far is a `0.1.0`
release candidate, and between two release candidates anything may change.
The promises below start with `0.1.0`. [CHANGELOG.md](../CHANGELOG.md)
records every change that affects a running installation, marked
**Operators**.

## The EgressRoutePolicy API

### `v1alpha1`

`v1alpha1` is the only API version today. It carries no compatibility
promise:

- Fields, defaults and validation may change in any release, and a field may
  be removed.
- The API version may be dropped without a conversion path. Moving the API
  group in 0.1.0-rc.3 was such a change: policies had to be recreated.
- What a field means may change. The changelog will say so.

One thing is held to even in `v1alpha1`, because it is a safety property and
not a convenience: **a release does not make an existing, valid policy allow
a request it denied before** without an **Operators** entry in the changelog
that says so. Grammar is extended in ways that leave existing templates
matching what they matched, as the trailing-slash templates of 0.1.0-rc.4
were.

Use `v1alpha1` knowing that an upgrade may ask you to edit or recreate
policies. Keep them in version control.

### From `v1beta1`

These rules apply to `v1beta1` and to every later version, from the release
that first serves it. They follow the
[Kubernetes API deprecation policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/)
where it fits a single CRD.

- **Within an API version, changes are additive.** A field is not removed or
  renamed, its type and default do not change, and validation is not
  tightened in a way that rejects an object the version already accepted.
  New fields are optional, and leaving one unset means what it meant before
  the field existed.
- **The meaning of a valid policy does not widen.** A policy that is valid
  under one release allows no more under the next. A change that would let
  an existing template match more paths, or an existing selector select more
  actors, needs a new API version.
- **The meaning of a valid policy narrows only with notice.** If a release
  must make an existing policy deny something it allowed, because the old
  behaviour was unsafe, the changelog says so under **Operators** and
  **Security**. This is the one way behaviour within a version may break.
- **Versions convert without loss.** While two versions are served, an
  object written in either reads back the same in both. No manual migration
  is needed to move stored objects to a newer version.
- **A deprecated version keeps being served** for at least the two minor
  releases after the one that deprecates it, and for at least six months.
  The release that deprecates it says which version replaces it. `v1alpha1`
  is covered by this rule once `v1beta1` exists, even though it has no other
  promise.
- **Removal is announced one minor release ahead** in the changelog, with the
  steps to move stored objects off the version.

The resource is cluster-scoped, and a CRD's scope cannot be changed. If
policies are ever delegated to namespaces, that will be a new Kind beside
this one, not a change to it. See
[ADR 0001](adr/0001-policy-delegation.md).

### The CRD and the binary

The CRD schema and the ate-gress binary are released together and should be
upgraded together, CRD first.

- **Newer CRD, older binary.** The API server may store a policy the older
  binary cannot compile. The binary rejects that policy whole and sets
  `Accepted=False` on it. A rejected policy is left out of the snapshot: its
  routes allow nothing, and it no longer claims its hosts. If no other policy
  claims those hosts for an actor, requests to them are left to Substrate's
  `EgressPolicy`. Watch `ategress_policies{state="rejected"}` across an
  upgrade or a rollback.
- **Older CRD, newer binary.** The API server prunes fields the older schema
  does not know and rejects syntax it does not admit. Policies keep their old
  meaning.

Helm installs the CRDs in a chart's `crds/` directory on first install and
does not upgrade them. Apply the CRD file from the GitHub release before
you upgrade the chart.

## Version skew

### What ate-gress is built and tested against

| | Version | Where it is pinned |
|---|---|---|
| Envoy | 1.39.5 | `ENVOY_IMAGE` in the `Makefile`, and the default in `test/envoy/envoy_test.go`. CI runs `make test-envoy` against it on every pull request |
| Envoy API (the `ext_proc` protocol types) | `go-control-plane/envoy` 1.40.0 | `go.mod` |
| Substrate's `ext_proc` filter and cluster configuration | as rendered by Substrate v1.0.0 | Copied verbatim into `test/envoy/envoy.yaml` |
| Kubernetes API server, for the controller tests | 1.37.0 | `ENVTEST_K8S_VERSION` in the `Makefile` |
| Kubernetes client libraries | `k8s.io/client-go` 0.37, `controller-runtime` 0.25 | `go.mod` |
| Go | 1.27 | `go.mod` |

Substrate v1.0.0 ships Envoy 1.39.5 as its egress gateway, the version the
integration test runs. The filter and cluster blocks in `test/envoy/envoy.yaml`
match what Substrate's installer renders at v1.0.0
(`cmd/ate-setup/internal/steps/overlay.go`).

`hack/e2e-kind.sh` runs ate-gress against a real Substrate on a kind
cluster, installed by the agent-substrate-operator. It is run by hand and is
not part of CI, so no release is automatically tested end to end against a
Substrate version.

### Supported combinations

| ate-gress | Substrate | Dataplane |
|---|---|---|
| 0.1.0 release candidates | v1.0.0 | Envoy only |

Nothing else is tested. In particular:

- **Substrate before v1.0.0** is not supported.
- **Substrate's agentgateway dataplane** is not supported. Substrate rejects
  the additional `ext_proc` option on it.
- **A newer Substrate** may work. Check it as described below before you rely
  on it.
- **Kubernetes** is whatever your Substrate release supports. ate-gress adds
  one requirement of its own, which Substrate shares: its pod gets its
  serving certificate and the gateway's trust bundle from Substrate's pod
  certificate signers, through projected `podCertificate` and
  `clusterTrustBundle` volumes.

### The extension point is experimental upstream

ate-gress plugs into Substrate's additional egress `ext_proc` service. Substrate
lists that extension point as
["Available (experimental)"](https://github.com/agent-substrate/substrate/blob/main/docs/security/extensibility.md),
enables it with a flag named `--experimental-additional-egress-extproc-service`,
and says that it "may be converted to an API in the future" and that what the
service receives "can be changed if necessary". Substrate's version skew
policy covers its own components and does not mention the extension point.

What that means for you:

- **A Substrate upgrade can break ate-gress, including a patch release.**
  ate-gress cannot configure the filter that calls it. It is built to fit the
  one Substrate renders.
- **The break is closed, not open, as long as the filter still fails
  closed.** The filter is rendered with `failure_mode_allow: false`. If the
  gateway cannot reach ate-gress, or ate-gress cannot read what it is sent,
  requests are denied. ate-gress denies a request without exactly one
  well-formed actor identity (`reason="identity"`).
- **The one failure that is open** is Substrate ceasing to call ate-gress at
  all: the flag being renamed or dropped, or the filter being left out of a
  request leg. Then requests flow under the `EgressPolicy` alone and nothing
  in ate-gress can notice. After every Substrate upgrade, send a request you
  expect ate-gress to deny and check that it is denied, and alert on
  `ategress_decisions_total` going flat.

ate-gress depends on these details of the extension point:

| Detail | Value today | If it changes |
|---|---|---|
| Which requests are sent | Every HTTP request on the cleartext and TLS MITM legs, after the `EgressPolicy` | Legs that stop calling ate-gress are unfiltered |
| Processing mode | Request headers only | Other phases are continued unchanged; no effect |
| Actor identity | The request attribute `filter_state['dev.ate.actor.identity']`, a SPIFFE ID of the form `spiffe://<trust-domain>/worker-for-actor/<atespace>/<name>` | Every request is denied with `reason="identity"` |
| Failure mode | `failure_mode_allow: false`, 2s timeout | If it became fail-open, an ate-gress outage would allow everything |
| Path handling | The gateway forwards `:path` as the actor sent it, with no normalization | ate-gress would decide on a different path than the one the actor sent |
| Transport | TLS 1.3; the gateway presents its podidentity certificate and checks ate-gress's servicedns certificate for `<service>.<namespace>.svc` | The gateway cannot connect; requests are denied |
| Gateway identity | `spiffe://cluster.local/ns/ate-system/sa/atenet-egress` (the chart's `gateway.spiffeIDs`) | ate-gress refuses the gateway; requests are denied |
| Service discovery | A `STRICT_DNS` cluster over the Service's DNS name | Load spreads differently; see the design's availability section |

Before you upgrade Substrate:

1. Compare the `ext_proc` filter and the `additional_egress_ext_proc`
   cluster your new Substrate renders with the two blocks marked "verbatim"
   in `test/envoy/envoy.yaml`.
2. Compare the Envoy version it ships with `ENVOY_IMAGE`. To test another,
   run `make test-envoy ENVOY_IMAGE=envoyproxy/envoy:<version>`.
3. Run `hack/e2e-kind.sh` against a cluster on the new Substrate if you can.
4. Upgrade a non-production cluster first, and run the denied-request check
   above.

### Upgrading ate-gress itself

ate-gress is stateless and its replicas do not talk to one another, so
replicas of two versions can serve side by side during a rollout. They may
decide the same request differently for as long as the rollout lasts if the
two versions differ in grammar or semantics; the changelog says when they
do. Skipping versions is not tested: read the **Operators** entries of every
version you skip.

## Metrics, logs and deny reasons

These are the interfaces operators build alerts and dashboards on. The same
rule applies as for the API: stable from `0.1.0`, and until then the
changelog is the only promise.

### Stable

- **The deny reason values**: `no_route`, `path`, `authority`, `identity`,
  `headers`, `not_ready`; and the allow reasons `route` and `unclaimed`. A
  value is not renamed or removed, and keeps its meaning.
- **Where the reason appears**: the `x-ate-gress-reason` response header on a
  denial, the `reason` label of `ategress_decisions_total`, and the `reason`
  field of the decision log. A denial is an HTTP `403`.
- **The decision values** `allow`, `deny` and `audit`, in the `decision`
  label and log field.
- **The metric names and label names** `ategress_decisions_total{decision,reason}`,
  `ategress_decision_duration_seconds`, `ategress_snapshot_generation` and
  `ategress_policies{state}`, and the `state` values `accepted` and
  `rejected`.
- **The decision log's field names**: `decision`, `reason`, `actor`,
  `method`, `authority`, `path`, `policy`, `pattern`, `request_id`. A field
  is not renamed or removed, and header values are never logged.
- **Labels stay bounded.** Actors, hosts, paths and policy names are not
  metric labels and will not become ones. They are in the decision log.

### Not stable

- **New values and new names.** A release may add a reason, a metric, a
  label, or a log field. Write alerts so that an unknown reason is still
  counted as a denial, and parsers so that an unknown field is ignored.
- **Which reason a given request gets**, when a release changes what is
  accepted. 0.1.0-rc.4 moved requests with one trailing slash from `path` to
  `no_route`. Such a change gets an **Operators** entry in the changelog.
  Alert on the `deny` decision for totals, and on single reasons only for
  diagnosis.
- **Histogram buckets** of `ategress_decision_duration_seconds`.
- **Log message text, field order, and log lines other than the decision
  log**, such as the snapshot and policy-rejected messages.
- **The body of a denial**, and the `ate_gress_denied_<reason>` string Envoy
  records as the response code details. The reason inside it is stable; the
  prefix is not promised.
- **The `policy` and `pattern` a decision reports** when several policies
  could account for it. Today a denial names the first claiming policy by
  name order.
- **Command-line flags, chart values and ports** are not covered by this
  document.

A deprecated stable name is kept for at least two minor releases, with the
replacement emitted beside it where that is possible.
