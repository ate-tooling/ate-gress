# Compatibility

What ate-gress relies on in Substrate and Envoy, and what you can rely on
across ate-gress releases.

## ate-gress is alpha

There are no compatibility promises between releases. Anything may change in
any release, including a patch release: the `EgressRoutePolicy` schema and
its API versions, what a valid policy means, the CRD's group, metric and
label names, deny reasons, the decision log's fields, flags and chart
values. An API version may be dropped without a conversion path, and
policies may have to be recreated.

[CHANGELOG.md](../CHANGELOG.md) records every change that affects a running
installation, marked **Operators**. Read the **Operators** entries of every
version you upgrade across. One thing gets particular care: a change that
makes an existing policy **allow** a request it denied before is always
called out there.

Keep your policies in version control, and test them with
[ategressctl](ategressctl.md) against the release you are moving to.

### The CRD and the binary

The CRD schema and the ate-gress binary are released together. Upgrade them
together, CRD first; the chart ships the CRD as a template, so
`helm upgrade` does that, and `helm uninstall` keeps it. With
`crds.install=false`, apply the CRD file from the GitHub release before you
upgrade the chart.

If the API server holds a policy the binary cannot compile, the binary
rejects that policy whole and sets `Accepted=False` on it. A rejected policy
fails closed: it allows nothing and still claims its hosts for the actors it
selects, so their requests to those hosts are denied with reason
`invalid_policy` unless another `Enforce` policy allows them. Watch
`ategress_policies{state="rejected"}` and
`ategress_decisions_total{reason="invalid_policy"}` across an upgrade or a
rollback.

The resource is cluster-scoped, and a CRD's scope cannot be changed. If
policies are ever delegated to namespaces, that will be a new Kind beside
this one. See [ADR 0001](adr/0001-policy-delegation.md).

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
cluster. The `e2e-substrate` workflow runs it every night against the
Substrate pinned in `hack/substrate-pins.env`, installed both by the
agent-substrate-operator and by Substrate's own installer, and against the
tip of Substrate's `main`. It does not gate a release, so a release is not
tested end to end before it is published; [docs/ci.md](ci.md) says what
happens when the nightly run fails. The `envoy` workflow runs the Envoy test
against the newest stable Envoy and Envoy's `dev` build as well.

### Supported combinations

| ate-gress | Substrate | Dataplane |
|---|---|---|
| 0.1.x | v1.0.0 | Envoy only |

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

These carry no stability promise either; the changelog says when they
change. Two rules hold by design and are not expected to change:

- **Labels stay bounded.** Actors, hosts and paths are not metric labels.
  They are in the decision log. The one policy label, on
  `ategress_policy_decisions_total`, is bounded by the policies the cluster
  holds, not by traffic.
- **Header values are never logged.**

Write alerts on the `deny` decision for totals and treat an unknown reason
as a denial, and parse the decision log ignoring unknown fields.
