# Runbook

What to do when ate-gress alerts, how to read a denial, how to roll a policy
out, and what to do when ate-gress is down and egress has to work anyway.

The alerts are in the chart (`prometheusRule.enabled=true`); each one's
`runbook_url` points at its section here. Their thresholds and `for:` are
values under `prometheusRule.alerts` in
[`values.yaml`](../charts/ate-gress/values.yaml), which says why each default
is what it is. The metrics are listed in the
[README](../README.md#metrics).

The commands assume the chart's defaults: release `ate-gress` in namespace
`ate-gress`, and Substrate's gateway, `atenet-egress`, in `ate-system`.
Statements marked **unverified** were not checked against a running
Substrate; they are what its source or docs say, or what Envoy documents.

Everything here follows from one fact: Substrate's gateway calls ate-gress on
every HTTP request, on claimed and unclaimed hosts alike, and **fails
closed**. If ate-gress denies, errors, times out (2s), or cannot be reached,
the request is denied. Requests on `tls_passthrough` rules do not go through
ate-gress and are unaffected by all of it.

```sh
kubectl -n ate-gress get pods -l app.kubernetes.io/name=ate-gress -o wide
kubectl -n ate-gress logs -l app.kubernetes.io/name=ate-gress --prefix --tail=50
kubectl get egressroutepolicies
```

## Alerts

### AteGressDown

**Meaning.** No replica reports a policy snapshot in effect, or none is
being scraped at all:
`absent(ategress_snapshot_last_build_timestamp_seconds{job="ate-gress/ate-gress"} > 0)`
for 2m.

**Impact.** If ate-gress really is down, all HTTP egress through the gateway
is denied, for every actor and every host. This is an outage.

**Confirm.** First rule out monitoring: are the pods ready?

```sh
kubectl -n ate-gress get pods -l app.kubernetes.io/name=ate-gress
kubectl -n ate-gress get endpointslices -l kubernetes.io/service-name=ate-gress
```

If the pods are ready, ate-gress is serving and Prometheus cannot see it:
check that the PodMonitor is selected by your Prometheus
(`podMonitor.labels`), and that `networkPolicy.metricsFrom`, if you set it,
includes Prometheus. If the pods are not ready, the readiness probe says why
(`no policy snapshot in effect yet`, see
[AteGressNoSnapshot](#ategressnosnapshot)), and a crash loop's log says why
it exits. The usual ones:

- `loading TLS material`: the serving certificate or the client CA bundle
  was not projected. The `podCertificate` and `clusterTrustBundle` volume
  sources need Substrate's signers (its podcertcontroller, in
  `podcertificate-controller-system`) and a cluster where those features are
  on. `kubectl -n ate-gress describe pod` shows a volume that cannot mount.
- An API server error listing `egressroutepolicies`: the CRD is missing
  (`crds.install=false` and it was not applied) or the ClusterRole is.

**Act.** If a rollout broke it, roll back: `helm -n ate-gress rollback
ate-gress`. If it cannot be brought back quickly and egress must work, see
[Break glass](#break-glass-when-ate-gress-is-down).

### AteGressReplicasLow

**Meaning.** Fewer than `minReplicas` (default 2) replicas have a snapshot in
effect, for 5m.

**Impact.** None yet: one serving replica handles the gateway's load (see
[sizing](sizing.md)). One more failure is an outage.

**Confirm.** `kubectl -n ate-gress get pods`. Pending pods: look at their
events. `podAntiAffinity.required=true` needs one node per replica plus one
for the surge of a rollout. Crash loops: as in [AteGressDown](#ategressdown).

**Act.** Restore the replica count. If nodes are being drained, the
PodDisruptionBudget (`minAvailable: 1`) keeps one; a cluster upgrade that
drains faster than pods reschedule is when this fires.

### AteGressNoSnapshot

**Meaning.** A replica has been running for 5m without building its first
snapshot. Until it does it is not ready and takes no traffic, so the others
carry it.

**Impact.** Fewer replicas than you think. Normally the first snapshot is
built within a second of the informer cache syncing.

**Confirm.** The replica's log: the informer is retrying a list or watch of
`egressroutepolicies`. Causes: the API server is unreachable from the pod, the
ClusterRole lost `list`/`watch`, or the CRD is not installed.

**Act.** Fix the cause; the replica becomes ready on its own once the cache
syncs. Deleting the pod helps only if the cause was transient.

### AteGressDecisionLatencyHigh

**Meaning.** A replica's 99th-percentile decision time
(`ategress_decision_duration_seconds`, from receiving the request headers to
building the response) is above 100ms for 5m. A decision normally takes
microseconds; the histogram's top bucket is 262ms.

**Impact.** The gateway gives the whole ext_proc call 2s, and denies the
request if it takes longer. 100ms is 5% of that, so this fires long before
requests fail, and long after anything a busy but healthy replica does: it
means the process is not getting CPU. This metric does not include the
network between the gateway and ate-gress.

**Confirm.** Is the pod starved? Its CPU usage against its request, the node's
load, and, if you set a CPU limit, throttling
(`container_cpu_cfs_throttled_periods_total`). Memory near the limit makes
the Go garbage collector run constantly, because `GOMEMLIMIT` is set to the
memory limit: compare `go_memstats_heap_inuse_bytes` with
`resources.limits.memory`.

**Act.** Raise `resources.requests.cpu` so the scheduler places the pod
where it gets CPU, remove a CPU limit if you set one, or raise the memory
limit. A `priorityClassName` at or above the gateway's keeps ate-gress from
being the pod that is starved or evicted. [Sizing](sizing.md) has what a
replica uses.

### AteGressDenyRateHigh

**Meaning.** Over 5 minutes, more than 25% of decisions were denials, and
more than one denial a second, for 10m. It counts every deny reason, so it
also sees reasons added after these rules were written, such as
`invalid_policy`.

**Impact.** Actors are being refused routes, at a rate that is new. Either a
policy now claims more than intended, or routes that should exist are
missing, or an actor is looping on a denied request.

**Confirm.** Which reason and which policy:

```promql
sum by (reason) (rate(ategress_decisions_total{decision="deny"}[5m]))
sum by (policy) (rate(ategress_policy_decisions_total{decision="deny"}[5m]))
```

Then which actor and route, from the decision log (see
[Reading a denial](#reading-a-denial)). One actor with many denials and
`suppressed` counts is a loop; many actors on one host after a policy change
is the policy.

**Act.** A policy change: revert it, or put the policy in `Audit` while you
fix it (see [Rolling out a policy](#rolling-out-a-policy-audit-then-enforce)).
An actor in a loop: that is the actor's problem, and the log rate limit
keeps it from drowning the log. Tune `ratio` and `minRate` to your traffic if
your normal denial share is high.

### AteGressGatewayContractBroken

**Meaning.** Requests are being denied with reason `identity` (no
well-formed actor identity attribute) or `headers` (a pseudo-header missing
or repeated), more than 0.1 a second for 5m.

**Impact.** Those requests are denied before any policy is looked at,
including requests to unclaimed hosts. The gateway always supplies both, so
a steady rate means the gateway and ate-gress disagree about the extension
point: usually a Substrate upgrade that changed the identity attribute
(`filter_state['dev.ate.actor.identity']`) or its encoding.

**Confirm.** The decision log of those denials shows what arrived in
`actor`. Compare the gateway's rendered filter with what
[`test/envoy/envoy.yaml`](../test/envoy/envoy.yaml) pins:

```sh
kubectl -n ate-system get configmap atenet-egress -o jsonpath='{.data.envoy\.yaml}' |
  grep -n -B2 -A20 'cluster_name: additional_egress_ext_proc'
```

**Act.** If a Substrate upgrade changed the contract, roll it back or
upgrade ate-gress to a release that supports it, and open an issue. If only
some requests are affected, the gateway may be calling ate-gress from a leg
that does not set the attribute.

### AteGressDecisionLogsSuppressed

**Meaning.** The decision log rate limit has been dropping denial and audit
lines for 15m (severity `info`).

**Impact.** None on traffic. The log is no longer a complete record of every
denial; `ategress_decisions_total` still counts all of them, and every
record written after a gap carries `suppressed`, the number dropped for its
actor, reason and policy.

**Confirm.** Find who is loud:

```sh
kubectl -n ate-gress logs -l app.kubernetes.io/name=ate-gress --since=15m |
  jq -r 'select(.suppressed) | [.actor, .reason, .policy, .suppressed] | @tsv' | sort | uniq -c | sort -rn | head
```

`suppressed_untracked` means more than 4096 actor, reason and policy
combinations were busy at once.

**Act.** Usually nothing: this is the limit working. If you need every
denial, raise `denyLogRate` and `denyLogBurst`, or set `denyLogRate: 0`, and
make sure your log pipeline can take it.

### AteGressPoliciesRejected

**Meaning.** At least one `EgressRoutePolicy` passed the CRD's admission
schema but failed ate-gress's compiler, for 5m. That happens when the
cluster's CRD is older than the binary, or after a rollback to a binary that
does not know something the policy uses.

**Impact.** None of the rejected policy's routes are in effect. What that
does to its hosts depends on the version of ate-gress:

- Releases whose deny reasons include `invalid_policy` keep a rejected
  policy as a lockdown: it still claims its hosts for its actors and allows
  nothing, so those requests are denied with `invalid_policy` unless another
  `Enforce` policy has a route for them. It fails closed.
- Earlier releases leave the rejected policy out of the snapshot entirely. A
  host that only it claimed is then unclaimed, and requests to it are
  allowed, as far as ate-gress is concerned. It fails open for those hosts.

**Confirm.**

```sh
kubectl get egressroutepolicies
kubectl get egressroutepolicy <name> -o jsonpath='{.status.conditions[?(@.type=="Accepted")].message}'
```

The message says what is wrong. Each replica also logs it at `WARN`, as
`policy rejected; it allows nothing`.

**Act.** Fix or delete the policy. If the cause is an old CRD, upgrade it:
the chart installs the CRD with the release unless `crds.install=false`, in
which case apply the release's `ate-gress-<version>-crds.yaml`.

### AteGressPoliciesDiverged

**Meaning.** Among replicas with a snapshot, `ategress_snapshot_policies_hash`
differs, for 5m. The hash covers the names, UIDs and generations of the
policies a snapshot was built from, so replicas serving the same policies
report the same value. They disagree for a moment on every policy change.

**Impact.** The same request can be allowed by one replica and denied by
another, because one of them stopped following policy changes. Which
policies it is missing is not visible from the metric.

**Confirm.**

```promql
ategress_snapshot_policies_hash and on (job, instance) ategress_snapshot_last_build_timestamp_seconds > 0
```

The odd one out is the stale replica, unless the stale ones are the
majority. Its log will show watch errors, or no `policy snapshot in effect`
line since the last policy change while the others have one.

**Act.** Delete the stale pod; its replacement lists every policy when it
starts. Then find out why its watch stopped: API server connectivity from
that node, or an API server that was restarted behind a load balancer that
kept the connection.

### AteGressCertificateExpiringSoon

**Meaning.** A replica's serving certificate, read from its credential
bundle at each scrape, expires in less than 20 minutes, for 1m.

**Impact.** When it expires, the gateway refuses to complete a handshake
with that replica, and requests it would have sent there fail.

The threshold comes from Substrate's servicedns signer
(`cmd/podcertcontroller/internal/servicednssigner`): it issues certificates
valid for 24 hours, or `maxExpirationSeconds` if that is shorter (the chart
does not set it, and Kubernetes defaults it to 24 hours), and sets
`beginRefreshAt` 30 minutes before expiry, which is when the kubelet starts
asking for the next one. A replica whose kubelet rotates on time therefore
never has less than about 30 minutes left. At 20 minutes the kubelet has had
10 minutes of retries and failed. A threshold above 1800 seconds fires on
every healthy rotation.

**Confirm.**

```sh
kubectl -n ate-gress get podcertificaterequests
kubectl -n podcertificate-controller-system get pods
kubectl -n podcertificate-controller-system logs deploy/podcertificate-controller --tail=50
```

A request that is pending or denied, or a controller that is not running, is
the cause. The kubelet's own log on the node says why it did not ask.

**Act.** Fix the signer. Deleting the pod gives the replacement a new
certificate, if the signer is issuing at all.

### AteGressCertificateUnreadable

**Meaning.** A replica is up (it reports `ategress_build_info`) but reports no
certificate expiry, for 5m. The metric is absent exactly when the credential
bundle cannot be loaded.

**Impact.** That replica refuses every new connection from the gateway. If
the gateway already has a connection open to it, those streams keep working
until the connection closes.

**Confirm.** `ategress_tls_reload_failures_total{file="credential_bundle"}`
is rising on that pod, and its log says what failed to parse. The projected
volume is written by the kubelet; a half-written file is retried at the next
handshake, so a persistent failure is a bad file, not a race.

**Act.** Delete the pod. If its replacement has the same problem, see
[AteGressCertificateExpiringSoon](#ategresscertificateexpiringsoon) for the
signer.

### AteGressTLSReloadFailures

**Meaning.** In the last 5 minutes a replica refused at least one handshake
because it could not load its credential bundle or its client CA bundle (the
`file` label says which). It fires at once.

**Impact.** Each one is a connection the gateway could not open. ate-gress
loads both files at every handshake, so a rotation is picked up without a
restart, and a bad file fails handshakes until it is fixed.

**Confirm.** The pod's log names the file and the error. For
`client_ca_bundle`, look at the ClusterTrustBundles the volume selects:

```sh
kubectl get clustertrustbundles -l podcert.ate.dev/canarying=live
```

**Act.** For `credential_bundle`, as in
[AteGressCertificateUnreadable](#ategresscertificateunreadable). For
`client_ca_bundle`, check that `podCertificates.podIdentitySigner` and
`podCertificates.trustBundleLabels` still match what Substrate publishes.

### AteGressGatewayCertificateRejected

**Meaning.** In the last 5 minutes a replica refused at least one handshake
because the client's certificate did not verify against the client CA
bundle (reason `client_certificate`). It fires at once.

**Impact.** The NetworkPolicy admits only the gateway's pods to the ext_proc
port, so the client is almost certainly the gateway, and its requests are
failing.

**Confirm.** Whether the gateway's podidentity CA is in the bundle ate-gress
loads: Substrate may have rotated its podidentity CA, or published it in a
ClusterTrustBundle the chart's `trustBundleLabels` do not select.

**Act.** Make `podCertificates.trustBundleLabels` select the bundle that
holds the gateway's issuing CA. During a CA rotation, both the old and the
new CA must be in the selected bundles.

### AteGressUnknownClient

**Meaning.** In the last 5 minutes a replica refused at least one handshake
from a client whose certificate verified but whose SPIFFE ID is not one of
`gateway.spiffeIDs` (reason `client_identity`).

**Impact.** If the client is something other than the gateway, nothing is
broken: ate-gress refused it, and something in the cluster has a podidentity
certificate and is calling ate-gress. If the client is the gateway, its
identity changed and **all HTTP egress is failing**, which no other alert
shows directly, because the gateway's requests never become decisions.

**Confirm.** Did the gateway's namespace or service account change? The
default allowed ID is
`spiffe://cluster.local/ns/ate-system/sa/atenet-egress`. Do actors see
failures on unclaimed hosts? If so, it is the gateway.

**Act.** If it is the gateway, set `gateway.spiffeIDs` (and
`gateway.namespace` and `gateway.podLabels`, which the NetworkPolicy uses) to
match it. Otherwise find the caller: with the NetworkPolicy on, it is a pod
that matches `gateway.podLabels` in `gateway.namespace`, or the
NetworkPolicy is off or not enforced by your CNI.

## Reading a denial

An actor whose request ate-gress denies gets:

- status `403`, body `egress route denied`;
- the header `x-ate-gress-reason: <reason>`.

The reasons:

| Reason | Means |
|---|---|
| `no_route` | The host is claimed for the actor, and no `Enforce` policy that claims it has a route for this method and path. |
| `path` | The host is claimed, and the path is one ate-gress will not match because an upstream could read it differently: encoded `/`, `\` or `.`, dot segments, empty segments, non-ASCII. |
| `authority` | `:authority` is not a hostname. |
| `invalid_policy` | (Releases that have it.) The host is claimed only by rejected policies; see [AteGressPoliciesRejected](#ategresspoliciesrejected). |
| `identity` | No single well-formed actor identity arrived with the request. See [AteGressGatewayContractBroken](#ategressgatewaycontractbroken). |
| `headers` | `:method`, `:authority` or `:path` missing or repeated. |
| `not_ready` | The replica had no snapshot yet. A ready replica never gives this. |

Other failures do not carry the header. When ate-gress errors, times out, or
cannot be reached, the gateway's ext_proc filter answers the request itself
with a 5xx, a 500 for a gRPC error by Envoy's documentation (**unverified**
against the gateway: the repo's Envoy test only checks that such a request
is not let through). A 403 without the header
came from somewhere else, such as Substrate's own `EgressPolicy`.

ate-gress hands Envoy `ate_gress_denied_<reason>` as the response's details,
which Envoy reports as `%RESPONSE_CODE_DETAILS%`. Substrate's gateway
(`manifests/ate-install/atenet-egress.yaml`, as of this writing) logs every
response of 400 or more on its MITM leg with the actor, authority, method,
path and status, but its format does not include `%RESPONSE_CODE_DETAILS%`,
so the gateway's log shows a `403` and ate-gress's log says why.

ate-gress logs each denial at `INFO` as JSON, with `msg` `egress route
decision` and these fields:

| Field | |
|---|---|
| `decision` | `deny`, `audit`, or `allow` (`allow` only at `DEBUG`, or for policies with `logAllowed`) |
| `reason` | as above |
| `actor` | `<atespace>/<actor>`; for `identity` and `headers` denials, whatever string arrived |
| `method`, `authority`, `path` | the request; the path without its query, at most 512 bytes |
| `policy` | the first policy, by name, that claims the host for the actor; it may be an `Audit` policy |
| `pattern` | the template that matched, on an allow or audit |
| `request_id` | the request's `x-request-id` |
| `suppressed`, `suppressed_untracked` | lines the rate limit dropped before this one |

No header values are logged: a request may carry a credential the gateway
injected.

```sh
kubectl -n ate-gress logs -l app.kubernetes.io/name=ate-gress --since=1h |
  jq 'select(.msg == "egress route decision" and .actor == "research/agent-1")'
```

Each replica logs the requests it decided, so read all of them. To fix a
`no_route`, add the route to a policy that claims the host for that actor,
or, for a host the actor should not reach at all, nothing.

## Rolling out a policy: Audit then Enforce

A new policy, or a narrower one, denies whatever it does not route. Roll it
out without denying anything first:

1. Apply it with `enforcementMode: Audit`. An `Audit` policy allows every
   request, and counts and logs (`decision` `audit`) each one it would have
   denied. It never overrides an `Enforce` policy on the same host.
2. Watch what it would deny, per policy:

   ```promql
   sum by (policy) (increase(ategress_policy_decisions_total{decision="audit"}[1h]))
   ```

   and read the `audit` lines in the decision log for the routes. Add the
   routes that should be allowed.
3. Switch it to `Enforce` once its `audit` series has stopped growing on every
   replica, over a period that covers the traffic you expect (a weekly job
   needs a week):

   ```promql
   sum by (policy) (increase(ategress_policy_decisions_total{decision="audit",policy="<name>"}[7d])) == 0
   ```

4. After switching, watch its `deny` series and
   [AteGressDenyRateHigh](#ategressdenyratehigh). To back out, set it to
   `Audit` again; it keeps its counts, because they follow the policy's name.

The counts are per replica and start from zero when a replica restarts;
`increase` over the sum handles both. The `policy` field of a decision log
line names only the first claiming policy, so use the metric, not the log, to
decide whether one policy is safe. The README's
[per-policy decisions](../README.md#per-policy-decisions) has the exact
semantics.

## Break glass: when ate-gress is down

If ate-gress cannot be brought back and HTTP egress has to work, take it out
of the gateway's path.

**Consequence: no route policy is enforced while it is out.** Every
`EgressRoutePolicy` stops applying, for every actor. Substrate's own
`EgressPolicy` still decides which hosts and ports actors may reach, and
still injects credentials, so each actor gets everything its `EgressPolicy`
allows, on every path, with every method, and with the injected credential.
That is what ate-gress was there to prevent. Prefer, in order:

1. Bring ate-gress back: roll back the release (`helm -n ate-gress rollback
   ate-gress`), fix the certificate or RBAC problem the
   [AteGressDown](#ategressdown) section lists, or scale it up.
2. If only some actors or hosts matter, consider tightening their
   `EgressPolicy` in Substrate before removing ate-gress, so that what opens
   up is only what has to.
3. Remove ate-gress from the path, as below, and put it back as soon as it
   is healthy.

**With the agent-substrate-operator** (**unverified**: the operator is not
in the Substrate checkout this was written against; this is the inverse of
the README's install step):

```sh
kubectl patch substrateinstall substrate --type json \
  -p '[{"op":"remove","path":"/spec/atenet/additionalEgressExtprocService"}]'
```

**With ate-setup**, deploy again without
`--experimental-additional-egress-extproc-service`, and without
`atenet.egress.additionalExtprocService` in the config file or
`ATE_ADDITIONAL_EGRESS_EXTPROC_SERVICE` in the environment. The gateway
reads its Envoy configuration from a ConfigMap at startup, and ate-setup
restarts the gateway only when the extension or a credential provider is
set (`applyAtenetEgress` in `cmd/ate-setup/internal/steps/overlay.go`). So
without a credential provider, restart it yourself:

```sh
kubectl -n ate-system rollout restart deployment/atenet-egress
kubectl -n ate-system rollout status deployment/atenet-egress
```

Whether the operator restarts the gateway itself is **unverified**; check
that the gateway's pods were replaced, and restart them as above if not.

Then confirm requests to a claimed host succeed. The restart drops the
gateway's open connections, so actors see one round of connection errors.

**To put ate-gress back**, once it is ready (`kubectl -n ate-gress get pods`),
set the extension again as in the [README](../README.md#install), and
restart the gateway if your installer did not. From then on HTTP egress
depends on ate-gress again, so check it is ready first.
