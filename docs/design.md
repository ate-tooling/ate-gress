# Design

## Problem

Substrate actors reach the network only through the `atenet-egress` gateway.
The gateway authenticates the actor and applies its `EgressPolicy`, which
matches hostnames and ports and can inject credentials. It cannot say "only
this GitHub organization": that needs method and path.

## Where ate-gress sits

Substrate offers two extension paths. One replaces the gateway, and has no
installer support. The other augments it with an `ext_proc` callout. ate-gress
takes the second.

The callout runs after the built-in policy filter on the cleartext and MITM
legs. It never sees a request the built-in policy denied, and it does see the
credential the built-in policy injected. Substrate's installer and the operator
generate its filter configuration:

- request headers only, no bodies;
- the actor identity as the CEL attribute `filter_state['dev.ate.actor.identity']`;
- `failure_mode_allow: false` and a 2s timeout;
- a TLS 1.3 cluster that presents the gateway's podidentity certificate and
  checks ate-gress's servicedns certificate.

ate-gress cannot change any of that. It is built to fit it, and
`test/envoy/envoy.yaml` pins it verbatim.

Requests with `tls_passthrough` rules bypass the HTTP legs, so ate-gress never
sees them. Hosts you want filtered must use `https` rules.

## Components

```
cmd/ate-gress        flags and wiring
internal/pathmatch   Canonicalize (strict path validation) and Template (compiled matcher)
internal/identity    actor SPIFFE ID parsing
internal/policy      Compile(policies) -> Snapshot; Snapshot.Decide(request) -> Decision
internal/extproc     ext_proc gRPC server: protocol in, Decide, protocol out
internal/loglimit    per-key token buckets for the decision log
internal/controller  informer -> Compile -> Store; status writer
internal/tlsconfig   mTLS with per-handshake certificate reload

cmd/ategressctl      the offline policy CLI (docs/ategressctl.md); not in the server image
internal/ctl         its commands: test, explain, lint
internal/policyfile  policy manifests from files, checked against the CRD schema as at admission
internal/lint        static findings over a policy set
internal/egresspolicy  Substrate EgressPolicy manifests: which hosts reach ate-gress
```

Every security decision is made in `policy.Snapshot.Decide`. It is a pure
function of compiled policies and four strings: actor, method, authority and
path. It is tested exhaustively, and fuzzed against a reference implementation
written to be obviously correct. The ext_proc server and the controller are
thin adapters around it. So is `ategressctl`: it calls `Compile` and `Decide`
on policies read from files, and reads the snapshot through a small read-only
view (`Snapshot.Hosts`, `Claims`, `ClaimsFor`) that `Decide` does not use.

## Request path

1. Envoy opens a stream per HTTP request and sends `RequestHeaders`.
2. The server reads `:method`, `:authority` and `:path`, denying if any is
   missing or repeated, and the identity attribute, denying if it is absent,
   ambiguous or malformed.
3. It loads the current `*Snapshot` from an `atomic.Pointer`, without a lock.
4. `Decide` normalizes the authority (lowercase, strip the port and a single
   trailing dot) and looks up the host. If no policy selecting the actor
   claims the host, it allows. Otherwise it canonicalizes the path and matches
   compiled routes.
5. On allow it replies with an empty `HeadersResponse`, which continues the
   request unmodified. On deny it sends an `ImmediateResponse` 403 with a
   reason code, which Envoy also records in `%RESPONSE_CODE_DETAILS%`.

`Decide` does not allocate for lowercase authorities, and takes about 130ns
on an M-series laptop. A whole ext_proc round trip in-process takes about
300ns. The cost that matters is the gateway-to-ate-gress network hop.

Per-policy counts do not change that. `policy.Store` keeps a tally of three
atomic counters per policy beside the snapshot, found through an index
compiled into it. While deciding, the snapshot notes which policies the
decision counts against, and the store's wrapper adds to their tallies
afterwards, so `Snapshot.Decide` stays pure and the request path does no label
lookup. Prometheus reads the tallies of the snapshot in effect at each scrape.
A swap carries a tally over by policy name and drops the rest, so a deleted
policy's series end with the snapshot that held it, and a request still
deciding on the old snapshot cannot bring them back: it counts into a tally
nothing reads any more.

## Decision logs

Denials and audits are logged at `INFO`, and the actor decides how many there
are. An agent looping on a denied path would otherwise set the log volume,
and bury the denials of every other actor. So those records are rate-limited
with a token bucket per key: `--deny-log-burst` lines at once, then
`--deny-log-rate` lines a second.

- **The key** is the actor, the outcome (deny or audit), the reason and the
  policy. Each is authenticated or bounded. The path and the authority are
  not in it, because the actor chooses them, and a key the actor can vary
  gets a fresh burst each time. A request denied before its identity is
  parsed (reasons `headers` and `identity`) has no authenticated actor, so
  all such denials share one key per reason. The `actor` field of those
  records is whatever string arrived.
- **Nothing is lost silently.** The first record for a key is always
  written. A record written after others were dropped carries their number
  as `suppressed`, and `ategress_decision_logs_suppressed_total` counts every
  dropped record. `ategress_decisions_total` is unaffected. What can go
  unreported in the log is the last fraction of a second of a flood that
  then stops for good: its count waits for a next record that never comes.
- **Memory is bounded.** The limiter tracks at most 4096 keys. A key is only
  forgotten once its bucket has refilled, when forgetting it changes nothing.
  If every tracked bucket is still in use, a new key is charged to one shared
  bucket instead, and its records carry `suppressed_untracked`, a count
  across all such keys. Evicting a busy key instead would let more than 4096
  looping actors displace each other and log without limit.
- **What is not limited.** The allowed requests of `logAllowed` policies,
  because the operator asked for a complete record of them. And everything
  when the log level is `DEBUG`, which records every decision.

An allowed request that logs nothing at `INFO` returns before the limiter, so
the limiter's lock is taken only by requests that would otherwise write a log
record.

## Control plane

- **Snapshot builder (every replica).** It waits for the informer cache to
  sync, then compiles all policies into a new snapshot on every spec change
  and swaps it in. Rebuilding from the full list, instead of patching, keeps
  the snapshot a pure function of the cache. It runs once per change and
  costs microseconds.
- **Status writer (leader only).** It compiles each policy alone and sets
  `Accepted`. Policies compile independently, so this is the same verdict
  every replica's snapshot reaches, and for a rejected policy the same
  account of what it still claims.
- **Validation in two layers.** The CRD schema rejects bad specs at
  admission. It uses one OpenAPI pattern for the path grammar, because the
  equivalent CEL rules exceeded the API server's cost budget. The compiler
  re-validates everything and rejects what the schema would. A fuzz test
  checks that the schema pattern and the compiler accept exactly the same
  templates.
- **A rejected policy fails closed.** A policy reaches the compiler without
  having passed the schema the compiler agrees with when the cluster's CRD
  is older than the binary, or when the chart is rolled back to a binary
  whose compiler does not know a newer template form. Leaving such a policy
  out of the snapshot removes its allows, but it also removes its claims:
  every host that it alone claimed becomes unclaimed, and requests to it are
  allowed. So a rejected policy stays in the snapshot as the lockdown of what
  it lists. It keeps its hosts, for its actors, with no routes, and whatever
  part of it cannot be understood is read the way that denies more:
  - *Routes.* None is kept, not even the valid ones. A rejected policy allows
    nothing, instead of some part of what was written.
  - *Mode.* `Audit` stays `Audit`, and so denies nothing. Anything else is
    `Enforce`: a mode this version does not know may be one that denies, and
    a misspelled `Enforce` was certainly meant to.
  - *Selector.* A list holding a glob that does not compile selects
    everything, because the glob may have been meant to select anyone. The
    other list still narrows the selector, since an actor is selected only
    when both lists match. One typo therefore does not claim the policy's
    hosts for the whole cluster unless the policy named no other list.
  - *Hosts.* A host is claimed under the name a request for it is looked up
    by, so `Example.com` and `example.com:443` claim `example.com`. A host
    that no `:authority` normalizes to, such as `*.example.com`, cannot be
    claimed. That, and a policy with no hosts, is all a rejection leaves
    unclaimed.

  The rejected policy only adds a claim. A route in another `Enforce` policy
  on the same host still allows, as it would beside a lockdown.

  This trades availability for safety, as the gateway's own filter does: a
  broken policy now denies traffic that used to flow, so it is made loud.
  The policy's `Accepted` condition is `False` and says what the policy still
  claims. Every replica logs the same at `WARN` on each snapshot, and counts
  the policy in `ategress_policies{state="rejected"}`. A request is denied
  with the reason `invalid_policy`, which nothing else uses, when every
  `Enforce` policy that claims its host for its actor was rejected; with no
  `Enforce` claim, a request that only rejected `Audit` policies claim is
  audited with that reason. Where an accepted `Enforce` policy claims the
  host as well, the request would be denied without the rejected policy, and
  keeps the reason `no_route` or `path`; the rejected policy's `deny` count
  in `ategress_policy_decisions_total` covers both.

## API versions

`EgressRoutePolicy` is served as `v1alpha1` and `v1beta1`. `v1beta1` was
added as a copy of `v1alpha1`, in a way that an upgrade and a rollback both
leave every policy as it was.

- **One schema, no conversion.** The CRD's conversion strategy is `None`: the
  API server serves a stored object as either version by rewriting its
  `apiVersion` and nothing else. That is only correct while the schemas are
  identical. A field in one alone would be pruned, without an error, from an
  object written through the other, and a validation rule in one alone could
  be bypassed. Tests in `api/` fail if the generated schemas or the type
  files differ. A real difference needs a conversion webhook, which every
  read and write of a policy would then depend on.
- **One version inside ate-gress.** The informer and the status writer use
  `v1alpha1`. The API server hands them every policy as `v1alpha1`,
  whichever version it was written as, so a second informer would only see
  the same objects twice. `ategressctl` reads files of either version, checks
  each against its own version's schema, and converts it to `v1alpha1` as
  the API server does; that conversion fails, rather than drops a field, if
  the versions ever differ (`internal/policyfile`).
- **Stored as `v1alpha1`, for now.** The API server records every version a
  CRD has stored objects in, in `status.storedVersions`, and refuses a CRD
  that lacks one of them. Had this release stored `v1beta1`, a rollback to
  any earlier chart would have been refused with `v1beta1 was previously a
  storage version, and must remain in spec.versions`. Serving the version
  first, and storing it later, keeps the rollback.
- **`v1beta1` is preferred.** The API server prefers the most mature served
  version, whichever is stored, so clients that name no version, `kubectl
  get` among them, get `v1beta1` for every policy.
- **`v1alpha1` is not marked deprecated.** The API server would then warn on
  every request that uses it, which is every manifest written so far and
  ate-gress's own informer. That warning belongs in the release that stops
  storing it.

The steps from here, one per release at most:

1. Serve `v1beta1`, store `v1alpha1`. This is the current state. A rollback
   to any earlier chart works.
2. Store `v1beta1`, and mark `v1alpha1` deprecated. From then on a rollback
   only works to a chart that has `v1beta1`, so this waits until nobody is
   expected to roll back past step 1. New and rewritten policies are stored
   as `v1beta1`; untouched ones stay as they are and are still served.
3. Remove `v1alpha1`. Before that, every policy must be rewritten so that
   none is stored as `v1alpha1`, and `v1alpha1` removed from
   `status.storedVersions`; otherwise the API server refuses the CRD.

`hack/upgrade-kind.sh` runs the upgrade and the rollback on a kind cluster,
and fails if an upgrade stores a version the chart it came from lacks.

## Availability

The gateway fails closed, so ate-gress availability is egress availability
for every claimed host. Unclaimed hosts still need ate-gress reachable,
because the filter runs on every HTTP request.

- **Multiple replicas.** Two by default, with a PDB and spread across nodes.
- **Headless Service.** The gateway's `STRICT_DNS` cluster resolves pod IPs
  and round-robins streams across them. Behind a ClusterIP, its single HTTP/2
  connection would pin all traffic to one pod.
- **Readiness.** A pod is not ready until a snapshot is in effect. Before
  that, it would deny everything.
- **Drain.** On SIGTERM a pod marks itself NOT_SERVING, keeps serving for
  `--drain-delay` (longer than the gateway's DNS refresh), then calls
  `GracefulStop`. `hack/e2e-kind.sh` rolls the Deployment under actor load and
  requires zero failed requests.
- **Warning before failure.** Metrics report what would otherwise first show
  as denied egress: when the serving certificate on disk expires, handshakes
  refused and why, TLS material that could not be reloaded, and a hash of the
  policies each replica's snapshot was built from, which differs on a replica
  whose informer has stopped following the cluster. The README lists them.

## Non-goals

- **Body inspection.** The extension point does not send bodies. GraphQL and
  other APIs that name their target in the body can't be filtered by
  ate-gress; deny them, and rely on credential scope.
- **Credential injection.** Substrate's `replaceHeaders` and credential
  providers already do this, with per-atespace access control. ate-gress never
  holds secrets.
- **agentgateway.** Substrate rejects the additional ext_proc option on that
  dataplane.
