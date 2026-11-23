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
internal/controller  informer -> Compile -> Store; status writer
internal/tlsconfig   mTLS with per-handshake certificate reload
```

Every security decision is made in `policy.Snapshot.Decide`. It is a pure
function of compiled policies and four strings: actor, method, authority and
path. It is tested exhaustively, and fuzzed against a reference implementation
written to be obviously correct. The ext_proc server and the controller are
thin adapters around it.

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

## Control plane

- **Snapshot builder (every replica).** It waits for the informer cache to
  sync, then compiles all policies into a new snapshot on every spec change
  and swaps it in. Rebuilding from the full list, instead of patching, keeps
  the snapshot a pure function of the cache. It runs once per change and
  costs microseconds.
- **Status writer (leader only).** It compiles each policy alone and sets
  `Accepted`. Policies compile independently, so this is the same verdict
  every replica's snapshot reaches.
- **Validation in two layers.** The CRD schema rejects bad specs at
  admission. It uses one OpenAPI pattern for the path grammar, because the
  equivalent CEL rules exceeded the API server's cost budget. The compiler
  re-validates everything and excludes a policy it rejects. Excluding a policy
  can only remove allows. A fuzz test checks that the schema pattern and the
  compiler accept exactly the same templates.

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
