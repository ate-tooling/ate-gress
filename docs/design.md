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

## Non-goals

- **Body inspection.** The extension point does not send bodies. GraphQL and
  other APIs that name their target in the body can't be filtered by
  ate-gress; deny them, and rely on credential scope.
- **Credential injection.** Substrate's `replaceHeaders` and credential
  providers already do this, with per-atespace access control. ate-gress never
  holds secrets.
- **agentgateway.** Substrate rejects the additional ext_proc option on that
  dataplane.
