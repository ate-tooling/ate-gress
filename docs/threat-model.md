# Threat model

## Assets and trust

- **Protected.** Data and actions behind upstream APIs that actors reach with
  credentials Substrate injects. The canonical case is one GitHub
  organization.
- **Untrusted.** The actor, and everything it controls: method, authority,
  path, headers and timing.
- **Trusted.** Substrate's gateway. It authenticates the actor from the
  atunnel certificate and supplies the identity attribute. It also checks the
  `:authority` against the SNI it terminated, and has already applied the
  actor's `EgressPolicy`.
- **Trusted.** The Kubernetes API, which holds the policies.

## Threats and mitigations

| Threat | Mitigation | Tested by |
|---|---|---|
| Path tricks that the upstream normalizes but a matcher would not: `..`, `.`, `//`, `%2F`, `%2E`, `%5C`, `%252F`, `\`, non-ASCII | `pathmatch.Canonicalize` refuses them on claimed hosts and never repairs them. Accepted paths decode, once or twice, to the same segments and are unchanged by `path.Clean`, apart from one trailing slash | `TestCanonicalize`, `FuzzCanonicalize`, `test/envoy`, `hack/e2e-kind.sh` |
| An upstream reading `/v2/` as `/v2` | One trailing slash is accepted, and matched only by a template that spells it; `*` and `**` never match the empty segment, so at worst the upstream serves the resource the template named | `TestMatch`, `FuzzMatch`, `TestDecide`, `FuzzDecide` |
| Org prefix confusion (`acme` vs `acme-evil`), case (`ACME`) | Segment-exact matching; ASCII-only case folding where enabled | `TestMatch`, `TestDecide` |
| Query-string smuggling (`/user?x=/repos/acme/`) | The query is cut before matching | `TestCanonicalize`, `TestDecide` |
| Spelling a claimed host differently: case, port, trailing dot, userinfo, empty labels | Authority normalized; anything that is not a hostname or IP literal is denied | `TestDecide`, `FuzzDecide` |
| Endpoints that name no org: `/repositories/{id}`, `/search`, `/user`, `/graphql` | Allow-only routes; nothing outside the listed templates on a claimed host | `TestDecide`, `TestGitHubSingleOrgExample` |
| Duplicate pseudo-headers, to make the gateway and ate-gress disagree | A repeated `:method`, `:authority` or `:path` is denied | `TestProcessRequestHeaders` |
| A forged or ambiguous identity | Exact `worker-for-actor` form in the configured trust domain; conflicting attributes are denied | `TestParse`, `FuzzParse`, `TestProcessRequestHeaders` |
| Something other than the gateway calling ate-gress | mTLS 1.3 with client-certificate verification against the podidentity bundle, plus a pinned SPIFFE URI SAN; NetworkPolicy | `TestServer`, `TestProcessRequiresGatewayCertificate` |
| ate-gress down or slow, to fail open | The filter's `failure_mode_allow: false`; ate-gress not ready before its first snapshot | `test/envoy` "fails closed", `TestProcessNotReady` |
| A malformed policy widening access | Schema validation at admission; the compiler re-validates and excludes failures, which can only remove allows | `TestSchemaRejects`, `TestCompileRejects`, `FuzzSchemaAgreesWithCompiler` |
| An Audit policy widening an Enforce policy | Audit routes never allow on a host an Enforce policy claims | `TestDecideEnforceOutranksAudit` |
| Log flooding: an actor repeating denied requests, to run up log volume or bury other actors' denials | Denial and audit logs are rate-limited by actor, outcome, reason and policy, none of which the actor can vary freely; path and authority are not in the key. Denials made before an identity is parsed share one key per reason, so a made-up identity earns nothing. The limiter's table is capped, and keys beyond the cap share one bucket. Dropped lines are counted on the next line logged and in `ategress_decision_logs_suppressed_total` | `TestDecisionLogLimit`, `TestDecisionLogLimitKeys`, `TestDecisionLogLimitBeforeIdentity`, `TestDecisionLogLimitBound`, `internal/loglimit` |
| Credential leakage via logs | No header values logged, including for `logAllowed`; the path is logged without its query | `TestDecisionLogOmitsHeaderValues`, `TestDecisionLogLevels` |

## Residual risk

- **Body-addressed APIs.** GraphQL and other batch APIs can't be checked.
  Deny them, and scope the injected credential to the organization. The
  credential's scope is the real boundary; ate-gress is defense in depth.
- **Unauthenticated public data.** Path rules can keep an actor away from
  another organization's public repositories. Nothing here stops the actor
  from encoding data into the paths it is allowed to request.
- **Hosts on `tls_passthrough` rules.** Their traffic never reaches
  ate-gress.
- **Extension point is experimental.** Substrate may change it. The Envoy
  integration test pins the filter and cluster configuration it is built
  against.
