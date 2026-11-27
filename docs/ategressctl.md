# ategressctl

`ategressctl` checks `EgressRoutePolicy` files without a cluster. It is for
keeping policies in git and gating changes to them in CI.

It answers with the code ate-gress answers with. Every decision ate-gress
makes comes from compiling the policies and calling one pure function on the
actor, method, authority and path. `ategressctl` compiles the files the same
way and calls the same function, so what it reports for a policy set is what
a cluster holding that set does. Nothing about a decision is implemented a
second time.

It is a separate binary. The server image does not contain it.

```
ategressctl test    [-f <policies>]... <test file>...
ategressctl explain  -f <policies>...  -a <atespace>/<name> <METHOD> <URL>
ategressctl lint     -f <policies>...  [--egress-policy [<atespace>/<name>=]<file>]...
ategressctl version
```

## Install

Each release has a binary for Linux and macOS, on amd64 and arm64:

```sh
VERSION=0.1.0
gh release download "v$VERSION" --repo ate-tooling/ate-gress \
  --pattern "ategressctl-$VERSION-linux-amd64" --pattern checksums.txt
sha256sum --check --ignore-missing checksums.txt
gh attestation verify "ategressctl-$VERSION-linux-amd64" --repo ate-tooling/ate-gress \
  --signer-workflow github.com/ate-tooling/ate-gress/.github/workflows/release.yaml \
  --source-ref "refs/tags/v$VERSION" --deny-self-hosted-runners
install -m 0755 "ategressctl-$VERSION-linux-amd64" /usr/local/bin/ategressctl
```

[releasing.md](releasing.md#verifying-a-release) says what the attestation
proves. From a checkout, `make build-ategressctl` builds `bin/ategressctl`.

## Policy files

`-f` names where the policies are, and may be repeated:

- a file of one or more YAML or JSON documents;
- a directory, searched recursively for `.yaml`, `.yml` and `.json` files,
  skipping directories whose name starts with a dot;
- `-` for stdin.

A document is an `EgressRoutePolicy`, or a list of them as `kubectl get
egressroutepolicies -o yaml` prints. A directory may also hold other things:
test files, other manifests. Those are skipped. A file you name must hold
policies and nothing else. An object in the `ategress.ate-tooling.github.io`
group that is not a readable `EgressRoutePolicy` is an error wherever it is
found, so a mistyped `kind` or an unknown version is never skipped. Two
policies with one name are an error: a cluster holds one.

A policy may be written as any version the CustomResourceDefinition serves,
`v1beta1` or `v1alpha1`. Each is checked against its own version's schema,
and both read the same, as the API server reads them: it stores either as
`v1alpha1` and changes only the `apiVersion`
([API versions](../README.md#api-versions)).

### Validation

Every command first checks each policy twice, and reports what fails:

1. **As the API server would at admission.** The check runs the
   CustomResourceDefinition's OpenAPI schema, the one `make generate` writes
   and the chart installs, through the validator the API server uses. It also
   checks `metadata.name`, the uniqueness the schema's list types declare (a
   method, path, host or glob listed twice), and unknown fields, which
   `kubectl apply` refuses by default.
2. **As ate-gress would when it compiles.** A policy the compiler rejects
   allows nothing and still claims its hosts: none of its routes is applied,
   and requests to its hosts from the actors it selects are denied with
   reason `invalid_policy` unless another `Enforce` policy allows them. Its
   mode is read as `Enforce` unless it says `Audit`, and a selector list with
   a glob that does not compile as selecting everyone. The `ERP003` finding
   says what the policy claims.

`test` and `explain` stop when a policy fails either check. The compiler
re-checks everything the schema checks, so a policy it rejects is also one the
API server refuses: a cluster with this CRD cannot hold the set, and reaches
it only past an older CRD. A decision made against a policy set no cluster
would hold says nothing, and the policy needs fixing first. `lint` does read
such a set, with the rejected policy's claims in it.

The first check is tested against a real API server. The test suite submits a
table of valid and invalid policies to one and requires the offline verdict to
be the server's on each. One difference is deliberate: a manifest with
`metadata.generateName` and no `name` is valid for the API server and refused
here, because nothing offline can refer to a policy without a name.

A YAML key written twice in one mapping is an error (exit `2`), as it is for
`kubectl apply`.

## test

```sh
ategressctl test examples/github-single-org.tests.yaml
```

runs each case in each test file through the policies and prints a line per
case. It exits `1` if a case fails or a policy is invalid.

### The test file

A test file says which requests the policies must allow, deny and audit,
grouped by the actor that sends them:

```yaml
policies:                       # relative to this file, not "-"; -f replaces them
- github-single-org.yaml

tests:
- name: research reads acme     # optional, printed in the report
  actor: research/agent         # <atespace>/<name>
  allow:
  - GET https://api.github.com/repos/acme/widget
  - GET https://github.com/acme/widget.git/info/refs?service=git-upload-pack
  deny:
  - POST https://github.com/acme/widget.git/git-receive-pack
  - request: POST https://api.github.com/graphql
    reason: no_route
    policy: github-lockdown

- actor: billing/agent
  deny:
  - GET https://api.github.com/repos/acme/widget
```

A case is a request, written `<METHOD> <URL>`, under the outcome it must have:

| Under | The request must be |
|---|---|
| `allow` | allowed, and not merely because of Audit mode |
| `deny` | denied |
| `audit` | allowed only because every policy claiming the host for the actor is in `Audit` mode: `Enforce` would deny it |

A case can instead be a mapping, to also pin down why. Each field you give
must equal the decision's; the ones you leave out are not checked.

| Field | Meaning |
|---|---|
| `request` | `<METHOD> <URL>` |
| `reason` | The decision's reason: `route` or `unclaimed` under `allow`; `no_route`, `path`, `invalid_policy` or `authority` under `deny`; `no_route`, `path` or `invalid_policy` under `audit` |
| `policy` | Under `allow`, the policy whose route matched. Under `deny` and `audit`, the first policy, by name, that claims the host for the actor |
| `template` | The path template that matched |

`reason: unclaimed` is worth using when a test means "these policies leave
this host alone": a request no policy claims is allowed, and without the
reason a typo in the hostname would pass as well.

The URL is split into the `:authority` and `:path` a client would send, and
nothing else is done to it. It is not decoded, cleaned or lowercased, so a
test can send `/repos/acme/../other`, `%2F`, or `user@host` and check that it
is denied with reason `path` or `authority`. Only the scheme must be `http`
or `https`; ate-gress decides both alike. A fragment is dropped, as a client
drops it.

The actor must be two DNS labels, as Substrate's actor identities are. A
request from anything else never reaches the policies: the server denies it
with reason `identity`.

`policies` is optional. With `-f` on the command line, the files it names are
used instead, which is how to run one set of expectations against a candidate
policy set:

```sh
ategressctl test -f candidate-policies/ expectations.tests.yaml
```

Unknown fields in a test file, and reasons that the outcome cannot have, are
errors (exit `2`), so a misspelling does not become a test that silently
checks nothing.

## explain

```sh
ategressctl explain -f examples/ -a research/agent \
  GET 'https://api.github.com/repos/acme/widget/pulls?state=open'
```

```
request   GET https://api.github.com/repos/acme/widget/pulls?state=open
actor     research/agent
decision  allow
reason    route: a route matched the method and path
policy    github-acme-readonly
template  /repos/acme/*/**

Policies claiming api.github.com for research/agent:
  github-acme-readonly  Enforce  alone: allow (route, /repos/acme/*/**)
  github-lockdown       Enforce  alone: deny (no_route)
```

It prints the decision, its reason, the policy and template that matched, and
every policy that claims the host for the actor, in the order ate-gress
considers them. `alone` is what the decision would be if that policy were the
only one. It comes from compiling that policy by itself and deciding again,
so it shows which policy a request depends on.

For a denied or audited request, `policy` is the first policy claiming the
host. That is what ate-gress logs; no policy matched. With reason
`invalid_policy` it is the first rejected policy that decided. A rejected
policy is marked `rejected` in the list of claims.

`explain` exits `0` whatever the decision is, and `1` if a policy is invalid.

## lint

```sh
ategressctl lint -f policies/
ategressctl lint -f policies/ --egress-policy research/agent=agent-egress.yaml
```

reports mistakes that can be found without a request. Each finding has a
stable code and name, the policy, its file, and the field it is about.

| Code | Name | Severity | What it means |
|---|---|---|---|
| `ERP001` | `schema` | error | The API server would reject the policy |
| `ERP002` | `duplicate-item` | error | A method, path, host or selector glob is listed twice; the API server rejects the policy |
| `ERP003` | `compile` | error | The compiler rejects the policy: it allows nothing and still claims its hosts for the actors it selects, so they are denied with `invalid_policy` unless another `Enforce` policy allows them |
| `ERP101` | `audit-shadowed` | warning | An `Audit` policy never has effect on a host: an `Enforce` policy claims the host for every actor it selects |
| `ERP102` | `audit-partly-shadowed` | warning | The same, for some of its actors. The finding names one |
| `ERP103` | `audit-maybe-shadowed` | info | An `Enforce` policy claims the host too, and whether their selectors can select the same actor could not be settled |
| `ERP201` | `redundant-path` | warning | A path template allows nothing that another template of the same policy and host does not |
| `ERP202` | `overlapping-routes` | info | A template is already allowed by another route for some of its methods |
| `ERP301` | `tls-passthrough` | warning | With `--egress-policy`: a claimed host is on a `tls_passthrough` rule, so ate-gress never sees that traffic |
| `ERP302` | `host-not-reached` | info | With `--egress-policy`: no `http` or `https` rule reaches a claimed host |

`ategressctl lint --list` prints the same table. Codes and names do not change
or get reused; new checks get new codes.

`lint` exits `1` if there is a finding at or above `--fail-on`, which is
`error` by default and may be `warning`, `info` or `never`.

### What the findings claim

Lint reports what follows from the policies, and says so when something does
not.

**Audit policies.** An `Enforce` policy on a host always takes precedence:
once one claims the host for an actor, the request is decided by the
`Enforce` policies' routes alone. An `Audit` policy's routes are not
consulted and no audit is recorded. Its `logAllowed` still applies. A
rejected `Enforce` policy counts: it claims its hosts with no routes, for the
actors its selector is read to select, so it shadows an `Audit` policy as a
lockdown would, and the finding says it was rejected. A rejected `Audit`
policy is left to its `ERP003` finding.

Whether that happens depends on whether two selectors select the same actor,
and selectors are globs. Lint separates three cases:

- `ERP101`: every glob of the `Audit` policy is contained in a glob of the
  `Enforce` policy. This is proved for all strings, so it holds for all
  actors.
- `ERP102`: the selectors share an actor. Lint constructs one, checks it
  against both compiled selectors, and prints it.
- `ERP103`: neither of those, and the selectors are not provably disjoint
  either. The finding says "may".

Lint looks at one `Enforce` policy at a time. An `Audit` policy that several
`Enforce` policies shadow only between them is reported as `ERP102`, not
`ERP101`.

**Redundant paths.** Routes only allow, so a template is redundant exactly
when another one of the same policy and host matches every path it matches,
for every method of its route. `caseInsensitive` counts: a case-sensitive
template does not cover a case-insensitive one. Routes of other policies are
not compared, because whether they apply depends on their selectors and
modes.

### Checking against Substrate's EgressPolicy

Substrate's own `EgressPolicy` decides, for each hostname and port, how the
gateway handles an actor's traffic:

- an `http` rule: cleartext HTTP, which ate-gress sees;
- an `https` rule: TLS the gateway intercepts, which ate-gress sees;
- a `tls_passthrough` rule: TLS forwarded undecrypted. The gateway never
  calls ate-gress, so an `EgressRoutePolicy` on that host is not enforced,
  and nothing says so.

`--egress-policy <file>` checks every host the policies claim against one
`EgressPolicy`. The file is the manifest `kubectl ate create egress-policy -f`
takes and `kubectl ate get egress-policy <actor> -a <atespace> -o yaml`
prints: one YAML or JSON document with `rules`, and optionally `metadata`.

```yaml
rules:
- https:
    hostnames: [api.github.com]
- tlsPassthrough:
    hostnames: ["*.github.com"]
    ports:
      numbers: [443]
```

It is read as Substrate reads it. A hostname pattern is a name, `*.` and a
name for exactly one more label, or `*` for everything. When several rules
match a host on a port, the one with the most specific pattern decides, then
one that names the port over one for all ports; cleartext is decided by the
`http` rules and a TLS connection by the `https` and `tls_passthrough` rules
together. An `http` rule without ports means port 80, and an `https` rule
port 443. Field names may be in either form protobuf JSON accepts
(`tlsPassthrough` or `tls_passthrough`). An unknown field is an error, as it
is for `kubectl ate`, because a rule read wrongly would make the answer
wrong.

`ERP301` names the ports that are passed through and the rule that does it,
and, if the host is intercepted on other ports, those too. `ERP302` means the
gateway refuses the host's traffic before it would call ate-gress. That is
often intended, for instance when a lockdown policy claims a host that this
actor has no business with, which is why it is `info`.

An `EgressPolicy` belongs to one actor, and the manifest does not name it.
Tell lint with a prefix, and only the policies that select that actor are
checked:

```sh
ategressctl lint -f policies/ --egress-policy research/agent=agent-egress.yaml
```

Without the prefix, the manifest's `metadata.atespace` narrows the check to
policies whose atespace globs match it, and without that every policy is
checked. The flag may be repeated, once per actor.

Not read: an `ActorTemplate`'s `goldenEgressPolicy`. It has the same rules,
but applies only to the golden actor during initialization. To check one, put
its `rules` in a file of their own.

## Output and exit codes

Every command prints text by default and JSON with `-o json`. Reports go to
stdout. Errors that stopped the command go to stderr.

| Exit code | Meaning |
|---|---|
| `0` | The command ran and found nothing wrong |
| `1` | A test case failed, a policy is invalid, or lint has a finding at or above `--fail-on` |
| `2` | The command could not do its job: bad flags, an unreadable or malformed file, a test file that makes no sense |

In CI, `1` means "the policies need a look" and `2` means "the job is
broken".

The JSON:

- `test`: `passed`, `failed`, and `files`, each with `file`, `policies`,
  `invalidPolicies` (findings, as from `lint`) and `cases`. A case has `id`
  (its place in the test file, such as `tests[0].deny[1]`), `group`, `actor`,
  `request`, `want`, `got`, `passed` and `mismatches`. `want` and `got` have
  `decision` (`allow`, `deny` or `audit`), `reason`, `policy` and `template`.
- `explain`: `actor`, `method`, `url`, `authority`, `path`, `host`,
  `decision`, `reason`, `policy`, `template`, `logAllowed`, and `claims`, each
  with `policy`, `mode`, `logAllowed`, `rejected` (only when set) and
  `alone`.
- `lint`: `findings`, each with `code`, `name`, `severity`, `policy`, `file`,
  `document` (the position of the YAML document in the file, from 1), `field`
  and `message`; and `summary`, the count per severity.

Match on a finding's `code` or `name`, not its `message`.

## In CI

```yaml
- run: |
    ategressctl lint -f policies/ --fail-on warning
    ategressctl test policies/*.tests.yaml
```

Keep a test file next to each policy file, as
[`examples/github-single-org.tests.yaml`](../examples/github-single-org.tests.yaml)
is next to its policies, and write a `deny` case for everything the policy
exists to stop.

## What it does not tell you

- Whether the gateway calls ate-gress at all for a host. That is Substrate's
  `EgressPolicy`; `lint --egress-policy` checks the manifests you give it and
  nothing reads a live cluster.
- What the server denies before it reaches the policies: a request without
  exactly one well-formed actor identity (`identity`), with a missing or
  repeated pseudo-header (`headers`), or arriving before the first snapshot
  (`not_ready`).
- What the upstream does with an allowed request. See the
  [threat model](threat-model.md).
