# Contributing

ate-gress decides whether an agent's request leaves the cluster. A change
that makes it allow one request too many is a security bug, so most of this
document is about what a change has to bring with it to show that it does
not.

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) says, not in
an issue or a pull request.

## Build and test

You need Go (the version in `go.mod`), Docker and Helm. The
[Makefile](Makefile) is the source of truth; these are its targets:

```sh
make build        # bin/ate-gress
make test         # unit and controller tests, with -race, three times, shuffled
make fuzz         # each fuzz target for FUZZTIME (default 10s)
make bench        # request-path benchmarks
make test-envoy   # behind a real Envoy configured like Substrate's gateway (Docker)
make lint         # golangci-lint, actionlint, shellcheck, helm lint (Docker, Helm)
make lint-workflows   # zizmor audit of the GitHub workflows (Docker)
make vulncheck    # govulncheck
make generate     # deepcopy code, the CRD, and RBAC
make verify       # generate, lint, test, go mod tidy; fails if any of it changed a tracked file
```

`make test` downloads an API server and etcd into `bin/envtest` the first
time, for the controller tests. `make test-envoy` pulls the Envoy image named
by `ENVOY_IMAGE`.

`hack/e2e-kind.sh <substrate checkout>` runs against a kind cluster that
already runs Substrate, installed by the agent-substrate-operator. CI does
not run it. Run it for a change to the ext_proc server, the chart, shutdown
or anything else the kind test drives, and say in the pull request that you
did.

CI runs `make verify`, `make vulncheck`, the workflow audit, `make fuzz
FUZZTIME=60s`, `make test-envoy` and an image build on every pull request.
Run `make verify` before you push; it is the same check.

### Fuzzing

There are five fuzz targets. Each states a property, not an example:

| Target | Property |
|---|---|
| `FuzzCanonicalize` | An accepted path decodes, once or twice, to the same segments, and `path.Clean` changes nothing but one trailing slash |
| `FuzzMatch` | A template and a path it matches agree on a trailing slash, and a template without wildcards matches only the path it spells |
| `FuzzParse` | An accepted actor identity is exactly the SPIFFE ID its atespace and name rebuild |
| `FuzzDecide` | `Snapshot.Decide` agrees with `referenceDecide`, a slow implementation in the test file written to be obviously correct |
| `FuzzSchemaAgreesWithCompiler` | The CRD's path pattern admits exactly the templates `pathmatch.Compile` accepts |

When a fuzz target fails, Go writes the input under `testdata/fuzz/`. Commit
it with the fix: it becomes a regression test that `make test` runs.

For a change to path handling or to `Decide`, fuzz for longer than the
default before you open the pull request, for example `make fuzz
FUZZTIME=5m`, and say how long in the pull request.

## Generated files

`make generate` writes:

- `api/v1alpha1/zz_generated.deepcopy.go` and
  `api/v1beta1/zz_generated.deepcopy.go`;
- `config/crd/`, and the chart's copy of it,
  `charts/ate-gress/templates/crds.yaml`, which
  `hack/generate-chart-crds.sh` writes;
- `config/rbac/role.yaml`, and its rules in
  `charts/ate-gress/files/clusterrole-rules.yaml`.

Never edit these by hand. Change the Go types or the `+kubebuilder` markers
and run `make generate`. The two API versions have one schema, so a change to
`api/v1alpha1/egressroutepolicy_types.go` is copied to
`api/v1beta1/egressroutepolicy_types.go`; tests in `api/` fail until the two
files differ only in their package and the storage-version marker.
[docs/design.md](docs/design.md#api-versions) says why. `make verify` regenerates them, runs `go mod tidy`,
and fails if `api`, `config`, the chart, `go.mod` or `go.sum` differ from
what is committed, so a stale file fails CI.

## Changing what a policy can say, or what `Decide` does

Every security decision is made in `policy.Snapshot.Decide`, from compiled
policies and four strings. The pieces below each check one another. A change
to the policy grammar, to path or authority handling, or to `Decide` is
complete only when all of them have moved together.

1. **It must not widen existing policies.** A policy that is valid today
   must not allow a request tomorrow that it denies today. Trailing-slash
   templates were added this way: `*` and `**` were defined not to match the
   new empty segment, so no existing template matches more. If a change
   cannot keep this, say so at the top of the pull request.

2. **The schema pattern and the compiler accept the same templates.** The
   CRD validates a path template with one OpenAPI pattern, in the
   `+kubebuilder:validation:items:Pattern` marker on `Route.Paths` in
   `api/v1alpha1/egressroutepolicy_types.go` and its `v1beta1` copy. `pathmatch.Compile` is what the
   decision relies on. `FuzzSchemaAgreesWithCompiler` reads the generated CRD
   and fails if the two disagree on any input. Change both, run `make
   generate`, and add seeds for the new syntax to the fuzz target.

3. **The compiler re-checks everything the schema checks.** The schema can
   be bypassed by an older CRD, so `compilePolicy` validates hosts, selector
   globs, methods and paths again, with the same patterns. A new field that
   the schema validates needs the same check in `internal/policy/compile.go`,
   a case in `TestCompileRejects`, and a case in `TestSchemaRejects`, which
   runs against a real API server. A policy the compiler rejects fails
   closed: it keeps its host claims with no routes, as `rejectedClaims` in
   `internal/policy/compile.go` reads them, so it allows nothing and denies
   on its hosts with reason `invalid_policy`. A new field that a rejected
   policy could be misread through needs the same conservative reading
   there.

4. **`referenceDecide` is updated by hand, not by copying.** `FuzzDecide`
   compares `Decide` with the reference implementation in
   `internal/policy/policy_test.go`. Its value is that it shares no code with
   the real one. When semantics change, write the new behaviour into the
   reference from the specification, then make `Decide` agree with it. If the
   set of policies the fuzz target compiles (`githubPolicies`) cannot
   exercise the change, extend it.

5. **The request path does not allocate.** `TestDecideDoesNotAllocate`,
   `TestMatchDoesNotAllocate`, `TestCanonicalizeDoesNotAllocate` and
   `TestParseDoesNotAllocate` enforce it. Run `make bench` and put the
   before and after in the pull request if you touched that path.

6. **The threat model has a row for it.** [docs/threat-model.md](docs/threat-model.md)
   lists each threat, its mitigation, and the tests that hold the mitigation
   in place. A change that adds an attack surface adds a row. A change that
   moves a mitigation updates the row and its "Tested by" column. If the
   change leaves something unmitigated, add it to "Residual risk".

7. **It is tested behind a real Envoy** if it changes which paths or
   headers are accepted: add cases to `test/envoy/envoy_test.go`. The two
   blocks of `test/envoy/envoy.yaml` marked "verbatim" are copies of what
   Substrate renders. Change them only to follow Substrate, never to make a
   test pass.

8. **Deny reasons are an interface.** The `policy.Reason` values are metric
   labels and are returned to actors in `x-ate-gress-reason`. Do not rename
   one. Adding one, or changing which reason an existing request gets, is a
   behaviour change operators alert on: see
   [docs/compatibility.md](docs/compatibility.md), and put it in the
   changelog under an **Operators** entry.

9. **An example shows it, and a test holds the example.** If the change lets
   policies express something new, use it in a file under `examples/` or add
   one, with a test in `internal/policy` that lists requests it must allow
   and requests it must deny. `TestExamplesCompile` compiles every example.
   Update the "Policies" section of the README and the field's doc comment,
   which becomes the CRD's description.

10. **A new API field is optional, and its zero value means "as before".**
    Think through both directions of a version mismatch and write them in the
    pull request: an older ate-gress reading a policy that uses the field,
    and an older CRD pruning it.

## Other changes

- **The chart.** `make lint` runs `helm lint`. The chart's CRD and RBAC rules
  are generated; see above.
- **Workflows.** `make lint` and `make lint-workflows` run the same
  `actionlint` and `zizmor` checks as CI. Actions are pinned to a commit SHA
  and jobs get only the permissions they use; [docs/releasing.md](docs/releasing.md)
  explains why.
- **Dependencies.** Dependabot proposes updates a week after their release.
  Minor and major versions of `k8s.io/*` and `controller-runtime` move
  together and are bumped by hand.
- **Documentation.** Keep it short, plain and concrete, and say why. Do not
  describe a feature before it is merged.

## Commits and pull requests

- Branch from `main`. Changes are merged by pull request with a merge
  commit.
- Write the subject in the imperative, capitalized, with no prefix and no
  trailing period: "Allow trailing-slash templates and per-policy
  logAllowed". Keep it near 60 characters.
- Use the body to say what changed in behaviour and why, wrapped at 72
  columns. If a commit fixes something, say what was wrong. Reference the
  issue with `Closes #7`.
- If an AI assistant wrote part of the change, keep its `Co-Authored-By`
  trailer.
- In the pull request, give the summary, then the evidence: what the
  behaviour was before and is after, and which tests show it. For a change
  under "Changing what a policy can say", also say whether it can be rolled
  back and what it affects if it is wrong.
- Add an entry to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md)
  for anything a user or operator would notice. Mark it **Operators** if it
  changes what a running installation does.

Releases are cut by a maintainer; [docs/releasing.md](docs/releasing.md)
describes how.
