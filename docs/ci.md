# CI

## What runs when

| Workflow | Pull request | Push to `main` | Nightly | Release tag | On demand |
|---|---|---|---|---|---|
| [`ci`](../.github/workflows/ci.yaml): lint, unit, race, envtest, real Envoy (the gateway's version), image build, workflow audit | yes | yes, plus 60s of each fuzz target | | yes, plus the fuzzing; nothing is published unless it passes | |
| [`envoy`](../.github/workflows/envoy.yaml): the real-Envoy test on the newest stable Envoy and on Envoy's `dev` build | yes | yes | yes | | yes |
| [`fuzz`](../.github/workflows/fuzz.yaml): Go fuzzing with a saved corpus | the targets the change can affect, 3 minutes each | | every target, 15 minutes each | | every target, for the time you give |
| [`e2e-substrate`](../.github/workflows/e2e-substrate.yaml): kind, a real Substrate, real actor traffic | only when the workflow or a script it runs changes | | yes | | yes |
| [`release`](../.github/workflows/release.yaml) | | | | yes | |

Only `ci` gates a release. The others look for trouble that arrives without
a commit here: a new Envoy, a change in Substrate, an input nobody thought
of.

Every workflow holds a read-only token. Two jobs are granted more: the
release jobs, and the job that files the nightly end-to-end issue, which
gets `issues: write` and runs no code from a repository. Actions are pinned
by commit; `zizmor` (pedantic) and `actionlint` check all of it in `ci`, and
`make lint lint-workflows` does locally.

## End-to-end against Substrate

ate-gress plugs into an extension point that Substrate calls experimental.
Substrate can change the flag, the filter it generates, the attribute that
carries the actor's identity, or the Envoy underneath, and no test in this
repository would notice. So every night
[`hack/substrate-kind-up.sh`](../hack/substrate-kind-up.sh) creates a kind
cluster and installs Substrate, and
[`hack/e2e-kind.sh`](../hack/e2e-kind.sh) installs ate-gress, points the
gateway at it, and checks what real actors can and cannot fetch.

There are three legs:

| Leg | Substrate | Installed by | Images |
|---|---|---|---|
| operator, pinned | the release in [`hack/substrate-pins.env`](../hack/substrate-pins.env) | the agent-substrate-operator chart, as the README tells users to | published |
| ate-setup, pinned | the same release | Substrate's `ate-setup`, from a checkout of the release tag | published |
| ate-setup, latest | the tip of Substrate's `main` | Substrate's `ate-setup`, from a checkout of `main` | built from the checkout |

The operator embeds one Substrate release and renders the ext_proc filter
with its own code, so it cannot install Substrate's `main`. `ate-setup` can,
and its `--experimental-additional-egress-extproc-service` flag is the
extension point itself. The two `ate-setup` legs differ only in the
Substrate they install, which makes the result readable:

| Pinned legs | Latest leg | Meaning |
|---|---|---|
| green | green | Nothing to do. |
| green | red | Substrate's `main` changed something ate-gress relies on. Read the failed leg's log next to Substrate's recent commits; the run summary names the commit tested. |
| red | red | Not Substrate's doing: ate-gress, the scripts, or the runner. |
| operator red, ate-setup green | | The operator, or the scripts' handling of it. |

A failed nightly run opens the issue "Nightly Substrate end-to-end test is
failing", or comments on it if it is open, with each leg's result. The next
passing run closes it. A scheduled run has no pull request to turn red, and
GitHub mails a failed one only to whoever last edited the schedule.

The last step of each leg, `hack/check-envoy-pin.sh`, compares the Envoy
that Substrate builds its gateway on with `ENVOY_IMAGE` in the Makefile. On
the latest leg a difference is the early warning that Substrate has moved
to an Envoy `make test-envoy` does not cover yet.

### What it needs, and why a hosted runner is enough

- **Kubernetes 1.37** with `certificates.k8s.io/v1beta1` served and the
  `ClusterTrustBundle`, `ClusterTrustBundleProjection` and
  `PodCertificateRequest` feature gates, for the pod certificates that the
  gateway and ate-gress authenticate each other with. Substrate's own
  `hack/create-kind-cluster.sh` sets these, pins kind, and starts the
  registry on `localhost:5001`; the bring-up script calls it from the
  checkout, so each Substrate gets the cluster it expects.
- **No KVM.** Only the gVisor sandbox class is installed. Micro-VM sandboxes
  need `/dev/kvm`, and nothing in the test uses them.
- **Images.** The pinned legs pull the release's images from
  `ghcr.io/ate-tooling/substrate`, which are public. The latest leg builds
  them: Go images with `ko`, and the gateway image, a Rust module on
  Envoy, with `docker buildx`. All legs build ate-gress, the egress demo
  actor and its worker image into the kind registry.
- **No secrets and no cloud.** Snapshots go to the object store the kind
  overlay runs in the cluster.

Substrate's own CI does the same on `ubuntu-latest`, with the micro-VM
suites on top.

The job compiles and runs Substrate's `main`, which nobody here reviews. It
holds a read-only token and no secrets, does not save the Go caches (the
`ci` and `release` workflows would restore them), and is separate from the
job that can write issues.

### The call to api.github.com

`hack/e2e-kind.sh` has actors fetch `https://api.github.com/...` unless
`E2E_GITHUB=0`. CI leaves it on. The gateway terminates TLS for `https`
rules and runs the ext_proc on that leg too, from a second copy of the
filter that Substrate splices in separately; the in-cluster target only
exercises the cleartext leg. Without the call, the leg ate-gress exists for
would go untested.

The call is unauthenticated, so GitHub limits it by source address, and
runners share theirs. A request that ate-gress allows and GitHub then
refuses with a rate-limit error still passes: it shows the request went
through the gateway and ate-gress, which is what the check is for. Denied
requests never reach GitHub. `workflow_dispatch` has a switch to turn the
calls off.

### Running it yourself

```sh
git clone https://github.com/agent-substrate/substrate ../substrate
git -C ../substrate checkout v1.0.0        # the release in hack/substrate-pins.env

hack/substrate-kind-up.sh ../substrate     # SUBSTRATE_INSTALL=operator, the default
hack/e2e-kind.sh ../substrate
```

For Substrate's `main`, check that out and set `SUBSTRATE_INSTALL=ate-setup`.
Both scripts default to a cluster called `substrate`
(`KIND_CLUSTER_NAME`); the bring-up refuses to replace an existing cluster
unless `RECREATE=1`. It needs Docker, `kubectl`, `helm` and Go, and about
4 GB of memory for the cluster.

kind adds the cluster to your kubeconfig and makes it the current context.
Both scripts name the context on every command, so
`export KUBECONFIG="$(mktemp)"` first keeps your own kubeconfig as it is.
The registry on `localhost:5001` is shared by every kind cluster Substrate's
script created on the machine, and `hack/e2e-kind.sh` pushes
`localhost:5001/ate-gress:e2e` to it.

In GitHub: `gh workflow run e2e-substrate`, optionally with
`-f substrate-ref=<branch, tag or commit>` for the latest leg.

### Moving the Substrate pin

Nothing moves it automatically: the pin is a statement that ate-gress
works with that release. When the agent-substrate-operator releases with a
newer embedded Substrate:

1. In `hack/substrate-pins.env`, set `SUBSTRATE_VERSION`, the commit its tag
   names (`git rev-parse 'vX.Y.Z^{commit}'`), and `OPERATOR_VERSION`.
2. Copy the last `FROM` line of Substrate's
   `cmd/dataplane/envoy/Dockerfile` at that tag into `ENVOY_IMAGE` in the
   Makefile, and its tag into the default in `test/envoy/envoy_test.go`.
   `hack/check-envoy-pin.sh <checkout>` confirms it.
3. Compare `test/envoy/envoy.yaml` with what the new release renders for the
   ext_proc filter and cluster (`emitAdditionalEgressExtprocFilter` and
   `emitAdditionalEgressExtprocCluster` in Substrate's
   `cmd/ate-setup/internal/steps/overlay.go`).
4. Open the pull request. Changing the pin file runs `e2e-substrate` on it.

## Envoy versions

`make test-envoy` runs ate-gress behind a real Envoy with the filter and
cluster configuration Substrate generates. It runs against three Envoys:

| Envoy | Image | Where | Updated by |
|---|---|---|---|
| The one Substrate's gateway ships | `ENVOY_IMAGE` in the Makefile, by digest | `ci`, so it gates pull requests and releases | hand, with the Substrate pin; the nightly end-to-end run reports when Substrate's `main` has moved |
| Newest stable | [`test/envoy/stable.Dockerfile`](../test/envoy/stable.Dockerfile), by digest | `envoy` | Dependabot. The file is never built; it is where Dependabot's docker ecosystem can read the pin. A new Envoy release arrives as a pull request, and `envoy` tests it there |
| `envoyproxy/envoy:dev`, Envoy's `main` | a moving tag, on purpose | `envoy` | nobody |

The `dev` leg is an early warning and gates nothing. On a pull request or a
push its failure does not fail the run (the job's log and annotation show
it). The nightly run does fail, and prints the digest and version of the
build it tested.

Locally: `make test-envoy`, `make test-envoy-stable`, `make test-envoy-dev`,
or `make test-envoy ENVOY_IMAGE=...` for any other.

## Fuzzing

[`hack/fuzz.sh`](../hack/fuzz.sh) finds every `func FuzzX(f *testing.F)`
and runs it with `go test -fuzz`. `make fuzz` and the workflows use it, so a
new target needs no registration.

- **Pull requests** fuzz only the targets the change can affect: those whose
  package, or a package of this module it imports, has a changed file.
  `go.mod`, the fuzz script and the workflow affect all of them, and the CRD
  affects `internal/policy`, whose schema target reads it. Each runs for
  3 minutes. A pull request that touches none runs none.
- **Nightly**, every target runs for 15 minutes, in parallel jobs.
- **The corpus persists.** Go keeps the inputs it finds interesting under
  `$GOCACHE/fuzz`. Each nightly job restores the newest saved copy for its
  target and saves the grown one under a new cache key. Pull requests
  restore it and save nothing. GitHub evicts cache entries that go a week
  unused, so the corpus lives as long as the nightly run does.
- **A crash fails the job.** `go test` minimizes the input and writes it to
  the package's `testdata/fuzz/<target>/`. The job summary shows it with the
  command that reproduces it, and the `fuzz-reproducer-<target>` artifact
  holds the file.

The files under `internal/**/testdata/fuzz` remain the record of known
crashes. `go test` replays each one in every `make test`, so the fix for a
crash is committed with the reproducer the workflow uploaded, at the path
the summary gives. The cached corpus is only a head start, and losing it
loses no regression test.

On a public repository anyone signed in can download a run's artifacts and
read its summary. An input that crashes `FuzzDecide` may be a request that
gets past a policy. Treat one as [SECURITY.md](../SECURITY.md) says: fix it
before discussing it in the open.

### Why not ClusterFuzzLite

ClusterFuzzLite was tried first and does not build these targets today. In
`gcr.io/oss-fuzz-base/base-builder-go` (November 2026, Go 1.27.1), with
`compile_native_go_fuzzer_v2`:

- The build overlays the standard library's `testing/fuzz.go`. This
  repository's `toolchain go1.27.4` line makes Go download that toolchain
  into the module cache, and Go refuses an overlay there: `overlay contains
  a replacement for .../golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/src/testing/fuzz.go.
  Files beneath GOMODCACHE must not be replaced.` It builds only with
  `GOTOOLCHAIN=local`, on whichever Go the image has, not the one the
  release is built with.
- With that, `FuzzCanonicalize`, `FuzzMatch` and `FuzzParse` build and run.
  `FuzzDecide` and `FuzzSchemaAgreesWithCompiler` do not compile: the
  tool's replacement `*testing.F` is not a `testing.TB` (`missing method
  ArtifactDir`), and both pass `f` to helpers that take one. `FuzzDecide` is
  the target that matters most.
- `FuzzSchemaAgreesWithCompiler` reads the CRD by a path relative to its
  package, which a libFuzzer binary run from another directory would not
  find.
- A libFuzzer crash file is raw bytes, not the `go test fuzz v1` file that
  `testdata/fuzz` holds, and the libFuzzer build does not replay the files
  that are there.

The targets could be rewritten to fit the tool. That would shape the tests
around the fuzzer's wrapper and still leave two corpus formats. Go's own
fuzzer runs all five as they are, with the toolchain the repository pins,
and writes reproducers in the format the repository already commits. What
ClusterFuzzLite would add is libFuzzer's sanitizers, which have little to
find in pure Go, and coverage reports. Try it again when
`go-118-fuzz-build` implements `testing.TB`.
