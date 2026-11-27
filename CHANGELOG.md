# Changelog

All notable changes to ate-gress are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions before 0.1.0 were release candidates, and anything could change
between two of them. [docs/compatibility.md](docs/compatibility.md) says what
is promised from 0.1.0 on. Entries marked **Operators** change what a
running installation does and need action or attention on upgrade.

## [Unreleased]

## [0.1.0] - 2026-11-27

### Added

- `EgressRoutePolicy` is served as `v1beta1` as well as `v1alpha1`, with the
  same schema. Policies are still stored as `v1alpha1`, and `v1alpha1` is not
  deprecated; `kubectl get` prints `v1beta1`. The examples and the README
  are written as `v1beta1`. See
  [API versions](README.md#api-versions).
- `ategressctl`, a separate binary that checks policy files without a
  cluster: `test` runs a table of requests through them, `explain` says why
  one request is decided as it is, and `lint` finds policies the API server
  or the compiler would reject, `Audit` policies an `Enforce` policy
  overrides, redundant paths, and claimed hosts that a Substrate
  `EgressPolicy` passes through undecrypted. It decides with ate-gress's own
  code and validates against the CRD's schema, for either API version.
  Releases attach binaries for Linux and macOS, with build provenance
  attestations.
  [docs/ategressctl.md](docs/ategressctl.md).
- Metrics: `ategress_policy_decisions_total{policy,decision}`, requests
  counted against each policy, with the rule for when an `Audit` policy is
  safe to switch to `Enforce`; `ategress_decision_logs_suppressed_total`;
  `ategress_snapshot_last_build_timestamp_seconds` and
  `ategress_snapshot_policies_hash`, to see replicas serving different
  policies; `ategress_tls_certificate_expiry_timestamp_seconds`,
  `ategress_tls_reload_failures_total{file}` and
  `ategress_tls_handshake_failures_total{reason}`;
  `ategress_active_streams`; and `ategress_build_info{version,goversion}`.
  [Metrics](README.md#metrics).
- The deny reason `invalid_policy`, for a request to a host where every
  `Enforce` policy claiming it for the actor was rejected; see Fixed.
- Example policies for PyPI, the npm registry, `ghcr.io`, Amazon S3 and the
  Claude API, each with a test and an `ategressctl` test file, and an index
  of them in [examples/README.md](examples/README.md).
- This changelog, [CONTRIBUTING.md](CONTRIBUTING.md),
  [docs/compatibility.md](docs/compatibility.md), and a proposed design for
  letting atespace owners write their own policies,
  [docs/adr/0001-policy-delegation.md](docs/adr/0001-policy-delegation.md).
- Opt-in chart monitoring: a `PodMonitor`, a `PrometheusRule` with 14
  alerts whose thresholds are chart values, a Grafana dashboard, and
  aggregated ClusterRoles that let `view` and `edit` read policies and only
  `admin` write them. Also zone topology spread, optional required pod
  anti-affinity, extra pod labels and annotations, and `imagePullSecrets`.
  [docs/runbook.md](docs/runbook.md) has a section per alert and the
  break-glass procedure; [docs/sizing.md](docs/sizing.md) has measured
  throughput, latency, CPU and memory, and `make load-test` reproduces them.
- CI runs the Envoy test on the newest stable Envoy and on Envoy's `dev`
  build, fuzzes the targets a pull request can affect and every target
  nightly with a saved corpus, tests a chart upgrade and rollback on kind,
  and runs the end-to-end test against a real Substrate nightly.
  [docs/ci.md](docs/ci.md).

### Changed

- **Operators:** the chart ships the CRD as a template, so `helm upgrade`
  upgrades it and `helm rollback` puts the earlier one back; `helm
  uninstall` keeps it, and the policies with it. `crds.install=false` leaves
  the CRD to you. **Once, when upgrading from 0.1.0-rc.4 or earlier**, hand
  the CRD to the release before `helm upgrade`, with the `kubectl label` and
  `kubectl annotate` commands under [Upgrade](README.md#upgrade); without
  them the upgrade stops with `invalid ownership metadata` and changes
  nothing.
- **Operators:** denial and audit decision logs are rate-limited, on by
  default: each actor gets a burst of 10 lines for each reason and policy,
  then 1 line a second (`--deny-log-burst` and `--deny-log-rate`, chart
  values `denyLogBurst` and `denyLogRate`). The next line logged carries the
  number dropped as `suppressed`, or `suppressed_untracked` when too many
  keys are busy to track, and `ategress_decision_logs_suppressed_total`
  counts them. `ategress_decisions_total` still counts every decision, and
  the allowed requests of `logAllowed` policies, and every line at `DEBUG`,
  are never dropped. `denyLogRate: 0` logs every denial, as before.
- **Operators:** new metrics, listed under Added. Dashboards and alerts need
  no change; the existing metrics are unchanged. Scrapes grow by three
  series per policy, from `ategress_policy_decisions_total`.
- **Operators:** the chart has a `values.schema.json`, so a value it does
  not know, or one of the wrong type, now fails `helm install` and `helm
  upgrade` instead of being ignored.
- **Operators:** `v1beta1` is served. Charts up to 0.1.0-rc.4 serve only
  `v1alpha1`: keep manifests at `v1alpha1` while you may run, or roll back
  to, one of them. A rollback keeps every policy, because they are stored as
  `v1alpha1`; [Rollback](README.md#rollback) lists what to expect from
  `kubectl` after one.

### Fixed

- **Security:** a path whose segment is a dot segment once its
  `;path-parameters` are removed, such as `/public/..;/admin`, is now denied
  with reason `path`. Java servlet containers (Tomcat, Jetty, Spring) strip
  path parameters before resolving dot segments, so such a request matched
  `/public/**` here and reached `/admin` upstream. `%3B` (an encoded `;`) is
  refused too, as are segments that are empty before a `;`.
- **Operators:** for the same reason, the CRD and the compiler refuse a
  `paths` template with a segment that is empty, `.` or `..` before its
  first `;`, such as `/a/..;x`, which no request could match any more. An
  existing policy with one is rejected and fails closed.
- **Operators:** the chart's `terminationGracePeriodSeconds` follows
  `drainDelay` and `stopTimeout` (their sum plus 20s) instead of being
  fixed at 40s, so a longer drain is no longer cut short by SIGKILL. The
  default is still 40s.
- **Operators:** the chart's schema refuses `denyLogBurst: 0`, which the
  binary refuses at startup whenever `denyLogRate` is not 0.
- **Operators, Security:** a rejected policy now fails closed. A policy the
  compiler rejects (after a rollback, or under a CRD older than the binary)
  used to be left out of the snapshot, which released every host it alone
  claimed: requests that it denied were allowed, as `unclaimed`. That was a
  fail-open bug. It now allows nothing and still claims its hosts for the
  actors it selects, reading what it cannot understand as denying more: a
  mode other than `Audit` is `Enforce`, and a selector list with a bad glob
  selects everyone. Requests to those hosts are denied with reason
  `invalid_policy` unless another `Enforce` policy allows them, and its
  `Accepted` condition says what it still claims. Traffic that flowed under
  a rejected policy stops: alert on `ategress_policies{state="rejected"} >
  0` and on `invalid_policy`, and fix or delete the policy to lift it.
  Rolling back to 0.1.0-rc.4 or earlier brings the old behaviour back.

## [0.1.0-rc.4] - 2026-11-23

### Added

- A path template may end in `/` to match exactly that one trailing slash, so
  a policy can allow a registry's `GET /v2/`. `*` and `**` never match the
  empty segment a trailing slash leaves, so existing policies allow nothing
  new. ([#7], [#8])
- `spec.logAllowed`. A policy that sets it logs, at `INFO`, the allowed
  requests of the actors and hosts it selects, with the same fields as a
  denial. Without it, allowed requests are logged only at `DEBUG`. ([#7],
  [#8])

### Changed

- **Operators:** a request whose path ends in one trailing slash, on a
  claimed host, is no longer refused as an ambiguous path. If no template
  allows it, it is still denied, but with `x-ate-gress-reason: no_route`
  where it used to be `path`. Alerts and dashboards on `reason="path"` no
  longer count these requests. Every other empty segment (`//`, `/a//b`,
  `/v2//`) is still denied with `path`.
- **Operators:** the CRD changed: the path pattern admits a trailing slash,
  and `spec.logAllowed` is new. Helm installs the CRDs in a chart's `crds/`
  directory only on first install and does not upgrade them. Apply
  `ate-gress-0.1.0-rc.4-crds.yaml` from the release before you upgrade the
  chart. Under the older CRD the API server rejects a trailing-slash
  template and silently drops `logAllowed`.
- **Operators:** rolling back to rc.3 while a policy uses a trailing-slash
  template makes rc.3 reject that whole policy. A rejected policy is left
  out of the snapshot, so it stops allowing its routes and stops claiming its
  hosts.
- Hosts claimed by a `logAllowed` policy produce more `INFO` log volume.

## [0.1.0-rc.3] - 2026-11-18

### Changed

- **Operators:** the project moved to the `ate-tooling` organization. The
  image is `ghcr.io/ate-tooling/ate-gress`, the chart is
  `oci://ghcr.io/ate-tooling/charts/ate-gress`, and the Go module is
  `github.com/ate-tooling/ate-gress`. ([#6])
- **Operators:** the API group is now `ategress.ate-tooling.github.io`; it
  was `ategress.samueltorres.github.io`. A new group is a new CRD. Nothing
  migrates objects from the old one: recreate every `EgressRoutePolicy` under
  the new group, and delete the old CRD. Until the policies are recreated,
  the new version sees none and claims no host. ([#6])
- Release signatures and attestations are issued to the release workflow of
  `github.com/ate-tooling/ate-gress`, and `hack/verify-release.sh` checks for
  that identity. ([#6])
- `github.com/envoyproxy/go-control-plane/envoy` 1.40.0. ([#5])

## [0.1.0-rc.2] - 2026-11-17

### Fixed

- The GitHub release published the build records of
  `docker/build-push-action` as release assets and listed them in
  `checksums.txt` under names GitHub then rewrote, so the release's own
  verification failed. The release now publishes only the CRD, the chart
  archive, the SBOM and the checksums, and fails if it finds anything else.
- `make lint` ran `actionlint` without `shellcheck` and passed a workflow
  script that CI rejected. It now runs the `actionlint` image, which bundles
  `shellcheck`, and also checks `hack/*.sh`.

## [0.1.0-rc.1] - 2026-11-17

The first release candidate. Its release run failed at the verification
step, because of the stray release assets fixed in rc.2; use rc.2 or later.

### Added

- An Envoy `ext_proc` service for Substrate's additional egress `ext_proc`
  extension point. It decides each HTTP request by actor, method, host and
  path, and fails closed.
- `EgressRoutePolicy`, a cluster-scoped resource in API version `v1alpha1`:
  policies claim hosts for the actors they select and only ever allow;
  a host listed with no routes is a lockdown; `enforcementMode: Audit` records
  what would be denied without denying it.
- Path templates with literal segments, `*` and a trailing `**`, and optional
  ASCII case-insensitive matching.
- Strict path handling on claimed hosts: a path an upstream could read
  differently (encoded separators and dots, dot segments, empty segments,
  non-ASCII) is denied, never normalized.
- Mutual TLS 1.3 to the gateway, pinned to its SPIFFE ID, with certificate
  reload.
- A policy snapshot on every replica, readiness that waits for the first
  snapshot, a drain on shutdown, and a leader-only status writer that sets
  each policy's `Accepted` condition.
- Prometheus metrics `ategress_decisions_total`,
  `ategress_decision_duration_seconds`, `ategress_snapshot_generation` and
  `ategress_policies`, and a JSON decision log that never contains header
  values.
- A Helm chart.
- A release pipeline that signs the image and chart with cosign and attaches
  SLSA build provenance and an SBOM, and `hack/verify-release.sh` to check
  them.
- A single-organization GitHub example policy.

[Unreleased]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.4...v0.1.0
[0.1.0-rc.4]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.3...v0.1.0-rc.4
[0.1.0-rc.3]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.2...v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/ate-tooling/ate-gress/releases/tag/v0.1.0-rc.1
[#5]: https://github.com/ate-tooling/ate-gress/pull/5
[#6]: https://github.com/ate-tooling/ate-gress/pull/6
[#7]: https://github.com/ate-tooling/ate-gress/issues/7
[#8]: https://github.com/ate-tooling/ate-gress/pull/8
