# Changelog

All notable changes to ate-gress are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until 0.1.0 is released, every version is a release candidate and anything
may change between two of them. [docs/compatibility.md](docs/compatibility.md)
says what is promised after that. Entries marked **Operators** change what a
running installation does and need action or attention on upgrade.

## [Unreleased]

### Added

- Example policies for PyPI, the npm registry, `ghcr.io`, Amazon S3 and the
  Claude API, each with a test, and an index of them in
  [examples/README.md](examples/README.md).
- This changelog, [CONTRIBUTING.md](CONTRIBUTING.md),
  [docs/compatibility.md](docs/compatibility.md), and a proposed design for
  letting atespace owners write their own policies,
  [docs/adr/0001-policy-delegation.md](docs/adr/0001-policy-delegation.md).

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

[Unreleased]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.4...HEAD
[0.1.0-rc.4]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.3...v0.1.0-rc.4
[0.1.0-rc.3]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.2...v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/ate-tooling/ate-gress/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/ate-tooling/ate-gress/releases/tag/v0.1.0-rc.1
[#5]: https://github.com/ate-tooling/ate-gress/pull/5
[#6]: https://github.com/ate-tooling/ate-gress/pull/6
[#7]: https://github.com/ate-tooling/ate-gress/issues/7
[#8]: https://github.com/ate-tooling/ate-gress/pull/8
