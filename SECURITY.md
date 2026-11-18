# Security policy

ate-gress sits on the egress path of every agent. Please report
vulnerabilities privately, through
[GitHub security advisories](https://github.com/ate-tooling/ate-gress/security/advisories/new),
not in a public issue.

Include the version, the policy and request that show the problem, and what
you expected. Bypasses of a route policy, such as a path that matches a route
but reaches a different upstream resource, are in scope. See
[the threat model](docs/threat-model.md) for what ate-gress does and does not
defend against.

Only the latest release receives fixes. To verify that a release came from
this repository's release workflow, see
[docs/releasing.md](docs/releasing.md#verifying-a-release).
