# Example policies

Each file is a complete set of `EgressRoutePolicy` objects for one upstream.
Its header says what the policies allow, where the request shapes were
checked, and what the policies cannot do. Read the header before you apply
one: several of these upstreams cannot be fully restricted by method and
path.

The names in them (`acme`, `acme-data`, the `research`, `build`, `ingest` and
`agents` atespaces) are placeholders.

| File | Allows | Main caveat |
|---|---|---|
| [`github-single-org.yaml`](github-single-org.yaml) | One atespace reads one GitHub organization: REST API, clone and fetch, archives, raw content. Everyone else is locked out of GitHub | `POST /graphql` and endpoints that name no organization are denied, because they cannot be checked |
| [`pypi-readonly.yaml`](pypi-readonly.yaml) | Every actor reads the PyPI Simple index and downloads files | Cannot limit which packages: a file's path does not carry the project name as a segment |
| [`npm-readonly.yaml`](npm-readonly.yaml) | Every actor reads package documents and tarballs of unscoped packages | Scoped packages (`@scope/name`) cannot be installed: the npm CLI percent-encodes the slash, which ate-gress refuses |
| [`oci-ghcr-pull.yaml`](oci-ghcr-pull.yaml) | One atespace pulls images from one `ghcr.io` namespace. Everyone else is locked out of `ghcr.io` | The token scope is in the query and is not checked; blobs are served from a second, undocumented host; one template set per repository depth |
| [`s3-single-bucket.yaml`](s3-single-bucket.yaml) | One atespace reads one S3 bucket, another also writes and deletes objects; nobody changes the bucket | Other buckets are other hostnames and cannot be claimed; S3 tells operations apart by query string, so a route allows every operation with its method and path |
| [`anthropic-messages.yaml`](anthropic-messages.yaml) | One atespace calls the Claude Messages, token counting and Models endpoints. Everyone else is locked out of `api.anthropic.com` | The model, the tools and the prompt are in the body, which ate-gress never sees |

## What every example assumes

- **The actors' Substrate `EgressPolicy` allows the hosts with `https`
  rules.** ate-gress only narrows what the `EgressPolicy` already allows, and
  it never sees a host on a `tls_passthrough` rule.
- **The credential's own scope is the real boundary.** A route policy is
  defense in depth on top of a token, key or IAM policy that is scoped to
  the same thing.

## What the policy grammar cannot express

The same limits come up in most of the headers. They are properties of
ate-gress, not of the examples:

- **Hosts are exact.** There is no host wildcard. An upstream that puts the
  tenant in the hostname (S3 buckets), or serves downloads from many
  hostnames, cannot be claimed as a family. An unclaimed host is left to the
  `EgressPolicy`.
- **`*` is one whole segment, and `**` is one or more trailing segments.**
  There is no partial-segment wildcard (`requests-*.whl`) and no `**` in the
  middle of a template.
- **A trailing slash is matched only by a template that spells it.**
- **The query string is not matched.** Operations an upstream tells apart by
  query parameter share a route.
- **Headers and bodies are not seen.** Neither is the response.
- **A redirect to another host is a new request to that host.** It needs its
  own entry, and its own `EgressPolicy` rule.
- **Some paths are always refused on a claimed host**, whatever the routes:
  an encoded `/`, `\`, `.` or `%`, a `.` or `..` segment, an empty segment
  other than one trailing slash, and non-ASCII bytes. A client that sends
  such paths cannot be used through a claimed host. See
  [the threat model](../docs/threat-model.md).

## Tests

Every example is compiled by `TestExamplesCompile`, and each has a test in
[`internal/policy`](../internal/policy) with requests it must allow and
requests it must deny, including the over-broad cases its header admits to.
Each also has a `.tests.yaml` file next to it with the same cases, which
[`ategressctl test`](../docs/ategressctl.md#test) runs, and which you can
copy as a start for your own:

```sh
ategressctl test examples/*.tests.yaml
```

Add all three when you add an example, and say in the header where you
checked the upstream's request shapes.

The request shapes were checked against the upstreams' documentation, and
where the header says so against the live service, on the date it gives.
Upstreams change. The examples are not run against the real services in CI.
