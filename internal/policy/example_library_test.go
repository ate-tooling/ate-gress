package policy

import (
	"testing"

	"github.com/ate-tooling/ate-gress/internal/identity"
)

// exampleCase is one request an example must allow or deny. A deny says why:
// the examples' comments tell the reader which reason to expect.
type exampleCase struct {
	actor             identity.Actor
	method, host, uri string
	// want is ReasonRoute or ReasonUnclaimed for a request that must be
	// allowed, and a deny reason for one that must not.
	want Reason
}

func checkExample(t *testing.T, file string, cases []exampleCase) {
	t.Helper()
	s := mustCompile(t, loadExample(t, file))
	for _, c := range cases {
		d := s.Decide(Request{Actor: c.actor, Method: c.method, Authority: c.host, Path: c.uri})
		if d.Audited {
			t.Errorf("%v %s %s%s: audited; the examples enforce", c.actor, c.method, c.host, c.uri)
		}
		wantAllowed := c.want == ReasonRoute || c.want == ReasonUnclaimed
		if d.Allowed != wantAllowed || d.Reason != c.want {
			t.Errorf("%v %s %s%s: allowed = %v, reason = %q (%+v), want reason %q",
				c.actor, c.method, c.host, c.uri, d.Allowed, d.Reason, d, c.want)
		}
	}
}

func TestPyPIReadOnlyExample(t *testing.T) {
	anyone := identity.Actor{Atespace: "research", Name: "agent"}
	const (
		index = "pypi.org"
		files = "files.pythonhosted.org"
		wheel = "/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl"
	)
	checkExample(t, "pypi-readonly.yaml", []exampleCase{
		{anyone, "GET", index, "/simple/", ReasonRoute},
		{anyone, "GET", index, "/simple/idna/", ReasonRoute},
		{anyone, "HEAD", index, "/simple/flask-sqlalchemy/", ReasonRoute},
		{anyone, "GET", files, wheel, ReasonRoute},
		{anyone, "GET", files, wheel + ".metadata", ReasonRoute},
		{anyone, "HEAD", files, wheel, ReasonRoute},
		// Another index is another host, which this example does not claim.
		{anyone, "GET", "test.pypi.org", "/simple/idna/", ReasonUnclaimed},

		{anyone, "GET", index, "/simple/idna", ReasonNoRoute},
		{anyone, "GET", index, "/simple/idna/extra/", ReasonNoRoute},
		{anyone, "POST", index, "/simple/idna/", ReasonNoRoute},
		{anyone, "GET", index, "/pypi/idna/json", ReasonNoRoute},
		{anyone, "POST", index, "/pypi", ReasonNoRoute},
		{anyone, "GET", index, "/account/login/", ReasonNoRoute},
		{anyone, "GET", index, "/simple/../account/login/", ReasonPath},
		{anyone, "GET", files, "/", ReasonNoRoute},
		{anyone, "PUT", files, wheel, ReasonNoRoute},
		{anyone, "POST", "upload.pypi.org", "/legacy/", ReasonNoRoute},
		{anyone, "GET", "upload.pypi.org", "/legacy/", ReasonNoRoute},
	})
}

func TestNPMReadOnlyExample(t *testing.T) {
	anyone := identity.Actor{Atespace: "research", Name: "agent"}
	const registry = "registry.npmjs.org"
	checkExample(t, "npm-readonly.yaml", []exampleCase{
		{anyone, "GET", registry, "/left-pad", ReasonRoute},
		{anyone, "HEAD", registry, "/left-pad", ReasonRoute},
		{anyone, "GET", registry, "/left-pad/-/left-pad-1.3.0.tgz", ReasonRoute},
		{anyone, "GET", registry, "/@babel/core/-/core-8.1.3.tgz", ReasonRoute},

		// What the npm CLI sends for a scoped package. No template can
		// allow it.
		{anyone, "GET", registry, "/@babel%2fcore", ReasonPath},
		{anyone, "GET", registry, "/@babel%2Fcore", ReasonPath},
		{anyone, "GET", registry, "/@babel/core", ReasonNoRoute},
		{anyone, "GET", registry, "/left-pad/latest", ReasonNoRoute},
		{anyone, "PUT", registry, "/left-pad", ReasonNoRoute},
		{anyone, "DELETE", registry, "/left-pad/-rev/1-abc", ReasonNoRoute},
		{anyone, "DELETE", registry, "/left-pad/-/left-pad-1.3.0.tgz", ReasonNoRoute},
		{anyone, "PUT", registry, "/-/user/org.couchdb.user:mallory", ReasonNoRoute},
		{anyone, "POST", registry, "/-/npm/v1/security/advisories/bulk", ReasonNoRoute},
		{anyone, "GET", registry, "/-/whoami", ReasonNoRoute},
		{anyone, "GET", registry, "/-/v1/search?text=left-pad", ReasonNoRoute},
		{anyone, "GET", registry, "/-/npm/v1/tokens", ReasonNoRoute},
		{anyone, "GET", registry, "/", ReasonNoRoute},
	})
}

func TestGHCRPullExample(t *testing.T) {
	builder := identity.Actor{Atespace: "build", Name: "agent"}
	outsider := identity.Actor{Atespace: "research", Name: "agent"}
	const (
		registry = "ghcr.io"
		blobs    = "pkg-containers.githubusercontent.com"
		digest   = "sha256:a0103553329c8a010ed68a1143bf9126b0f1977fec308953e9068a9722790d9d"
	)
	checkExample(t, "oci-ghcr-pull.yaml", []exampleCase{
		{builder, "GET", registry, "/v2/", ReasonRoute},
		{builder, "GET", registry, "/token?service=ghcr.io&scope=repository:acme/app:pull", ReasonRoute},
		{builder, "GET", registry, "/v2/acme/app/manifests/v1.2.3", ReasonRoute},
		{builder, "HEAD", registry, "/v2/acme/app/manifests/" + digest, ReasonRoute},
		{builder, "GET", registry, "/v2/acme/app/blobs/" + digest, ReasonRoute},
		{builder, "GET", registry, "/v2/acme/app/tags/list?n=100", ReasonRoute},
		{builder, "GET", registry, "/v2/acme/app/referrers/" + digest, ReasonRoute},
		{builder, "GET", blobs, "/ghcr1/blobs/" + digest + "?se=2026-11-23T12%3A00%3A00Z&sig=abc", ReasonRoute},
		// The token scope is in the query, which is not matched: a token
		// for another repository, or to push, is still handed out.
		{builder, "GET", registry, "/token?service=ghcr.io&scope=repository:other/app:pull,push", ReasonRoute},
		// Only the build policy claims the blob host.
		{outsider, "GET", blobs, "/ghcr1/blobs/" + digest, ReasonUnclaimed},

		{builder, "GET", registry, "/v2", ReasonNoRoute},
		{builder, "GET", registry, "/v2/_catalog", ReasonNoRoute},
		{builder, "GET", registry, "/v2/other/app/manifests/v1.2.3", ReasonNoRoute},
		{builder, "GET", registry, "/v2/other/app/blobs/" + digest, ReasonNoRoute},
		{builder, "GET", registry, "/v2/acme-evil/app/manifests/v1.2.3", ReasonNoRoute},
		{builder, "GET", registry, "/v2/ACME/app/manifests/v1.2.3", ReasonNoRoute},
		// A deeper repository name needs its own templates.
		{builder, "GET", registry, "/v2/acme/team/app/manifests/v1.2.3", ReasonNoRoute},
		{builder, "GET", registry, "/v2/acme/app/../../other/app/manifests/v1.2.3", ReasonPath},
		{builder, "GET", registry, "/v2/acme%2f..%2fother/app/manifests/v1.2.3", ReasonPath},
		{builder, "POST", registry, "/v2/acme/app/blobs/uploads/", ReasonNoRoute},
		{builder, "POST", registry, "/v2/acme/app/blobs/uploads/?mount=" + digest + "&from=other/app", ReasonNoRoute},
		{builder, "PUT", registry, "/v2/acme/app/manifests/v1.2.3", ReasonNoRoute},
		{builder, "PATCH", registry, "/v2/acme/app/blobs/uploads/4f2b", ReasonNoRoute},
		{builder, "DELETE", registry, "/v2/acme/app/manifests/" + digest, ReasonNoRoute},
		{builder, "POST", registry, "/token", ReasonNoRoute},
		{builder, "GET", blobs, "/ghcr1/blobs/" + digest + "/extra", ReasonNoRoute},
		{builder, "PUT", blobs, "/ghcr1/blobs/" + digest, ReasonNoRoute},
		{outsider, "GET", registry, "/v2/", ReasonNoRoute},
		{outsider, "GET", registry, "/token?service=ghcr.io", ReasonNoRoute},
		{outsider, "GET", registry, "/v2/acme/app/manifests/v1.2.3", ReasonNoRoute},
	})
}

func TestS3SingleBucketExample(t *testing.T) {
	reader := identity.Actor{Atespace: "research", Name: "agent"}
	writer := identity.Actor{Atespace: "ingest", Name: "agent"}
	outsider := identity.Actor{Atespace: "billing", Name: "agent"}
	const (
		bucket    = "acme-data.s3.us-east-1.amazonaws.com"
		legacy    = "acme-data.s3.amazonaws.com"
		pathStyle = "s3.us-east-1.amazonaws.com"
	)
	checkExample(t, "s3-single-bucket.yaml", []exampleCase{
		{reader, "GET", bucket, "/?list-type=2&prefix=reports/", ReasonRoute},
		{reader, "HEAD", bucket, "/", ReasonRoute},
		{reader, "GET", bucket, "/reports/2026/q3.parquet", ReasonRoute},
		{reader, "HEAD", bucket, "/reports/2026/q3.parquet", ReasonRoute},
		{reader, "GET", bucket, "/caf%C3%A9/menu%20du%20jour.txt", ReasonRoute},
		// Reads the query string tells apart, and so the route does not.
		{reader, "GET", bucket, "/?policy", ReasonRoute},
		{reader, "GET", bucket, "/reports/2026/q3.parquet?acl", ReasonRoute},

		{writer, "GET", bucket, "/?list-type=2", ReasonRoute},
		{writer, "PUT", bucket, "/incoming/batch-1.csv", ReasonRoute},
		{writer, "DELETE", bucket, "/incoming/batch-1.csv", ReasonRoute},
		{writer, "POST", bucket, "/incoming/large.bin?uploads", ReasonRoute},
		{writer, "PUT", bucket, "/incoming/large.bin?partNumber=1&uploadId=abc", ReasonRoute},
		{writer, "POST", bucket, "/incoming/large.bin?uploadId=abc", ReasonRoute},
		// Writes the query string tells apart, and so the route does not.
		{writer, "PUT", bucket, "/incoming/batch-1.csv?acl", ReasonRoute},

		// Another bucket is another host. This example cannot claim it.
		{reader, "GET", "other-bucket.s3.us-east-1.amazonaws.com", "/secret.txt", ReasonUnclaimed},
		{reader, "GET", "acme-data.s3.dualstack.us-east-1.amazonaws.com", "/reports/2026/q3.parquet", ReasonUnclaimed},

		{reader, "PUT", bucket, "/reports/2026/q3.parquet", ReasonNoRoute},
		{reader, "DELETE", bucket, "/reports/2026/q3.parquet", ReasonNoRoute},
		{reader, "POST", bucket, "/?delete", ReasonNoRoute},
		{reader, "GET", legacy, "/reports/2026/q3.parquet", ReasonNoRoute},
		{reader, "GET", pathStyle, "/acme-data/reports/2026/q3.parquet", ReasonNoRoute},
		{reader, "GET", pathStyle, "/other-bucket/secret.txt", ReasonNoRoute},
		{reader, "GET", "s3.amazonaws.com", "/other-bucket/secret.txt", ReasonNoRoute},

		// Bucket-level writes are all on "/".
		{writer, "PUT", bucket, "/?policy", ReasonNoRoute},
		{writer, "PUT", bucket, "/?acl", ReasonNoRoute},
		{writer, "PUT", bucket, "/", ReasonNoRoute},
		{writer, "DELETE", bucket, "/", ReasonNoRoute},
		{writer, "DELETE", bucket, "/?policy", ReasonNoRoute},
		{writer, "POST", bucket, "/?delete", ReasonNoRoute},
		{writer, "PUT", pathStyle, "/acme-data/incoming/batch-1.csv", ReasonNoRoute},

		// Keys no route can allow, and keys /** does not reach.
		{reader, "GET", bucket, "/a//b", ReasonPath},
		{reader, "GET", bucket, "/a/../b", ReasonPath},
		{reader, "GET", bucket, "/100%25.txt", ReasonPath},
		{reader, "GET", bucket, "/a%5Cb", ReasonPath},
		{reader, "GET", bucket, "/folder/", ReasonNoRoute},
		{writer, "PUT", bucket, "/folder/", ReasonNoRoute},

		{outsider, "GET", bucket, "/reports/2026/q3.parquet", ReasonNoRoute},
		{outsider, "GET", bucket, "/", ReasonNoRoute},
	})
}

func TestAnthropicMessagesExample(t *testing.T) {
	agent := identity.Actor{Atespace: "agents", Name: "agent"}
	outsider := identity.Actor{Atespace: "research", Name: "agent"}
	const api = "api.anthropic.com"
	checkExample(t, "anthropic-messages.yaml", []exampleCase{
		{agent, "POST", api, "/v1/messages", ReasonRoute},
		{agent, "POST", api, "/v1/messages?beta=true", ReasonRoute},
		{agent, "POST", api, "/v1/messages/count_tokens", ReasonRoute},
		{agent, "GET", api, "/v1/models", ReasonRoute},
		{agent, "GET", api, "/v1/models?limit=100", ReasonRoute},
		{agent, "GET", api, "/v1/models/claude-opus-5-5", ReasonRoute},

		{agent, "GET", api, "/v1/messages", ReasonNoRoute},
		{agent, "POST", api, "/v1/messages/", ReasonNoRoute},
		{agent, "POST", api, "/V1/messages", ReasonNoRoute},
		{agent, "POST", api, "/v1/messages/batches", ReasonNoRoute},
		{agent, "GET", api, "/v1/messages/batches", ReasonNoRoute},
		{agent, "GET", api, "/v1/messages/batches/msgbatch_01/results", ReasonNoRoute},
		{agent, "POST", api, "/v1/files", ReasonNoRoute},
		{agent, "GET", api, "/v1/files", ReasonNoRoute},
		{agent, "GET", api, "/v1/files/file_01/content", ReasonNoRoute},
		{agent, "POST", api, "/v1/skills", ReasonNoRoute},
		{agent, "POST", api, "/v1/agents", ReasonNoRoute},
		{agent, "POST", api, "/v1/sessions", ReasonNoRoute},
		{agent, "GET", api, "/v1/sessions/sesn_01/events/stream", ReasonNoRoute},
		{agent, "POST", api, "/v1/environments", ReasonNoRoute},
		{agent, "GET", api, "/v1/organizations/users", ReasonNoRoute},
		{agent, "POST", api, "/v1/oauth/token", ReasonNoRoute},
		{agent, "POST", api, "/v1/models", ReasonNoRoute},
		{agent, "DELETE", api, "/v1/models/claude-opus-5-5", ReasonNoRoute},
		{agent, "POST", api, "/v1/messages/../files", ReasonPath},
		{outsider, "POST", api, "/v1/messages", ReasonNoRoute},
		{outsider, "GET", api, "/v1/models", ReasonNoRoute},
	})
}
