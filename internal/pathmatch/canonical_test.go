package pathmatch

import (
	"errors"
	"net/url"
	"path"
	"strings"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{name: "root", raw: "/", want: "/"},
		{name: "simple", raw: "/repos/acme/widget", want: "/repos/acme/widget"},
		{name: "query stripped", raw: "/repos/acme/widget?per_page=100", want: "/repos/acme/widget"},
		{name: "query smuggling a path", raw: "/search?q=/repos/acme/", want: "/search"},
		{name: "empty query", raw: "/orgs/acme?", want: "/orgs/acme"},
		{name: "sub-delims and colon", raw: "/a:b@c/!$&'()*+,;=", want: "/a:b@c/!$&'()*+,;="},
		{name: "dot inside segment", raw: "/acme/widget.git/info/refs", want: "/acme/widget.git/info/refs"},
		{name: "benign escape", raw: "/contents/My%20File", want: "/contents/My%20File"},
		{name: "lowercase hex escape", raw: "/a%c3%a9", want: "/a%c3%a9"},
		{name: "trailing slash", raw: "/v2/", want: "/v2/"},
		{name: "trailing slash before query", raw: "/orgs/acme/?x=1", want: "/orgs/acme/"},

		{name: "empty", raw: "", wantErr: ErrNotAbsolute},
		{name: "relative", raw: "repos/acme", wantErr: ErrNotAbsolute},
		{name: "asterisk form", raw: "*", wantErr: ErrNotAbsolute},
		{name: "absolute form", raw: "https://api.github.com/repos/acme", wantErr: ErrNotAbsolute},
		{name: "only query", raw: "?/repos/acme", wantErr: ErrNotAbsolute},

		{name: "double slash", raw: "/repos//acme", wantErr: ErrEmptySegment},
		{name: "leading double slash", raw: "//evil.example/repos", wantErr: ErrEmptySegment},
		{name: "double trailing slash", raw: "/orgs/acme//", wantErr: ErrEmptySegment},
		{name: "only slashes", raw: "//", wantErr: ErrEmptySegment},
		{name: "empty segment before trailing slash", raw: "/a//b/", wantErr: ErrEmptySegment},
		{name: "trailing slash after dot-dot", raw: "/repos/acme/../", wantErr: ErrDotSegment},

		{name: "dot segment", raw: "/repos/./acme", wantErr: ErrDotSegment},
		{name: "dot-dot segment", raw: "/repos/acme/../evil", wantErr: ErrDotSegment},
		{name: "trailing dot-dot", raw: "/repos/acme/..", wantErr: ErrDotSegment},
		// Java servlet containers strip ;path-parameters before resolving dot
		// segments, so these are ".." and "." upstream.
		{name: "dot-dot with path parameter", raw: "/public/..;/admin", wantErr: ErrDotSegment},
		{name: "dot-dot with named path parameter", raw: "/public/..;x=1/admin", wantErr: ErrDotSegment},
		{name: "dot with path parameter", raw: "/public/.;x/admin", wantErr: ErrDotSegment},
		{name: "empty segment with path parameter", raw: "/public/;x/admin", wantErr: ErrEmptySegment},
		{name: "encoded semicolon", raw: "/public/..%3B/admin", wantErr: ErrForbiddenEscape},
		{name: "encoded semicolon lowercase", raw: "/public/a%3bb", wantErr: ErrForbiddenEscape},

		{name: "backslash", raw: `/repos/acme\..\evil`, wantErr: ErrInvalidByte},
		{name: "space", raw: "/repos/ac me", wantErr: ErrInvalidByte},
		{name: "fragment", raw: "/repos/acme#x", wantErr: ErrInvalidByte},
		{name: "NUL", raw: "/repos/acme\x00/evil", wantErr: ErrInvalidByte},
		{name: "tab", raw: "/repos/acme\t", wantErr: ErrInvalidByte},
		{name: "DEL", raw: "/repos/acme\x7f", wantErr: ErrInvalidByte},
		{name: "raw non-ASCII", raw: "/repos/acmé", wantErr: ErrInvalidByte},
		{name: "kelvin sign", raw: "/repos/Kcme", wantErr: ErrInvalidByte},

		{name: "truncated escape", raw: "/repos/acme%2", wantErr: ErrMalformedEscape},
		{name: "bare percent", raw: "/repos/acme%", wantErr: ErrMalformedEscape},
		{name: "non-hex escape", raw: "/repos/acme%zz", wantErr: ErrMalformedEscape},
		{name: "escape split by slash", raw: "/repos/acme%2/F", wantErr: ErrMalformedEscape},

		{name: "encoded slash", raw: "/repos/acme%2Fevil", wantErr: ErrForbiddenEscape},
		{name: "encoded slash lowercase", raw: "/repos/acme%2fevil", wantErr: ErrForbiddenEscape},
		{name: "encoded backslash", raw: "/repos/acme%5Cevil", wantErr: ErrForbiddenEscape},
		{name: "encoded dot-dot", raw: "/repos/acme/%2e%2e/evil", wantErr: ErrForbiddenEscape},
		{name: "half-encoded dot-dot", raw: "/repos/acme/.%2E/evil", wantErr: ErrForbiddenEscape},
		{name: "double-encoded slash", raw: "/repos/acme%252Fevil", wantErr: ErrForbiddenEscape},
		{name: "encoded NUL", raw: "/repos/acme%00", wantErr: ErrForbiddenEscape},
		{name: "encoded newline", raw: "/repos/acme%0A", wantErr: ErrForbiddenEscape},
		{name: "encoded DEL", raw: "/repos/acme%7F", wantErr: ErrForbiddenEscape},
		{name: "traversal after benign escape", raw: "/repos/acme%20/..%2Fevil", wantErr: ErrForbiddenEscape},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.raw)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Canonicalize(%q) error = %v, want %v", tt.raw, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeDoesNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := Canonicalize("/repos/acme/widget/contents/docs/My%20File.md?ref=main"); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("Canonicalize allocated %v times per call, want 0", allocs)
	}
}

// FuzzCanonicalize checks the property Canonicalize exists to provide: an
// accepted path reads the same whether or not an upstream percent-decodes and
// cleans it before routing. The one difference allowed is that cleaning drops
// a single trailing slash.
func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{
		"/", "/repos/acme/widget", "/repos/acme/widget?x=1", "/a%20b", "//x", "/a/../b",
		"/a%2Fb", "/a%2e%2e", "/a%252F", `/a\b`, "/a/b/", "/a/b//", "/a/../", "/%", "/%c3%a9", "/a;b=c/d",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := Canonicalize(raw)
		if err != nil {
			if got != "" {
				t.Fatalf("Canonicalize(%q) returned %q with error %v", raw, got, err)
			}
			return
		}
		if !strings.HasPrefix(raw, got) {
			t.Fatalf("Canonicalize(%q) = %q, not a prefix of the input", raw, got)
		}
		if again, err := Canonicalize(got); err != nil || again != got {
			t.Fatalf("Canonicalize is not idempotent on %q: got %q, %v", got, again, err)
		}
		if strings.ContainsAny(got, "?#\\") {
			t.Fatalf("Canonicalize(%q) = %q, contains a query, fragment, or backslash", raw, got)
		}

		decoded, err := url.PathUnescape(got)
		if err != nil {
			t.Fatalf("accepted path %q does not unescape: %v", got, err)
		}
		if strings.Count(decoded, "/") != strings.Count(got, "/") {
			t.Fatalf("decoding %q to %q changed the segment count", got, decoded)
		}
		want := decoded
		if decoded != "/" {
			want = strings.TrimSuffix(decoded, "/")
		}
		if path.Clean(decoded) != want {
			t.Fatalf("decoded path %q changes under path.Clean, beyond a trailing slash: %q", decoded, path.Clean(decoded))
		}
		if twice, err := url.PathUnescape(decoded); err == nil && strings.Count(twice, "/") != strings.Count(got, "/") {
			t.Fatalf("double-decoding %q to %q changed the segment count", got, twice)
		}
	})
}

func BenchmarkCanonicalize(b *testing.B) {
	const raw = "/repos/acme/widget/contents/docs/My%20File.md?ref=main"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Canonicalize(raw); err != nil {
			b.Fatal(err)
		}
	}
}
