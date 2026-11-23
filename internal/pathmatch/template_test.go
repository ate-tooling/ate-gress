package pathmatch

import (
	"strings"
	"testing"
)

func TestCompileRejects(t *testing.T) {
	for _, pattern := range []string{
		"",
		"repos/acme",
		"/repos//acme",
		"//",
		"/repos/acme//",
		"/repos//",
		"/repos/**/",
		"/**/",
		"/repos/../",
		"/repos/../acme",
		"/repos/./acme",
		"/repos/**/acme",
		"/**/**",
		"/repos/ac*",
		"/repos/***",
		"/repos/acme%2F",
		"/repos/acme%20x",
		"/repos/ac me",
		`/repos\acme`,
		"/repos/acme?x=1",
		"/repos/acme#x",
	} {
		t.Run(pattern, func(t *testing.T) {
			if tmpl, err := Compile(pattern, false); err == nil {
				t.Errorf("Compile(%q) = %v, want an error", pattern, tmpl)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern         string
		caseInsensitive bool
		match           []string
		noMatch         []string
	}{
		{
			pattern: "/",
			match:   []string{"/"},
			noMatch: []string{"/a"},
		},
		{
			pattern: "/orgs/acme",
			match:   []string{"/orgs/acme"},
			noMatch: []string{"/", "/orgs", "/orgs/acme/repos", "/orgs/acme-evil", "/orgs/acm", "/orgs/ACME", "/orgsx/acme"},
		},
		{
			pattern:         "/orgs/acme",
			caseInsensitive: true,
			match:           []string{"/orgs/acme", "/orgs/ACME", "/ORGS/AcMe"},
			noMatch:         []string{"/orgs/acme-evil", "/orgs/acme/repos"},
		},
		{
			pattern: "/repos/acme/*",
			match:   []string{"/repos/acme/widget", "/repos/acme/widget.git", "/repos/acme/a%20b"},
			noMatch: []string{"/repos/acme", "/repos/acme/widget/pulls", "/repos/other/widget", "/repos/acmeevil/widget"},
		},
		{
			pattern: "/repos/acme/*/**",
			match:   []string{"/repos/acme/widget/pulls", "/repos/acme/widget/contents/a/b/c"},
			noMatch: []string{"/repos/acme", "/repos/acme/widget", "/repos/other/widget/pulls"},
		},
		{
			pattern: "/repos/acme/**",
			match:   []string{"/repos/acme/widget", "/repos/acme/widget/pulls"},
			noMatch: []string{"/repos/acme", "/repos", "/repos/acme-evil/widget"},
		},
		{
			pattern: "/**",
			match:   []string{"/a", "/a/b/c"},
			noMatch: []string{"/"},
		},
		{
			pattern: "/v2/",
			match:   []string{"/v2/"},
			noMatch: []string{"/", "/v2", "/v2/x", "/v2/x/", "/v3/"},
		},
		{
			pattern:         "/V2/",
			caseInsensitive: true,
			match:           []string{"/v2/", "/V2/"},
			noMatch:         []string{"/v2"},
		},
		{
			pattern: "/v2/*/",
			match:   []string{"/v2/library/"},
			noMatch: []string{"/v2/", "/v2/library", "/v2/library/alpine/"},
		},
		{
			pattern: "/*/",
			match:   []string{"/v2/"},
			noMatch: []string{"/", "/v2"},
		},
		{
			// Wildcards never match the empty segment a trailing slash
			// leaves, so policies written before trailing slashes were
			// allowed allow nothing new.
			pattern: "/**",
			noMatch: []string{"/v2/", "/v2/library/alpine/"},
		},
		{
			pattern: "/v2/**",
			match:   []string{"/v2/library/alpine/manifests/3.22"},
			noMatch: []string{"/v2/", "/v2", "/v2/library/"},
		},
		{
			pattern: "/v2/*",
			match:   []string{"/v2/x"},
			noMatch: []string{"/v2/", "/v2/x/"},
		},
		{
			pattern: "/*/*/info/refs",
			match:   []string{"/acme/widget.git/info/refs", "/acme/widget/info/refs"},
			noMatch: []string{"/acme/info/refs", "/acme/widget/info/refs/x", "/acme/widget/info/ref"},
		},
	}
	for _, tt := range tests {
		tmpl, err := Compile(tt.pattern, tt.caseInsensitive)
		if err != nil {
			t.Fatalf("Compile(%q): %v", tt.pattern, err)
		}
		for _, p := range tt.match {
			if !tmpl.Match(mustCanonicalize(t, p)) {
				t.Errorf("%q (fold=%v) does not match %q, want a match", tt.pattern, tt.caseInsensitive, p)
			}
		}
		for _, p := range tt.noMatch {
			if tmpl.Match(mustCanonicalize(t, p)) {
				t.Errorf("%q (fold=%v) matches %q, want no match", tt.pattern, tt.caseInsensitive, p)
			}
		}
	}
}

func TestMatchDoesNotAllocate(t *testing.T) {
	tmpl, err := Compile("/repos/acme/*/**", true)
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if !tmpl.Match("/repos/ACME/widget/contents/docs/readme.md") {
			t.Fatal("no match")
		}
	})
	if allocs != 0 {
		t.Errorf("Match allocated %v times per call, want 0", allocs)
	}
}

// FuzzMatch checks that Match never panics on canonical input, that a
// template without wildcards matches only the path it spells, and that a
// template without a trailing slash never matches a path with one.
func FuzzMatch(f *testing.F) {
	f.Add("/repos/acme/*/**", "/repos/acme/widget/pulls", false)
	f.Add("/orgs/acme", "/orgs/ACME", true)
	f.Add("/", "/", false)
	f.Add("/v2/", "/v2/", false)
	f.Add("/**", "/v2/", false)
	f.Fuzz(func(t *testing.T, pattern, raw string, fold bool) {
		tmpl, err := Compile(pattern, fold)
		if err != nil {
			return
		}
		p, err := Canonicalize(raw)
		if err != nil {
			return
		}
		if !tmpl.Match(p) {
			return
		}
		if strings.HasSuffix(p, "/") != strings.HasSuffix(pattern, "/") {
			t.Fatalf("pattern %q matched %q: they disagree on a trailing slash", pattern, p)
		}
		if strings.Contains(pattern, "*") {
			return
		}
		if fold && !strings.EqualFold(p, pattern) || !fold && p != pattern {
			t.Fatalf("literal pattern %q (fold=%v) matched %q", pattern, fold, p)
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	tmpl, err := Compile("/repos/acme/*/**", true)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		tmpl.Match("/repos/ACME/widget/contents/docs/readme.md")
	}
}

func mustCanonicalize(t *testing.T, raw string) string {
	t.Helper()
	p, err := Canonicalize(raw)
	if err != nil {
		t.Fatalf("Canonicalize(%q): %v", raw, err)
	}
	return p
}
