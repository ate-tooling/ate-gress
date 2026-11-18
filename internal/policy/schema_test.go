package policy

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ate-tooling/ate-gress/internal/pathmatch"
)

// crdPathPattern returns the pattern the generated CRD validates route paths
// with.
func crdPathPattern(t testing.TB) *regexp.Regexp {
	t.Helper()
	crd, err := os.ReadFile("../../config/crd/ategress.ate-tooling.github.io_egressroutepolicies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(crd), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "pattern: ^(/"); ok {
			return regexp.MustCompile("^(/" + p)
		}
	}
	t.Fatal("no path pattern in the CRD")
	return nil
}

// FuzzSchemaAgreesWithCompiler checks that the CRD admits exactly the path
// templates pathmatch.Compile accepts. If the schema admitted more, a policy
// would be stored that every replica rejects; if less, a valid one could not
// be written.
func FuzzSchemaAgreesWithCompiler(f *testing.F) {
	for _, s := range []string{
		"/", "/repos/acme/*/**", "/a/*/b", "/**", "/...", "/a.b", "/.a", "/a.",
		"//", "/a/", "/./a", "/../a", "/a/**/b", "/a*", "/*a", "/***", "/a%2F", "/a b", `/a\b`, "/a?b", "",
	} {
		f.Add(s)
	}
	re := crdPathPattern(f)
	f.Fuzz(func(t *testing.T, pattern string) {
		if len(pattern) > 1024 {
			return
		}
		_, err := pathmatch.Compile(pattern, false)
		if schemaOK, compileOK := re.MatchString(pattern), err == nil; schemaOK != compileOK {
			t.Fatalf("pattern %q: schema admits = %v, compiler accepts = %v (%v)", pattern, schemaOK, compileOK, err)
		}
	})
}
