package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
)

// loadExample reads the examples as v1alpha1, whatever apiVersion they name:
// that is how the API server hands them to ate-gress, and the versions have
// one schema.
func loadExample(t *testing.T, name string) []v1alpha1.EgressRoutePolicy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	var out []v1alpha1.EgressRoutePolicy
	for doc := range strings.SplitSeq(string(data), "\n---\n") {
		var p v1alpha1.EgressRoutePolicy
		if err := yaml.UnmarshalStrict([]byte(doc), &p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Kind == "" {
			continue // a comment-only document
		}
		out = append(out, p)
	}
	return out
}

func TestExamplesCompile(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	for _, m := range matches {
		t.Run(filepath.Base(m), func(t *testing.T) {
			mustCompile(t, loadExample(t, filepath.Base(m)))
		})
	}
}

func TestGitHubSingleOrgExample(t *testing.T) {
	s := mustCompile(t, loadExample(t, "github-single-org.yaml"))
	researcher := identity.Actor{Atespace: "research", Name: "agent"}
	outsider := identity.Actor{Atespace: "billing", Name: "agent"}
	tests := []struct {
		actor             identity.Actor
		method, host, uri string
		allowed           bool
	}{
		{researcher, "GET", "api.github.com", "/repos/acme/widget/pulls?state=open", true},
		{researcher, "GET", "api.github.com", "/orgs/Acme/repos", true},
		{researcher, "GET", "github.com", "/acme/widget.git/info/refs?service=git-upload-pack", true},
		{researcher, "POST", "github.com", "/acme/widget.git/git-upload-pack", true},
		{researcher, "GET", "codeload.github.com", "/acme/widget/tar.gz/refs/heads/main", true},
		{researcher, "GET", "raw.githubusercontent.com", "/acme/widget/main/README.md", true},
		{researcher, "GET", "pypi.org", "/simple/requests/", true},

		{researcher, "POST", "github.com", "/acme/widget.git/git-receive-pack", false},
		{researcher, "POST", "api.github.com", "/graphql", false},
		{researcher, "GET", "api.github.com", "/repos/other/widget", false},
		{researcher, "GET", "api.github.com", "/repositories/1", false},
		{researcher, "GET", "api.github.com", "/user/repos", false},
		{researcher, "PATCH", "api.github.com", "/repos/acme/widget", false},
		{researcher, "GET", "raw.githubusercontent.com", "/other/widget/main/README.md", false},
		{outsider, "GET", "api.github.com", "/repos/acme/widget", false},
	}
	for _, tt := range tests {
		d := s.Decide(Request{Actor: tt.actor, Method: tt.method, Authority: tt.host, Path: tt.uri})
		if d.Allowed != tt.allowed {
			t.Errorf("%v %s %s%s: allowed = %v (%+v), want %v", tt.actor, tt.method, tt.host, tt.uri, d.Allowed, d, tt.allowed)
		}
	}
}
