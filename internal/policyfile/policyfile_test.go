package policyfile

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func names(s *Set) []string {
	out := make([]string, len(s.Documents))
	for i := range s.Documents {
		out[i] = s.Documents[i].Name()
	}
	return out
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const lockdown = "hosts:\n- host: api.github.com"

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	multi := write(t, dir, "multi.yaml", "# a comment-only document\n---\n"+manifest("a", lockdown)+"---\n"+manifest("b", lockdown)+"---\n")
	asJSON := write(t, dir, "c.json", `{"apiVersion":"ategress.ate-tooling.github.io/v1alpha1","kind":"EgressRoutePolicy","metadata":{"name":"c"},"spec":{"hosts":[{"host":"api.github.com"}]}}`)
	// What `kubectl get egressroutepolicies -o yaml` prints.
	list := write(t, dir, "list.yaml", "apiVersion: v1\nkind: List\nitems:\n- "+strings.ReplaceAll(manifest("d", lockdown), "\n", "\n  ")+
		"\n- "+strings.ReplaceAll(manifest("e", lockdown), "\n", "\n  ")+"\n")

	set, err := Load([]string{multi, asJSON, list, "-"}, strings.NewReader(manifest("f", lockdown)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := names(set), []string{"a", "b", "c", "d", "e", "f"}; !slices.Equal(got, want) {
		t.Errorf("policies = %v, want %v", got, want)
	}
	if !set.Valid() {
		t.Errorf("a valid set is reported invalid: %+v", set.Documents)
	}
	if got := set.Documents[1].Source(); got != multi+"#3" {
		t.Errorf("Source() = %q, want the file and document index", got)
	}
	if got := set.Policies()[0].Spec.Hosts[0].Host; got != "api.github.com" {
		t.Errorf("decoded host = %q", got)
	}
}

func TestLoadDirectory(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", manifest("a", lockdown))
	write(t, dir, "nested/b.yml", manifest("b", lockdown))
	// Things a policy directory holds that are not policies.
	write(t, dir, "a.tests.yaml", "policies: [a.yaml]\ntests: []\n")
	write(t, dir, "namespace.yaml", "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n")
	write(t, dir, "values.yaml", "- just\n- a list\n")
	write(t, dir, "README.md", "not YAML: [")
	write(t, dir, ".git/c.yaml", manifest("hidden", lockdown))

	set, err := Load([]string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := names(set), []string{"a", "b"}; !slices.Equal(got, want) {
		t.Errorf("policies = %v, want %v", got, want)
	}
	if set.Skipped != 3 {
		t.Errorf("Skipped = %d, want the test file, the Namespace and the list", set.Skipped)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		files   map[string]string
		paths   []string
		wantErr string
	}{
		{name: "no paths", wantErr: "no policy files"},
		{name: "missing file", paths: []string{"absent.yaml"}, wantErr: "no such file"},
		{name: "malformed YAML", files: map[string]string{"bad.yaml": "spec: [\n"}, paths: []string{"bad.yaml"}, wantErr: "document 1"},
		{name: "duplicate key", files: map[string]string{"dupkey.yaml": manifest("a", lockdown) + "kind: Other\n"}, paths: []string{"dupkey.yaml"}, wantErr: "already set"},
		{name: "another kind in a named file", files: map[string]string{"ns.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n"},
			paths: []string{"ns.yaml"}, wantErr: "is not an EgressRoutePolicy"},
		{name: "empty file", files: map[string]string{"empty.yaml": "# nothing\n"}, paths: []string{"empty.yaml"}, wantErr: "no EgressRoutePolicy found"},
		{name: "directory without policies", files: map[string]string{"none/ns.yaml": "apiVersion: v1\nkind: Namespace\n"}, paths: []string{"none"}, wantErr: "no EgressRoutePolicy found"},
		// Skipping these in a directory would hide a typo, so they are
		// errors there too.
		{name: "mistyped kind in a directory", files: map[string]string{"kind/a.yaml": strings.Replace(manifest("a", lockdown), "kind: EgressRoutePolicy", "kind: EgressRoutePolicies", 1)},
			paths: []string{"kind"}, wantErr: `kind "EgressRoutePolicies"`},
		{name: "unknown version in a directory", files: map[string]string{"version/a.yaml": strings.Replace(manifest("a", lockdown), "v1alpha1", "v9", 1)},
			paths: []string{"version"}, wantErr: "not a version ategressctl knows"},
		{name: "one name twice", files: map[string]string{"twice/a.yaml": manifest("a", lockdown), "twice/b.yaml": manifest("a", lockdown)},
			paths: []string{"twice"}, wantErr: `policy "a" is defined in both`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for name, content := range tt.files {
				write(t, dir, name, content)
			}
			paths := make([]string, len(tt.paths))
			for i, p := range tt.paths {
				paths[i] = filepath.Join(dir, p)
			}
			_, err := Load(paths, nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestInvalid checks what is reported for a policy the API server would
// reject: the field, and whether it is a duplicate.
func TestInvalid(t *testing.T) {
	doc := manifest("p", `
enforcmentMode: Audit
actorSelector: {atespaces: [a, a]}
hosts:
- host: API.github.com
  routes:
  - methods: [GET, get]
    paths: [/a, /a/**/b]
`)
	set, err := Load([]string{"-"}, strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if set.Valid() {
		t.Fatal("Valid() = true")
	}
	type key struct {
		field     string
		duplicate bool
	}
	var got []key
	for _, e := range set.Documents[0].Invalid {
		got = append(got, key{e.Field, e.Duplicate})
		if e.Message == "" || strings.HasPrefix(e.Message, e.Field) {
			t.Errorf("message %q of %s should say what is wrong without repeating the field", e.Message, e.Field)
		}
	}
	want := []key{
		{"spec.actorSelector.atespaces[1]", true},
		{"spec.enforcmentMode", false},
		{"spec.hosts[0].host", false},
		{"spec.hosts[0].routes[0].methods[1]", false},
		{"spec.hosts[0].routes[0].paths[1]", false},
	}
	if !slices.Equal(got, want) {
		t.Errorf("invalid fields = %v, want %v", got, want)
	}
}

// TestExamples checks that every shipped example is one the API server would
// admit.
func TestExamples(t *testing.T) {
	set, err := Load([]string{filepath.Join("..", "..", "examples")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range set.Documents {
		if len(d.Invalid) > 0 {
			t.Errorf("%s: %s: %v", d.Source(), d.Name(), d.Invalid)
		}
	}
}
