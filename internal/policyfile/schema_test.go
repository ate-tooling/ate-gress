package policyfile

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	"github.com/ate-tooling/ate-gress/config/crd"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// apiServer is a client for an envtest API server with the CRD installed, or
// nil when KUBEBUILDER_ASSETS is not set. `make test` sets it.
var apiServer client.Client

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		os.Exit(m.Run())
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}
	if apiServer, err = client.New(cfg, client.Options{}); err != nil {
		panic(err)
	}
	code := m.Run()
	if err := env.Stop(); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func manifest(name, spec string) string {
	return fmt.Sprintf("apiVersion: ategress.ate-tooling.github.io/v1alpha1\nkind: EgressRoutePolicy\nmetadata:\n  name: %s\nspec:\n%s",
		name, indent(spec))
}

func indent(s string) string {
	lines := strings.Split(strings.Trim(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n") + "\n"
}

// route wraps one route's fields into a spec with a single host.
func route(fields string) string {
	return "hosts:\n- host: api.github.com\n  routes:\n  - " + strings.ReplaceAll(strings.Trim(fields, "\n"), "\n", "\n    ") + "\n"
}

func paths(p ...string) string {
	quoted := make([]string, len(p))
	for i, s := range p {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return route("methods: [GET]\npaths: [" + strings.Join(quoted, ", ") + "]")
}

func hosts(n int) string {
	var b strings.Builder
	b.WriteString("hosts:\n")
	for i := range n {
		fmt.Fprintf(&b, "- host: h%d.example.com\n", i)
	}
	return b.String()
}

// admissionCases are manifests and whether the API server admits them. The
// offline validator must reach the same verdict on every one, and
// TestSchemaAgreesWithAPIServer asks a real API server whether the verdicts
// written here are right.
var admissionCases = []struct {
	name     string
	manifest string
	valid    bool
}{
	// Valid.
	{"lockdown", manifest("p", "hosts:\n- host: api.github.com"), true},
	{"everything set", manifest("p", `
enforcementMode: Audit
logAllowed: true
actorSelector:
  atespaces: [research, "team-*"]
  names: ["*"]
hosts:
- host: api.github.com
  routes:
  - methods: [GET, HEAD]
    paths: [/repos/acme/*, /repos/acme/*/**, /orgs/acme]
    caseInsensitive: true
  - methods: [POST]
    paths: [/]
- host: registry-1.docker.io
  routes:
  - methods: [GET]
    paths: [/v2/, /**]
`), true},
	{"dotted name", manifest("github.acme-readonly", "hosts:\n- host: api.github.com"), true},
	{"no routes", manifest("p", "hosts:\n- host: api.github.com\n  routes: []"), true},
	{"empty selector", manifest("p", "actorSelector: {}\nhosts:\n- host: api.github.com"), true},
	{"null mode reads as absent", manifest("p", "enforcementMode: null\nhosts:\n- host: api.github.com"), true},
	{"null selector reads as absent", manifest("p", "actorSelector: null\nhosts:\n- host: api.github.com"), true},
	{"null routes reads as absent", manifest("p", "hosts:\n- host: api.github.com\n  routes: null"), true},
	{"32 hosts", manifest("p", hosts(32)), true},
	{"same path in two routes", manifest("p", "hosts:\n- host: a.example.com\n  routes:\n  - {methods: [GET], paths: [/a]}\n  - {methods: [GET], paths: [/a]}"), true},
	{"literal of dots", manifest("p", paths("/...", "/a.b", "/.a")), true},

	// Invalid: what the controller's TestSchemaRejects submits.
	{"no hosts", manifest("p", "hosts: []"), false},
	{"uppercase host", manifest("p", "hosts:\n- host: API.github.com"), false},
	{"host with port", manifest("p", "hosts:\n- host: api.github.com:443"), false},
	{"wildcard host", manifest("p", "hosts:\n- host: \"*.github.com\""), false},
	{"duplicate host", manifest("p", "hosts:\n- host: api.github.com\n- host: api.github.com"), false},
	{"bad mode", manifest("p", "enforcementMode: Permissive\nhosts:\n- host: api.github.com"), false},
	{"lowercase method", manifest("p", route("methods: [get]\npaths: [/a]")), false},
	{"no methods", manifest("p", route("methods: []\npaths: [/a]")), false},
	{"no paths", manifest("p", route("methods: [GET]\npaths: []")), false},
	{"relative path", manifest("p", paths("repos/acme")), false},
	{"double slash", manifest("p", paths("/repos//acme")), false},
	{"double trailing slash", manifest("p", paths("/repos/acme//")), false},
	{"trailing slash after double star", manifest("p", paths("/repos/**/")), false},
	{"dot-dot", manifest("p", paths("/repos/../acme")), false},
	{"dot", manifest("p", paths("/repos/./acme")), false},
	{"percent", manifest("p", paths("/repos/acme%2F")), false},
	{"double star not last", manifest("p", paths("/repos/**/acme")), false},
	{"embedded star", manifest("p", paths("/repos/ac*")), false},
	{"leading embedded star", manifest("p", paths("/repos/*cme")), false},
	{"triple star", manifest("p", paths("/repos/***")), false},
	{"query in path", manifest("p", paths("/repos/acme?x=1")), false},
	{"uppercase glob", manifest("p", "actorSelector: {atespaces: [Research]}\nhosts:\n- host: api.github.com"), false},
	{"glob with slash", manifest("p", "actorSelector: {names: [a/b]}\nhosts:\n- host: api.github.com"), false},

	// Invalid: structure, types, limits and names.
	{"no spec", "apiVersion: ategress.ate-tooling.github.io/v1alpha1\nkind: EgressRoutePolicy\nmetadata:\n  name: p\n", false},
	{"spec without hosts", manifest("p", "enforcementMode: Audit"), false},
	{"hosts not a list", manifest("p", "hosts: api.github.com"), false},
	{"host not a string", manifest("p", "hosts:\n- host: 5"), false},
	{"host missing", manifest("p", "hosts:\n- routes: []"), false},
	{"route without methods", manifest("p", route("paths: [/a]")), false},
	{"route without paths", manifest("p", route("methods: [GET]")), false},
	{"boolean as string", manifest("p", route("methods: [GET]\npaths: [/a]\ncaseInsensitive: \"yes\"")), false},
	{"logAllowed as string", manifest("p", "logAllowed: \"true\"\nhosts:\n- host: api.github.com"), false},
	{"null method", manifest("p", route("methods: [null]\npaths: [/a]")), false},
	{"33 hosts", manifest("p", hosts(33)), false},
	{"33 routes", manifest("p", "hosts:\n- host: a.example.com\n  routes:\n"+strings.Repeat("  - {methods: [GET], paths: [/a]}\n", 33)), false},
	{"path too long", manifest("p", paths("/"+strings.Repeat("a", 1024))), false},
	{"host too long", manifest("p", "hosts:\n- host: "+strings.Repeat("a.", 127)+"a"), false},
	{"glob too long", manifest("p", "actorSelector: {atespaces: ["+strings.Repeat("a", 64)+"]}\nhosts:\n- host: api.github.com"), false},
	{"duplicate method", manifest("p", route("methods: [GET, GET]\npaths: [/a]")), false},
	{"duplicate path", manifest("p", paths("/a", "/b", "/a")), false},
	{"duplicate glob", manifest("p", "actorSelector: {atespaces: [a, a]}\nhosts:\n- host: api.github.com"), false},
	{"unknown spec field", manifest("p", "enforcmentMode: Audit\nhosts:\n- host: api.github.com"), false},
	{"unknown host field", manifest("p", "hosts:\n- host: api.github.com\n  route: []"), false},
	{"unknown route field", manifest("p", route("methods: [GET]\npaths: [/a]\ncaseSensitive: false")), false},
	{"wrong case field", manifest("p", "Hosts:\n- host: api.github.com"), false},
	{"uppercase name", manifest("Policy", "hosts:\n- host: api.github.com"), false},
	{"name with underscore", manifest("a_b", "hosts:\n- host: api.github.com"), false},
}

func TestSchema(t *testing.T) {
	for _, tc := range admissionCases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := Load([]string{"-"}, strings.NewReader(tc.manifest))
			if err != nil {
				t.Fatal(err)
			}
			d := set.Documents[0]
			if valid := len(d.Invalid) == 0; valid != tc.valid {
				t.Fatalf("valid = %v (%v), want %v\n%s", valid, d.Invalid, tc.valid, tc.manifest)
			}
			// Whatever the schema lets through, the compiler must accept:
			// otherwise the tool would call valid a policy ate-gress drops.
			if _, results := policy.Compile(set.Policies()); tc.valid && results[0].Err != nil {
				t.Errorf("the compiler rejects a policy the schema admits: %v", results[0].Err)
			}
		})
	}
}

// TestSchemaAgreesWithAPIServer submits every admission case to a real API
// server with the CRD installed, as a dry run with kubectl's default strict
// field validation, and requires the offline verdict to be the server's. It
// is what stands behind "passes ategressctl, rejected by the API server
// cannot happen".
func TestSchemaAgreesWithAPIServer(t *testing.T) {
	if apiServer == nil {
		t.Skip("KUBEBUILDER_ASSETS is not set; run through `make test`")
	}
	for _, tc := range admissionCases {
		t.Run(tc.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{}
			if err := yaml.Unmarshal([]byte(tc.manifest), &obj.Object); err != nil {
				t.Fatal(err)
			}
			err := apiServer.Create(t.Context(), obj, client.DryRunAll, client.FieldValidation("Strict"))
			if admitted := err == nil; admitted != tc.valid {
				t.Fatalf("the API server admitted = %v (%v), and the case says valid = %v", admitted, err, tc.valid)
			}
		})
	}
}

// TestSchemaAssumptions fails when the CRD gains something validate does not
// repeat, so that the gap is closed before the tool starts passing policies
// the API server refuses.
func TestSchemaAssumptions(t *testing.T) {
	if bytes.Contains(crd.EgressRoutePolicies, []byte("x-kubernetes-validations")) {
		t.Error("the CRD has CEL rules, which validate does not evaluate: evaluate them, or the tool will pass policies admission rejects")
	}
	var defaults []string
	for line := range strings.SplitSeq(string(crd.EgressRoutePolicies), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "default:") {
			defaults = append(defaults, strings.TrimSpace(line))
		}
	}
	if want := []string{"default: Enforce"}; !slices.Equal(defaults, want) {
		t.Errorf("the CRD's defaults are %q, want %q: validate applies no defaults, which is sound only while a defaulted field is valid when absent", defaults, want)
	}
}

// TestVersions checks that every version the CRD serves can be read, and
// that nothing is read that the CRD does not define.
func TestVersions(t *testing.T) {
	all, err := schemas()
	if err != nil {
		t.Fatal(err)
	}
	served := slices.Sorted(maps.Keys(all))
	if known := slices.Sorted(maps.Keys(versions)); !slices.Equal(served, known) {
		t.Errorf("the CRD serves %v and policyfile reads %v: add the missing version to versions", served, known)
	}
}
