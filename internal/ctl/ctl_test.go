package ctl

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// run runs ategressctl and returns its exit code and output.
func run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(args, Env{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut, Version: "test"})
	return code, out.String(), errOut.String()
}

// golden compares got with testdata/golden/<name>, or rewrites the file
// under -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run `go test ./internal/ctl -update` to create it)", err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s (run `go test ./internal/ctl -update` if the change is intended)\n--- got\n%s--- want\n%s", path, got, want)
	}
}

const (
	lintPolicies   = "testdata/lint/policies.yaml"
	lintInvalid    = "testdata/lint/invalid.yaml"
	lintEgress     = "testdata/lint/egress-policy.yaml"
	testPolicies   = "testdata/test/policies.yaml"
	examplePolicy  = "../../examples/github-single-org.yaml"
	exampleTests   = "../../examples/github-single-org.tests.yaml"
	exampleTestsOK = "45 passed, 0 failed\n"
)

// TestGolden pins the output and exit code of every command, in both
// formats. The JSON is an interface: a diff in a .json golden is a change
// someone's script may notice.
func TestGolden(t *testing.T) {
	tests := []struct {
		golden string
		code   int
		args   []string
	}{
		{"test-example.txt", ExitOK, []string{"test", exampleTests}},
		{"test-passing.txt", ExitOK, []string{"test", "testdata/test/passing.tests.yaml"}},
		{"test-passing.json", ExitOK, []string{"test", "-o", "json", "testdata/test/passing.tests.yaml"}},
		{"test-failing.txt", ExitFailed, []string{"test", "testdata/test/failing.tests.yaml"}},
		{"test-failing.json", ExitFailed, []string{"test", "testdata/test/failing.tests.yaml", "-o", "json"}},
		{"test-invalid-policies.txt", ExitFailed, []string{"test", "testdata/test/invalid-policies.tests.yaml"}},
		{"test-invalid-policies.json", ExitFailed, []string{"test", "testdata/test/invalid-policies.tests.yaml", "-o", "json"}},
		{"test-several.txt", ExitFailed, []string{"test", "testdata/test/passing.tests.yaml", "testdata/test/failing.tests.yaml"}},

		{"explain-allow.txt", ExitOK, []string{"explain", "-f", examplePolicy, "-a", "research/agent", "GET", "https://api.github.com/repos/acme/widget/pulls?state=open"}},
		{"explain-allow.json", ExitOK, []string{"explain", "-f", examplePolicy, "-a", "research/agent", "-o", "json", "GET", "https://api.github.com/repos/acme/widget/pulls?state=open"}},
		{"explain-deny.txt", ExitOK, []string{"explain", "-f", examplePolicy, "-a", "research/agent", "POST", "https://api.github.com/graphql"}},
		{"explain-lockdown.txt", ExitOK, []string{"explain", "-f", examplePolicy, "--actor", "billing/agent", "GET", "https://API.GitHub.com:443/repos/acme/widget"}},
		{"explain-unclaimed.txt", ExitOK, []string{"explain", "-f", examplePolicy, "-a", "research/agent", "GET", "https://pypi.org/simple/requests/"}},
		{"explain-path.txt", ExitOK, []string{"explain", "-f", examplePolicy, "-a", "research/agent", "GET", "https://api.github.com/repos/acme/../other/widget"}},
		{"explain-authority.txt", ExitOK, []string{"explain", "-f", examplePolicy, "-a", "research/agent", "GET", "https://user@api.github.com/repos/acme/widget"}},
		{"explain-audit.txt", ExitOK, []string{"explain", "-f", testPolicies, "-a", "research/agent", "GET", "https://files.example.com/private/a.txt"}},
		{"explain-audit.json", ExitOK, []string{"explain", "-f", testPolicies, "-a", "research/agent", "GET", "https://files.example.com/private/a.txt", "-o", "json"}},
		{"explain-enforce-over-audit.txt", ExitOK, []string{"explain", "-f", testPolicies, "-a", "research/agent", "POST", "https://api.example.com/v1/items"}},
		{"explain-log-allowed.txt", ExitOK, []string{"explain", "-f", testPolicies, "-a", "research/agent", "GET", "https://api.example.com/v1/items"}},
		{"explain-invalid-policies.txt", ExitFailed, []string{"explain", "-f", lintInvalid, "-a", "research/agent", "GET", "https://api.example.com/a"}},

		{"lint-example.txt", ExitOK, []string{"lint", "-f", "../../examples"}},
		{"lint-policies.txt", ExitOK, []string{"lint", "-f", lintPolicies}},
		{"lint-policies.json", ExitOK, []string{"lint", "-f", lintPolicies, "-o", "json"}},
		{"lint-egress.txt", ExitOK, []string{"lint", "-f", lintPolicies, "--egress-policy", "research/agent=" + lintEgress}},
		{"lint-egress.json", ExitOK, []string{"lint", "-f", lintPolicies, "--egress-policy", lintEgress, "-o", "json"}},
		{"lint-invalid.txt", ExitFailed, []string{"lint", "-f", lintInvalid}},
		{"lint-invalid.json", ExitFailed, []string{"lint", "-f", lintInvalid, "-o", "json"}},
		{"lint-list.txt", ExitOK, []string{"lint", "--list"}},
		{"lint-list.json", ExitOK, []string{"lint", "--list", "-o", "json"}},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			code, stdout, stderr := run(t, "", tt.args...)
			if code != tt.code {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, tt.code, stderr)
			}
			if strings.HasSuffix(tt.golden, ".json") && !json.Valid([]byte(stdout)) {
				t.Errorf("stdout is not JSON:\n%s", stdout)
			}
			// What a command reports about the policies goes to stdout;
			// stderr is for what stopped it from reporting.
			golden(t, tt.golden, stdout+stderr)
		})
	}
}

// TestExamplesPassTheirTests runs every test file shipped in examples/, so
// that an example and its tests cannot drift apart.
func TestExamplesPassTheirTests(t *testing.T) {
	files, err := filepath.Glob("../../examples/*.tests.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no test files in examples/: %v", err)
	}
	for _, f := range files {
		code, stdout, stderr := run(t, "", "test", f)
		if code != ExitOK {
			t.Errorf("%s: exit code %d\n%s%s", f, code, stdout, stderr)
		}
	}
	// And every example has one.
	policies, _ := filepath.Glob("../../examples/*.yaml")
	for _, p := range policies {
		if strings.HasSuffix(p, ".tests.yaml") {
			continue
		}
		if _, err := os.Stat(strings.TrimSuffix(p, ".yaml") + ".tests.yaml"); err != nil {
			t.Errorf("%s has no test file next to it", p)
		}
	}
}

func TestTestPolicySources(t *testing.T) {
	// -f replaces the policies the test file names: against the lockdown
	// alone, the example's allowed reads are denied.
	lockdown := "apiVersion: ategress.ate-tooling.github.io/v1alpha1\nkind: EgressRoutePolicy\nmetadata:\n  name: github-lockdown\n" +
		"spec:\n  hosts:\n  - host: api.github.com\n  - host: github.com\n  - host: codeload.github.com\n  - host: raw.githubusercontent.com\n"
	code, stdout, _ := run(t, lockdown, "test", "-f", "-", exampleTests)
	if code != ExitFailed || !strings.Contains(stdout, "33 passed, 12 failed") {
		t.Errorf("exit code %d, output:\n%s", code, stdout)
	}

	// With -f -, every test file reads the same stdin.
	example, err := os.ReadFile(examplePolicy)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, string(example), "test", "-f", "-", exampleTests, exampleTests)
	if code != ExitOK || !strings.HasSuffix(stdout, "90 passed, 0 failed\n") {
		t.Errorf("exit code %d, output:\n%s%s", code, stdout, stderr)
	}

	// A directory works for -f, and a flag may follow the test file.
	code, stdout, _ = run(t, "", "test", exampleTests, "-f", "../../examples")
	if code != ExitOK || !strings.HasSuffix(stdout, exampleTestsOK) {
		t.Errorf("exit code %d, output:\n%s", code, stdout)
	}

	// A test file without policies needs -f.
	dir := t.TempDir()
	bare := filepath.Join(dir, "bare.tests.yaml")
	if err := os.WriteFile(bare, []byte("tests:\n- actor: research/agent\n  deny:\n  - POST https://api.github.com/graphql\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run(t, "", "test", bare); code != ExitUsage || !strings.Contains(stderr, "no policies") {
		t.Errorf("exit code %d, stderr: %s", code, stderr)
	}
	if code, stdout, stderr := run(t, "", "test", "-f", examplePolicy, bare); code != ExitOK {
		t.Errorf("exit code %d\n%s%s", code, stdout, stderr)
	}
}

func TestTestFileErrors(t *testing.T) {
	tests := []struct{ name, content, wantErr string }{
		{"not YAML", "tests: [", "yaml"},
		{"no tests", "policies: [p.yaml]\n", "no tests"},
		{"unknown field", "test:\n- actor: a/b\n", `unknown field "test"`},
		{"unknown group field", "tests:\n- actor: a/b\n  allows: [GET https://a.example.com/]\n", `unknown field "allows"`},
		{"unknown expectation field", "tests:\n- actor: a/b\n  allow:\n  - request: GET https://a.example.com/\n    because: route\n", `unknown field "because"`},
		{"no actor", "tests:\n- allow: [GET https://a.example.com/]\n", `tests[0]: actor "" is not <atespace>/<name>`},
		{"actor without a name", "tests:\n- actor: research\n  allow: [GET https://a.example.com/]\n", "is not <atespace>/<name>"},
		{"actor that is not a label", "tests:\n- actor: Research/agent\n  allow: [GET https://a.example.com/]\n", "is not <atespace>/<name>"},
		{"empty group", "tests:\n- actor: a/b\n", "tests[0]: no requests under allow, deny or audit"},
		{"request without a method", "tests:\n- actor: a/b\n  allow: [https://a.example.com/]\n", `tests[0].allow[0]: request "https://a.example.com/" is not "<METHOD> <URL>"`},
		{"request without a scheme", "tests:\n- actor: a/b\n  deny: [GET a.example.com/x]\n", "tests[0].deny[0]"},
		{"request without a host", "tests:\n- actor: a/b\n  deny: [GET https:///x]\n", "has no host"},
		{"misspelled reason", "tests:\n- actor: a/b\n  deny:\n  - request: GET https://a.example.com/\n    reason: noroute\n", `reason "noroute" is not one a request under "deny" can have (no_route, path, invalid_policy, authority)`},
		{"reason of another outcome", "tests:\n- actor: a/b\n  allow:\n  - request: GET https://a.example.com/\n    reason: no_route\n", `can have (route, unclaimed)`},
		{"invalid_policy under allow", "tests:\n- actor: a/b\n  allow:\n  - request: GET https://a.example.com/\n    reason: invalid_policy\n", `can have (route, unclaimed)`},
	}
	dir := t.TempDir()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(dir, "bad.tests.yaml")
			if err := os.WriteFile(file, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := run(t, "", "test", "-f", examplePolicy, file)
			if code != ExitUsage || !strings.Contains(stderr, tt.wantErr) || stdout != "" {
				t.Errorf("exit code %d, stdout %q, stderr %q; want exit 2 and an error containing %q", code, stdout, stderr, tt.wantErr)
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		code    int
		wantErr string
	}{
		{"no command", nil, ExitUsage, "Usage:"},
		{"unknown command", []string{"apply"}, ExitUsage, `unknown command "apply"`},
		{"unknown flag", []string{"lint", "--bogus"}, ExitUsage, "flag provided but not defined"},
		{"unknown output", []string{"lint", "-f", examplePolicy, "-o", "yaml"}, ExitUsage, "text or json"},
		{"test without a file", []string{"test"}, ExitUsage, "no test file"},
		{"test with a missing file", []string{"test", "absent.tests.yaml"}, ExitUsage, "no such file"},
		{"test with missing policies", []string{"test", "-f", "absent.yaml", exampleTests}, ExitUsage, "no such file"},
		{"explain without policies", []string{"explain", "-a", "a/b", "GET", "https://a.example.com/"}, ExitUsage, "-f <policies> is required"},
		{"explain without an actor", []string{"explain", "-f", examplePolicy, "GET", "https://a.example.com/"}, ExitUsage, "-a <atespace>/<name> is required"},
		{"explain with a bad actor", []string{"explain", "-f", examplePolicy, "-a", "research", "GET", "https://a.example.com/"}, ExitUsage, "is not <atespace>/<name>"},
		{"explain without a request", []string{"explain", "-f", examplePolicy, "-a", "a/b"}, ExitUsage, "<METHOD> <URL>"},
		{"explain with a bad URL", []string{"explain", "-f", examplePolicy, "-a", "a/b", "GET", "api.github.com/x"}, ExitUsage, "does not start with http:// or https://"},
		{"lint without policies", []string{"lint"}, ExitUsage, "-f <policies> is required"},
		{"lint with an argument", []string{"lint", examplePolicy}, ExitUsage, "policies are given with -f"},
		{"lint with a bad severity", []string{"lint", "-f", examplePolicy, "--fail-on", "fatal"}, ExitUsage, "--fail-on"},
		{"lint with a missing EgressPolicy", []string{"lint", "-f", examplePolicy, "--egress-policy", "absent.yaml"}, ExitUsage, "no such file"},
		{"lint with an EgressRoutePolicy as EgressPolicy", []string{"lint", "-f", examplePolicy, "--egress-policy", lintPolicies}, ExitUsage, "--egress-policy"},
		{"lint with an actor outside the EgressPolicy's atespace", []string{"lint", "-f", examplePolicy, "--egress-policy", "billing/agent=" + lintEgress}, ExitUsage, `metadata.atespace is "research"`},
		{"lint with a bad actor", []string{"lint", "-f", examplePolicy, "--egress-policy", "research=" + lintEgress}, ExitUsage, "is not <atespace>/<name>"},
		{"help", []string{"help"}, ExitOK, ""},
		{"command help", []string{"lint", "-h"}, ExitOK, "Usage: ategressctl lint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(t, "", tt.args...)
			if code != tt.code || !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("exit code %d, stderr %q; want exit %d and an error containing %q", code, stderr, tt.code, tt.wantErr)
			}
		})
	}
	if code, stdout, _ := run(t, "", "version"); code != ExitOK || stdout != "test\n" {
		t.Errorf("version: exit code %d, stdout %q", code, stdout)
	}
	if code, stdout, _ := run(t, "", "help"); code != ExitOK || !strings.Contains(stdout, "Exit codes:") {
		t.Errorf("help: exit code %d, stdout %q", code, stdout)
	}
}

func TestLintFailOn(t *testing.T) {
	// policies.yaml has warnings and info, and no errors.
	for failOn, want := range map[string]int{"error": ExitOK, "warning": ExitFailed, "info": ExitFailed, "never": ExitOK} {
		if code, _, stderr := run(t, "", "lint", "-f", lintPolicies, "--fail-on", failOn); code != want {
			t.Errorf("--fail-on %s: exit code %d, want %d (%s)", failOn, code, want, stderr)
		}
	}
	// With only info findings, warning does not fail.
	info := "apiVersion: ategress.ate-tooling.github.io/v1alpha1\nkind: EgressRoutePolicy\nmetadata:\n  name: p\nspec:\n  hosts:\n  - host: a.example.com\n" +
		"    routes:\n    - {methods: [GET, HEAD], paths: [/a]}\n    - {methods: [GET, POST], paths: [/a]}\n"
	for failOn, want := range map[string]int{"warning": ExitOK, "info": ExitFailed} {
		if code, stdout, _ := run(t, info, "lint", "-f", "-", "--fail-on", failOn); code != want {
			t.Errorf("--fail-on %s: exit code %d, want %d\n%s", failOn, code, want, stdout)
		}
	}
	// Errors fail even under "never"? No: never means never.
	if code, _, _ := run(t, "", "lint", "-f", lintInvalid, "--fail-on", "never"); code != ExitOK {
		t.Errorf("--fail-on never: exit code %d", code)
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		url, authority, path string
	}{
		{"https://api.github.com/repos/acme/widget", "api.github.com", "/repos/acme/widget"},
		{"http://api.github.com", "api.github.com", "/"},
		{"https://api.github.com?x=1", "api.github.com", "/?x=1"},
		{"https://api.github.com/a?x=/b#frag", "api.github.com", "/a?x=/b"},
		{"https://API.GitHub.com:8443/a", "API.GitHub.com:8443", "/a"},
		// Nothing is cleaned or decoded: these are what the test is about.
		{"https://api.github.com/a/../b//c/%2e%2E/", "api.github.com", "/a/../b//c/%2e%2E/"},
		{"https://user:pw@api.github.com/a", "user:pw@api.github.com", "/a"},
		{"https://[::1]:443/a", "[::1]:443", "/a"},
		{"https://api.github.com/a b", "api.github.com", "/a b"},
	}
	for _, tt := range tests {
		r, err := parseURL("GET", tt.url)
		if err != nil || r.Authority != tt.authority || r.Path != tt.path {
			t.Errorf("parseURL(%q) = %q, %q, %v; want %q, %q", tt.url, r.Authority, r.Path, err, tt.authority, tt.path)
		}
	}
	for _, bad := range []string{"", "api.github.com/a", "ftp://api.github.com/a", "https://", "https:///a", "HTTPS://api.github.com/"} {
		if r, err := parseURL("GET", bad); err == nil {
			t.Errorf("parseURL(%q) = %+v, want an error", bad, r)
		}
	}
	for _, bad := range []string{"", "GET POST"} {
		if _, err := parseURL(bad, "https://a.example.com/"); err == nil {
			t.Errorf("parseURL with method %q: want an error", bad)
		}
	}
}

// TestInvalidPolicyReason checks that a test file may expect invalid_policy
// wherever Decide can give it: a denial, when a rejected Enforce policy is
// all that claims the host, and an audit, when rejected Audit policies are.
func TestInvalidPolicyReason(t *testing.T) {
	data := "tests:\n- actor: a/b\n  deny:\n  - request: GET https://a.example.com/\n    reason: invalid_policy\n" +
		"  audit:\n  - request: GET https://b.example.com/\n    reason: invalid_policy\n"
	if _, cases, err := parseTestFile([]byte(data)); err != nil || len(cases) != 2 {
		t.Fatalf("parseTestFile = %d cases, %v", len(cases), err)
	}
}
