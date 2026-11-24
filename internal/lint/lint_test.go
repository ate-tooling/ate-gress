package lint

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ate-tooling/ate-gress/internal/egresspolicy"
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/policyfile"
)

func manifest(name, spec string) string {
	lines := strings.Split(strings.Trim(spec, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return "apiVersion: ategress.ate-tooling.github.io/v1alpha1\nkind: EgressRoutePolicy\nmetadata:\n  name: " + name +
		"\nspec:\n" + strings.Join(lines, "\n") + "\n"
}

func load(t *testing.T, manifests ...string) *policyfile.Set {
	t.Helper()
	set, err := policyfile.Load([]string{"-"}, strings.NewReader(strings.Join(manifests, "---\n")))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// brief renders findings as "policy field code" lines.
func brief(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = strings.TrimSpace(fmt.Sprintf("%s %s %s", f.Policy, f.Field, f.Code))
	}
	return out
}

func check(t *testing.T, got []Finding, want ...string) {
	t.Helper()
	if !slices.Equal(brief(got), want) {
		t.Errorf("findings:\n  %s\nwant:\n  %s", strings.Join(brief(got), "\n  "), strings.Join(want, "\n  "))
		for _, f := range got {
			t.Logf("%s %s: %s", f.Policy, f.Code, f.Message)
		}
	}
}

func TestChecksAreStable(t *testing.T) {
	// Scripts match on these. A code or name is never reused or renamed;
	// new checks get new codes.
	want := []string{
		"ERP001 schema error", "ERP002 duplicate-item error", "ERP003 compile error",
		"ERP101 audit-shadowed warning", "ERP102 audit-partly-shadowed warning", "ERP103 audit-maybe-shadowed info",
		"ERP201 redundant-path warning", "ERP202 overlapping-routes info",
		"ERP301 tls-passthrough warning", "ERP302 host-not-reached info",
	}
	var got []string
	for _, c := range Checks {
		got = append(got, fmt.Sprintf("%s %s %s", c.Code, c.Name, c.Severity))
		if c.Summary == "" {
			t.Errorf("%s has no summary", c.Code)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("checks = %q, want %q", got, want)
	}
}

func TestClean(t *testing.T) {
	set := load(t,
		manifest("lockdown", "hosts:\n- host: api.github.com"),
		manifest("readonly", `
actorSelector: {atespaces: [research]}
hosts:
- host: api.github.com
  routes:
  - methods: [GET, HEAD]
    paths: [/orgs/acme, /orgs/acme/**, /repos/acme/*, /repos/acme/*/**]
    caseInsensitive: true
  - methods: [POST]
    paths: [/repos/acme/*/issues]
`))
	check(t, Run(set, nil))
}

func TestInvalidPolicies(t *testing.T) {
	set := load(t,
		manifest("bad-template", "hosts:\n- host: api.github.com\n  routes:\n  - methods: [GET]\n    paths: [/a/**/b]"),
		manifest("twice", "hosts:\n- host: api.github.com\n  routes:\n  - methods: [GET, GET]\n    paths: [/a, /a]"),
		manifest("typo", "enforcmentMode: Audit\nhosts:\n- host: api.github.com"),
		manifest("fine", "hosts:\n- host: api.github.com"),
	)
	snap, results, invalid := Validate(set)
	check(t, invalid,
		"bad-template spec.hosts[0].routes[0].paths[0] ERP001",
		"bad-template spec.hosts[0].routes[0].paths ERP003",
		"twice spec.hosts[0].routes[0].methods[1] ERP002",
		"twice spec.hosts[0].routes[0].paths[1] ERP002",
		"typo spec.enforcmentMode ERP001",
	)
	if results[0].Err == nil || results[3].Err != nil {
		t.Errorf("compile results = %+v", results)
	}
	// Every policy is in the snapshot. The one the compiler rejected is a
	// claim with no routes, which fails closed; one only the API server
	// would reject compiled as it was decoded.
	var claiming, rejected []string
	for _, c := range snap.Claims("api.github.com") {
		claiming = append(claiming, c.Policy)
		if c.Rejected {
			rejected = append(rejected, c.Policy)
		}
	}
	if want := []string{"bad-template", "fine", "twice", "typo"}; !slices.Equal(claiming, want) {
		t.Errorf("policies in the snapshot = %v, want %v", claiming, want)
	}
	if want := []string{"bad-template"}; !slices.Equal(rejected, want) {
		t.Errorf("rejected claims = %v, want %v", rejected, want)
	}
	// The compile finding says what the rejected policy does meanwhile.
	for _, f := range invalid {
		if f.Code == Compile.Code && !strings.Contains(f.Message, "allows nothing and still claims its hosts") {
			t.Errorf("compile finding %q does not say what the policy claims", f.Message)
		}
	}
	// Run reports the same, and nothing more for a duplicate the schema
	// check already has.
	check(t, Run(set, nil), brief(invalid)...)
	for _, f := range invalid {
		if f.Severity != Error || f.File == "" || f.Message == "" {
			t.Errorf("finding %+v should be an error with a file and a message", f)
		}
	}
}

func TestSplitCompileError(t *testing.T) {
	for msg, want := range map[string][2]string{
		`hosts[0].routes[1]: paths: pattern "/a/**/b": "**" must be the last segment`: {"spec.hosts[0].routes[1].paths", `pattern "/a/**/b": "**" must be the last segment`},
		`hosts: at least one host is required`:                                        {"spec.hosts", "at least one host is required"},
		`actorSelector: atespaces: "A" is not a glob of [a-z0-9*-]`:                   {"spec.actorSelector.atespaces", `"A" is not a glob of [a-z0-9*-]`},
		`enforcementMode "X" is not Enforce or Audit`:                                 {"spec", `enforcementMode "X" is not Enforce or Audit`},
	} {
		if field, rest := splitCompileError(msg); field != want[0] || rest != want[1] {
			t.Errorf("splitCompileError(%q) = %q, %q; want %q, %q", msg, field, rest, want[0], want[1])
		}
	}
}

func auditPolicy(name, selector string, hosts ...string) string {
	spec := "enforcementMode: Audit\n"
	if selector != "" {
		spec += "actorSelector: " + selector + "\n"
	}
	spec += "hosts:\n"
	for _, h := range hosts {
		spec += "- host: " + h + "\n"
	}
	return manifest(name, spec)
}

func enforcePolicy(name, selector string, hosts ...string) string {
	return strings.Replace(auditPolicy(name, selector, hosts...), "  enforcementMode: Audit\n", "", 1)
}

func TestAuditShadowing(t *testing.T) {
	tests := []struct {
		name      string
		manifests []string
		want      []string
		// message must appear in the first finding.
		message string
	}{
		{
			name:      "an Enforce policy selecting everyone shadows it",
			manifests: []string{enforcePolicy("lockdown", "", "a.example.com"), auditPolicy("audit", "{atespaces: [research]}", "a.example.com")},
			want:      []string{"audit spec.hosts[0] ERP101"},
			message:   `never has effect on a.example.com: Enforce policy "lockdown"`,
		},
		{
			name:      "the same selector shadows it",
			manifests: []string{enforcePolicy("enforce", "{atespaces: [team-*], names: [bot]}", "a.example.com"), auditPolicy("audit", "{atespaces: [team-*], names: [bot]}", "a.example.com")},
			want:      []string{"audit spec.hosts[0] ERP101"},
		},
		{
			name:      "a wider glob shadows a narrower one",
			manifests: []string{enforcePolicy("enforce", "{atespaces: [team-*]}", "a.example.com"), auditPolicy("audit", "{atespaces: [team-a, team-b*]}", "a.example.com")},
			want:      []string{"audit spec.hosts[0] ERP101"},
		},
		{
			name:      "only on the hosts both claim",
			manifests: []string{enforcePolicy("enforce", "", "b.example.com"), auditPolicy("audit", "", "a.example.com", "b.example.com", "c.example.com")},
			want:      []string{"audit spec.hosts[1] ERP101"},
		},
		{
			name:      "no Enforce policy on the host",
			manifests: []string{enforcePolicy("enforce", "", "b.example.com"), auditPolicy("audit", "", "a.example.com"), auditPolicy("audit-2", "", "a.example.com")},
		},
		{
			name:      "selectors that cannot overlap",
			manifests: []string{enforcePolicy("enforce", "{atespaces: [billing, ops-*]}", "a.example.com"), auditPolicy("audit", "{atespaces: [research, dev-*]}", "a.example.com")},
		},
		{
			name:      "selectors that differ only in names",
			manifests: []string{enforcePolicy("enforce", "{names: [bot]}", "a.example.com"), auditPolicy("audit", "{names: [agent]}", "a.example.com")},
		},
		{
			name:      "a narrower Enforce policy shadows it for some actors",
			manifests: []string{enforcePolicy("enforce", "{atespaces: [research]}", "a.example.com"), auditPolicy("audit", "", "a.example.com")},
			want:      []string{"audit spec.hosts[0] ERP102"},
			message:   `for the actors that Enforce policy "enforce" also selects, such as research/a`,
		},
		{
			name:      "globs that overlap without one containing the other",
			manifests: []string{enforcePolicy("enforce", "{atespaces: [team-*]}", "a.example.com"), auditPolicy("audit", "{atespaces: [\"*-prod\"]}", "a.example.com")},
			want:      []string{"audit spec.hosts[0] ERP102"},
			message:   "such as team-prod/a",
		},
		{
			name: "several Enforce policies are named together",
			manifests: []string{enforcePolicy("enforce-a", "{atespaces: [a]}", "a.example.com"), enforcePolicy("enforce-b", "{atespaces: [b]}", "a.example.com"),
				auditPolicy("audit", "", "a.example.com")},
			want:    []string{"audit spec.hosts[0] ERP102"},
			message: `Enforce policies "enforce-a", "enforce-b"`,
		},
		{
			// A rejected policy keeps its claims with no routes, and a glob
			// that does not compile is read as selecting everything: it is a
			// lockdown of the host for every atespace.
			name: "a rejected Enforce policy shadows it as a lockdown",
			manifests: []string{enforcePolicy("rejected", "{atespaces: [Research]}", "a.example.com"),
				auditPolicy("audit", "{atespaces: [research]}", "a.example.com")},
			want: []string{
				"rejected spec.actorSelector.atespaces[0] ERP001",
				"rejected spec.actorSelector.atespaces ERP003",
				"audit spec.hosts[0] ERP101",
			},
		},
		{
			// The names list still narrows the selector.
			name: "a rejected Enforce policy shadows it for the actors it is read to select",
			manifests: []string{enforcePolicy("rejected", "{atespaces: [Research], names: [bot]}", "a.example.com"),
				auditPolicy("audit", "", "a.example.com")},
			want: []string{
				"rejected spec.actorSelector.atespaces[0] ERP001",
				"rejected spec.actorSelector.atespaces ERP003",
				"audit spec.hosts[0] ERP102",
			},
		},
		{
			name: "a rejected Audit policy is left to its compile finding",
			manifests: []string{enforcePolicy("lockdown", "", "a.example.com"),
				auditPolicy("rejected", "{atespaces: [Research]}", "a.example.com")},
			want: []string{
				"rejected spec.actorSelector.atespaces[0] ERP001",
				"rejected spec.actorSelector.atespaces ERP003",
			},
		},
		{
			// "*-" matches no DNS label, so the policies never meet, but that
			// is not something the glob reasoning proves: it says "may".
			name:      "an overlap that could not be settled",
			manifests: []string{enforcePolicy("enforce", "{atespaces: [\"*-\"]}", "a.example.com"), auditPolicy("audit", "{atespaces: [research]}", "b.example.com"), auditPolicy("audit-2", "", "a.example.com")},
			want:      []string{"audit-2 spec.hosts[0] ERP103"},
			message:   "may have no effect on a.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Run(load(t, tt.manifests...), nil)
			check(t, got, tt.want...)
			if tt.message != "" && len(got) > 0 && !strings.Contains(got[0].Message, tt.message) {
				t.Errorf("message %q does not contain %q", got[0].Message, tt.message)
			}
		})
	}
}

// TestAuditShadowedIsTrue checks the claim ERP101 makes against Decide: with
// the Audit policy removed, no decision for an actor it selects changes on
// the host, except in the fields that only name policies.
func TestAuditShadowedIsTrue(t *testing.T) {
	enforce := manifest("enforce", "actorSelector: {atespaces: [team-*]}\nhosts:\n- host: a.example.com\n  routes:\n  - methods: [GET]\n    paths: [/public/**]")
	audit := manifest("audit", "enforcementMode: Audit\nactorSelector: {atespaces: [team-a]}\nhosts:\n- host: a.example.com\n  routes:\n  - methods: [GET, POST]\n    paths: [/**]")
	with := load(t, enforce, audit)
	check(t, Run(with, nil), "audit spec.hosts[0] ERP101")

	withSnap, _ := policy.Compile(with.Policies())
	withoutSnap, _ := policy.Compile(load(t, enforce).Policies())
	for _, actor := range []identity.Actor{{Atespace: "team-a", Name: "x"}, {Atespace: "team-b", Name: "x"}, {Atespace: "other", Name: "x"}} {
		for _, method := range []string{"GET", "POST"} {
			for _, path := range []string{"/public/a", "/private/a", "/a/../b"} {
				r := policy.Request{Actor: actor, Method: method, Authority: "a.example.com", Path: path}
				a, b := withSnap.Decide(r), withoutSnap.Decide(r)
				if a.Allowed != b.Allowed || a.Audited != b.Audited || a.Reason != b.Reason || a.Pattern != b.Pattern {
					t.Errorf("%+v: %+v with the Audit policy and %+v without", r, a, b)
				}
			}
		}
	}
}

// TestRejectedShadowIsTrue checks ERP101 for a rejected Enforce policy
// against Decide, as TestAuditShadowedIsTrue does for an accepted one, and
// that the finding says the policy was rejected.
func TestRejectedShadowIsTrue(t *testing.T) {
	rejected := enforcePolicy("rejected", "{atespaces: [Research]}", "a.example.com")
	audit := manifest("audit", "enforcementMode: Audit\nactorSelector: {atespaces: [research]}\nhosts:\n- host: a.example.com\n  routes:\n  - methods: [GET]\n    paths: [/**]")
	with := load(t, rejected, audit)
	findings := Run(with, nil)
	check(t, findings,
		"rejected spec.actorSelector.atespaces[0] ERP001", "rejected spec.actorSelector.atespaces ERP003", "audit spec.hosts[0] ERP101")
	if len(findings) == 3 && !strings.Contains(findings[2].Message, `Enforce policy "rejected" (rejected: it allows nothing and still claims the host)`) {
		t.Errorf("ERP101 does not say the Enforce policy was rejected: %s", findings[2].Message)
	}

	withSnap, _ := policy.Compile(with.Policies())
	withoutSnap, _ := policy.Compile(load(t, rejected).Policies())
	for _, actor := range []identity.Actor{{Atespace: "research", Name: "x"}, {Atespace: "other", Name: "x"}} {
		r := policy.Request{Actor: actor, Method: "GET", Authority: "a.example.com", Path: "/a"}
		a, b := withSnap.Decide(r), withoutSnap.Decide(r)
		if a.Allowed || b.Allowed || a.Reason != policy.ReasonInvalidPolicy || b.Reason != policy.ReasonInvalidPolicy {
			t.Errorf("%+v: %+v with the Audit policy and %+v without; want both denied with %s", r, a, b, policy.ReasonInvalidPolicy)
		}
	}
}

func TestRoutes(t *testing.T) {
	routes := func(lines string) string {
		return manifest("p", "hosts:\n- host: a.example.com\n  routes:\n"+lines)
	}
	tests := []struct {
		name     string
		manifest string
		want     []string
		message  string
	}{
		{
			name:     "covered in the same route",
			manifest: routes("  - {methods: [GET], paths: [/repos/acme/**, /repos/acme/*, /repos/acme/widget/pulls, /orgs/acme]}"),
			want:     []string{"p spec.hosts[0].routes[0].paths[1] ERP201", "p spec.hosts[0].routes[0].paths[2] ERP201"},
			message:  `"/repos/acme/*" is redundant: "/repos/acme/**" in the same route already allows everything it matches for GET`,
		},
		{
			name:     "covered by another route with all its methods",
			manifest: routes("  - {methods: [GET, HEAD], paths: [/v2/**]}\n  - {methods: [GET], paths: [/v2/library/alpine]}"),
			want:     []string{"p spec.hosts[0].routes[1].paths[0] ERP201"},
			message:  `"/v2/**" (spec.hosts[0].routes[0].paths[0])`,
		},
		{
			name:     "the same template in two routes with the same methods is reported once",
			manifest: routes("  - {methods: [GET, HEAD], paths: [/a]}\n  - {methods: [HEAD, GET], paths: [/a]}"),
			want:     []string{"p spec.hosts[0].routes[1].paths[0] ERP201"},
		},
		{
			name:     "covered for some of its methods",
			manifest: routes("  - {methods: [GET, HEAD], paths: [/v2/**]}\n  - {methods: [GET, POST], paths: [/v2/token]}"),
			want:     []string{"p spec.hosts[0].routes[1].paths[0] ERP202"},
			message:  `"/v2/token" is already allowed for GET by "/v2/**"`,
		},
		{
			name:     "the same template for overlapping methods is reported once",
			manifest: routes("  - {methods: [GET, HEAD], paths: [/a]}\n  - {methods: [GET, POST], paths: [/a]}"),
			want:     []string{"p spec.hosts[0].routes[1].paths[0] ERP202"},
		},
		{
			name:     "other methods",
			manifest: routes("  - {methods: [GET], paths: [/v2/**]}\n  - {methods: [POST], paths: [/v2/token]}"),
		},
		{
			name:     "a trailing slash is its own path",
			manifest: routes("  - {methods: [GET], paths: [/, /v2/, /**, /v2/*]}"),
			want:     []string{"p spec.hosts[0].routes[0].paths[3] ERP201"},
		},
		{
			name:     "a case-sensitive template does not cover a case-insensitive one",
			manifest: routes("  - {methods: [GET], paths: [/orgs/acme]}\n  - {methods: [GET], paths: [/orgs/acme], caseInsensitive: true}"),
			want:     []string{"p spec.hosts[0].routes[0].paths[0] ERP201"},
		},
		{
			name: "another host is another matter",
			manifest: manifest("p", "hosts:\n- host: a.example.com\n  routes:\n  - {methods: [GET], paths: [/**]}\n"+
				"- host: b.example.com\n  routes:\n  - {methods: [GET], paths: [/a]}"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Run(load(t, tt.manifest), nil)
			check(t, got, tt.want...)
			if tt.message != "" && len(got) > 0 && !strings.Contains(got[0].Message, tt.message) {
				t.Errorf("message %q does not contain %q", got[0].Message, tt.message)
			}
		})
	}

	// Another policy's routes are not grounds for a finding: whether they
	// apply depends on its selector and mode.
	check(t, Run(load(t,
		manifest("wide", "hosts:\n- host: a.example.com\n  routes:\n  - {methods: [GET], paths: [/**]}"),
		manifest("narrow", "hosts:\n- host: a.example.com\n  routes:\n  - {methods: [GET], paths: [/a]}"),
	), nil))
}

func TestEgressPolicy(t *testing.T) {
	set := load(t,
		manifest("everyone", "hosts:\n- host: api.example.com\n- host: files.example.com\n- host: both.example.com\n- host: elsewhere.example.org"),
		manifest("research-only", "actorSelector: {atespaces: [research], names: [agent-*]}\nhosts:\n- host: files.example.com\n- host: plain.example.com"),
	)
	parse := func(manifest string) *egresspolicy.Policy {
		p, err := egresspolicy.Parse([]byte(manifest))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	rules := `
rules:
- https: {hostnames: [api.example.com]}
- tlsPassthrough: {hostnames: ["*.example.com"], ports: {numbers: [443]}}
- https: {hostnames: [both.example.com], ports: {numbers: [8443]}}
- http: {hostnames: [plain.example.com]}
`
	agent := identity.Actor{Atespace: "research", Name: "agent-1"}
	bot := identity.Actor{Atespace: "research", Name: "bot"}

	t.Run("the actor is known", func(t *testing.T) {
		got := Run(set, []EgressPolicy{{File: "ep.yaml", Policy: parse(rules), Actor: &agent}})
		check(t, got,
			"everyone spec.hosts[1].host ERP301",
			"everyone spec.hosts[2].host ERP301",
			"everyone spec.hosts[3].host ERP302",
			"research-only spec.hosts[0].host ERP301",
			// plain.example.com is passed through on 443 and seen on 80.
			"research-only spec.hosts[1].host ERP301",
		)
		for i, want := range []string{
			`ep.yaml forwards TLS to files.example.com on port 443 without decrypting it (rules[1].tlsPassthrough "*.example.com"), so ate-gress never sees those requests and this policy is not enforced on them for actor research/agent-1`,
			`it is enforced only on port 8443 (rules[2].https "both.example.com")`,
			`no http or https rule in ep.yaml reaches elsewhere.example.org`,
			`files.example.com`,
			`it is enforced only on port 80 (rules[3].http "plain.example.com")`,
		} {
			if !strings.Contains(got[i].Message, want) {
				t.Errorf("finding %d: message %q does not contain %q", i, got[i].Message, want)
			}
		}
	})

	t.Run("a policy that does not select the actor is left alone", func(t *testing.T) {
		got := Run(set, []EgressPolicy{{File: "ep.yaml", Policy: parse(rules), Actor: &bot}})
		check(t, got,
			"everyone spec.hosts[1].host ERP301",
			"everyone spec.hosts[2].host ERP301",
			"everyone spec.hosts[3].host ERP302",
		)
	})

	t.Run("only the atespace is known", func(t *testing.T) {
		// research-only may select the actor, whatever its name is.
		got := Run(set, []EgressPolicy{{File: "ep.yaml", Policy: parse("metadata: {atespace: research}" + rules)}})
		if len(got) != 5 || !strings.Contains(got[0].Message, "for the actor in atespace research that the EgressPolicy belongs to") {
			t.Errorf("findings = %v", brief(got))
		}
		got = Run(set, []EgressPolicy{{File: "ep.yaml", Policy: parse("metadata: {atespace: billing}" + rules)}})
		check(t, got,
			"everyone spec.hosts[1].host ERP301",
			"everyone spec.hosts[2].host ERP301",
			"everyone spec.hosts[3].host ERP302",
		)
	})

	t.Run("nothing is known about the actor", func(t *testing.T) {
		got := Run(set, []EgressPolicy{{File: "ep.yaml", Policy: parse(rules)}})
		if len(got) != 5 || !strings.Contains(got[0].Message, "for the actor the EgressPolicy belongs to") {
			t.Errorf("findings = %v", brief(got))
		}
	})

	t.Run("every claimed host is intercepted", func(t *testing.T) {
		all := parse("rules:\n- https: {hostnames: [\"*.example.com\", elsewhere.example.org]}\n- tlsPassthrough: {hostnames: [\"*\"], ports: {numbers: [443]}}\n")
		check(t, Run(set, []EgressPolicy{{File: "ep.yaml", Policy: all, Actor: &agent}}))
	})

	t.Run("passthrough on every port", func(t *testing.T) {
		all := parse("rules:\n- tlsPassthrough: {hostnames: [\"*\"], ports: {all: {}}}\n- https: {hostnames: [api.example.com]}\n")
		got := Run(set, []EgressPolicy{{File: "ep.yaml", Policy: all, Actor: &bot}})
		check(t, got,
			"everyone spec.hosts[0].host ERP301",
			"everyone spec.hosts[1].host ERP301",
			"everyone spec.hosts[2].host ERP301",
			"everyone spec.hosts[3].host ERP301",
		)
		if want := "on every other port without decrypting it"; !strings.Contains(got[0].Message, want) {
			t.Errorf("message %q does not contain %q", got[0].Message, want)
		}
		if want := "on every port without decrypting it"; !strings.Contains(got[1].Message, want) {
			t.Errorf("message %q does not contain %q", got[1].Message, want)
		}
	})
}
