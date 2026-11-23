package policy

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
)

// githubPolicies is the layering examples/github-single-org.yaml recommends:
// every actor is locked out of GitHub, and research actors may read the acme
// org. gitlab-audit is being trialed in Audit mode. registry-pull lets every
// actor pull, but not push, container images, and logs what they fetch.
func githubPolicies() []v1alpha1.EgressRoutePolicy {
	return []v1alpha1.EgressRoutePolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "github-lockdown"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com"}, {Host: "github.com"}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "github-acme-readonly"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				EnforcementMode: v1alpha1.EnforcementModeEnforce,
				ActorSelector:   v1alpha1.ActorSelector{Atespaces: []string{"research-*"}},
				Hosts: []v1alpha1.HostRoutes{
					{Host: "api.github.com", Routes: []v1alpha1.Route{{
						Methods:         []v1alpha1.Method{"GET", "HEAD"},
						Paths:           []string{"/repos/acme/*", "/repos/acme/*/**", "/orgs/acme", "/orgs/acme/**"},
						CaseInsensitive: true,
					}}},
					{Host: "github.com", Routes: []v1alpha1.Route{
						{Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/acme/*/info/refs"}, CaseInsensitive: true},
						{Methods: []v1alpha1.Method{"POST"}, Paths: []string{"/acme/*/git-upload-pack"}, CaseInsensitive: true},
					}},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "gitlab-audit"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				EnforcementMode: v1alpha1.EnforcementModeAudit,
				Hosts: []v1alpha1.HostRoutes{{Host: "gitlab.com", Routes: []v1alpha1.Route{{
					Methods: []v1alpha1.Method{"GET"},
					Paths:   []string{"/api/v4/groups/acme/**"},
				}}}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "registry-pull"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				LogAllowed: true,
				Hosts: []v1alpha1.HostRoutes{{Host: "registry-1.docker.io", Routes: []v1alpha1.Route{{
					Methods: []v1alpha1.Method{"GET", "HEAD"},
					Paths:   []string{"/", "/v2/", "/**"},
				}}}},
			},
		},
	}
}

func mustCompile(t testing.TB, policies []v1alpha1.EgressRoutePolicy) *Snapshot {
	t.Helper()
	s, results := Compile(policies)
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("policy %s: %v", r.Name, r.Err)
		}
	}
	return s
}

var (
	research = identity.Actor{Atespace: "research-a", Name: "agent-1"}
	other    = identity.Actor{Atespace: "billing", Name: "agent-1"}
)

func TestDecide(t *testing.T) {
	s := mustCompile(t, githubPolicies())
	tests := []struct {
		name      string
		actor     identity.Actor
		method    string
		authority string
		path      string
		want      Decision
	}{
		// Allowed routes.
		{name: "read a repo", actor: research, method: "GET", authority: "api.github.com", path: "/repos/acme/widget",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/repos/acme/*"}},
		{name: "read repo contents with a query", actor: research, method: "GET", authority: "api.github.com", path: "/repos/acme/widget/contents/README.md?ref=main",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/repos/acme/*/**"}},
		{name: "HEAD", actor: research, method: "HEAD", authority: "api.github.com", path: "/orgs/acme",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/orgs/acme"}},
		{name: "org name in another case", actor: research, method: "GET", authority: "api.github.com", path: "/repos/ACME/widget",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/repos/acme/*"}},
		{name: "authority with port", actor: research, method: "GET", authority: "api.github.com:443", path: "/orgs/acme",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/orgs/acme"}},
		{name: "authority in another case", actor: research, method: "GET", authority: "API.GitHub.com", path: "/orgs/acme",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/orgs/acme"}},
		{name: "git clone discovery", actor: research, method: "GET", authority: "github.com", path: "/acme/widget.git/info/refs?service=git-upload-pack",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/acme/*/info/refs"}},
		{name: "git fetch", actor: research, method: "POST", authority: "github.com", path: "/acme/widget.git/git-upload-pack",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "github-acme-readonly", Pattern: "/acme/*/git-upload-pack"}},

		// Hosts nobody claims are Substrate's EgressPolicy's business.
		{name: "unclaimed host", actor: research, method: "DELETE", authority: "pypi.org", path: "/anything",
			want: Decision{Allowed: true, Reason: ReasonUnclaimed}},
		{name: "unclaimed host with a path Canonicalize refuses", actor: research, method: "GET", authority: "pypi.org", path: "/a//b",
			want: Decision{Allowed: true, Reason: ReasonUnclaimed}},
		{name: "subdomain of a claimed host is a different host", actor: research, method: "GET", authority: "uploads.github.com", path: "/x",
			want: Decision{Allowed: true, Reason: ReasonUnclaimed}},

		// The lockdown applies to actors no org policy selects.
		{name: "other atespace locked out", actor: other, method: "GET", authority: "api.github.com", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-lockdown"}},

		// Bypass attempts.
		{name: "another org", actor: research, method: "GET", authority: "api.github.com", path: "/repos/evil/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "org prefix collision", actor: research, method: "GET", authority: "api.github.com", path: "/repos/acme-evil/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "write method", actor: research, method: "DELETE", authority: "api.github.com", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "lowercase method", actor: research, method: "get", authority: "api.github.com", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "unknown method", actor: research, method: "PROPFIND", authority: "api.github.com", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "graphql", actor: research, method: "POST", authority: "api.github.com", path: "/graphql",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "repository by id", actor: research, method: "GET", authority: "api.github.com", path: "/repositories/1296269",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "search", actor: research, method: "GET", authority: "api.github.com", path: "/search/code?q=org:evil",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "query smuggling", actor: research, method: "GET", authority: "api.github.com", path: "/user?x=/repos/acme/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "git push", actor: research, method: "POST", authority: "github.com", path: "/acme/widget.git/git-receive-pack",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "dot-dot traversal", actor: research, method: "GET", authority: "api.github.com", path: "/repos/acme/widget/../../evil/widget",
			want: Decision{Reason: ReasonPath, Policy: "github-acme-readonly"}},
		{name: "encoded traversal", actor: research, method: "GET", authority: "api.github.com", path: "/repos/acme/widget/..%2F..%2Fevil",
			want: Decision{Reason: ReasonPath, Policy: "github-acme-readonly"}},
		{name: "encoded slash in org", actor: research, method: "GET", authority: "api.github.com", path: "/repos/acme%2F..%2Fevil/widget",
			want: Decision{Reason: ReasonPath, Policy: "github-acme-readonly"}},
		{name: "double slash", actor: research, method: "GET", authority: "api.github.com", path: "/repos//acme/widget",
			want: Decision{Reason: ReasonPath, Policy: "github-acme-readonly"}},
		{name: "backslash", actor: research, method: "GET", authority: "api.github.com", path: `/repos/acme\..\evil`,
			want: Decision{Reason: ReasonPath, Policy: "github-acme-readonly"}},
		{name: "trailing slash is not matched by a template without one", actor: research, method: "GET", authority: "api.github.com", path: "/orgs/acme/",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "trailing slash is not matched by **", actor: research, method: "GET", authority: "api.github.com", path: "/repos/acme/widget/pulls/",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "double trailing slash", actor: research, method: "GET", authority: "api.github.com", path: "/orgs/acme//",
			want: Decision{Reason: ReasonPath, Policy: "github-acme-readonly"}},
		{name: "trailing-dot authority is the same host", actor: research, method: "GET", authority: "api.github.com.", path: "/repos/evil/widget",
			want: Decision{Reason: ReasonNoRoute, Policy: "github-acme-readonly"}},
		{name: "userinfo in authority", actor: research, method: "GET", authority: "acme@api.github.com", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonAuthority}},
		{name: "empty authority", actor: research, method: "GET", authority: "", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonAuthority}},
		{name: "bad port", actor: research, method: "GET", authority: "api.github.com:https", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonAuthority}},
		{name: "two trailing dots", actor: research, method: "GET", authority: "api.github.com..", path: "/repos/evil/widget",
			want: Decision{Reason: ReasonAuthority}},
		{name: "empty label", actor: research, method: "GET", authority: "api..github.com", path: "/repos/acme/widget",
			want: Decision{Reason: ReasonAuthority}},

		// A registry: pulls allowed, including the version check, and logged.
		{name: "registry version check", actor: other, method: "GET", authority: "registry-1.docker.io", path: "/v2/",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "registry-pull", Pattern: "/v2/", LogAllowed: true}},
		{name: "registry manifest", actor: other, method: "HEAD", authority: "registry-1.docker.io", path: "/v2/library/alpine/manifests/3.22",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "registry-pull", Pattern: "/**", LogAllowed: true}},
		{name: "registry push", actor: other, method: "POST", authority: "registry-1.docker.io", path: "/v2/library/alpine/blobs/uploads/",
			want: Decision{Reason: ReasonNoRoute, Policy: "registry-pull"}},
		{name: "registry trailing slash ** does not reach", actor: other, method: "GET", authority: "registry-1.docker.io", path: "/v2/library/alpine/tags/",
			want: Decision{Reason: ReasonNoRoute, Policy: "registry-pull"}},

		// Audit mode allows, but says it would not have.
		{name: "audit allows a matching route", actor: other, method: "GET", authority: "gitlab.com", path: "/api/v4/groups/acme/projects",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "gitlab-audit", Pattern: "/api/v4/groups/acme/**"}},
		{name: "audit records a would-deny", actor: other, method: "GET", authority: "gitlab.com", path: "/api/v4/groups/evil/projects",
			want: Decision{Allowed: true, Audited: true, Reason: ReasonNoRoute, Policy: "gitlab-audit"}},
		{name: "audit records a would-deny path", actor: other, method: "GET", authority: "gitlab.com", path: "/api/v4/groups/acme/../evil",
			want: Decision{Allowed: true, Audited: true, Reason: ReasonPath, Policy: "gitlab-audit"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Decide(Request{Actor: tt.actor, Method: tt.method, Authority: tt.authority, Path: tt.path})
			if got != tt.want {
				t.Errorf("Decide() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecideEnforceOutranksAudit(t *testing.T) {
	// An Audit policy's routes must not allow what an Enforce policy on the
	// same host denies.
	policies := []v1alpha1.EgressRoutePolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "a-audit-wide-open"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				EnforcementMode: v1alpha1.EnforcementModeAudit,
				Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
					Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/**"},
				}}}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "b-enforce"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
					Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/orgs/acme"},
				}}}},
			},
		},
	}
	s := mustCompile(t, policies)
	got := s.Decide(Request{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/orgs/evil"})
	want := Decision{Reason: ReasonNoRoute, Policy: "a-audit-wide-open"}
	if got != want {
		t.Errorf("Decide() = %+v, want %+v", got, want)
	}
}

func TestDecideLogAllowed(t *testing.T) {
	// The policies claiming api.github.com, in the order Decide sees them.
	// b-allow allows the request before Decide reaches c-log, which must
	// still be found.
	policy := func(name string, logAllowed bool, sel v1alpha1.ActorSelector, paths ...string) v1alpha1.EgressRoutePolicy {
		var routes []v1alpha1.Route
		if len(paths) > 0 {
			routes = []v1alpha1.Route{{Methods: []v1alpha1.Method{"GET"}, Paths: paths}}
		}
		return v1alpha1.EgressRoutePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.EgressRoutePolicySpec{
				LogAllowed: logAllowed, ActorSelector: sel,
				Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: routes}},
			},
		}
	}
	researchOnly := v1alpha1.ActorSelector{Atespaces: []string{"research-*"}}
	tests := []struct {
		name     string
		policies []v1alpha1.EgressRoutePolicy
		actor    identity.Actor
		path     string
		want     bool
	}{
		{
			name:     "no policy asks",
			policies: []v1alpha1.EgressRoutePolicy{policy("a", false, v1alpha1.ActorSelector{}, "/**")},
			actor:    research, path: "/orgs/acme",
		},
		{
			name:     "the allowing policy asks",
			policies: []v1alpha1.EgressRoutePolicy{policy("a", true, v1alpha1.ActorSelector{}, "/**")},
			actor:    research, path: "/orgs/acme", want: true,
		},
		{
			name: "an earlier claiming policy asks",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("a-log", true, v1alpha1.ActorSelector{}),
				policy("b-allow", false, v1alpha1.ActorSelector{}, "/**"),
			},
			actor: research, path: "/orgs/acme", want: true,
		},
		{
			name: "a later claiming policy asks",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("b-allow", false, v1alpha1.ActorSelector{}, "/**"),
				policy("c-log", true, researchOnly),
			},
			actor: research, path: "/orgs/acme", want: true,
		},
		{
			name: "a later policy asks but does not select the actor",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("b-allow", false, v1alpha1.ActorSelector{}, "/**"),
				policy("c-log", true, researchOnly),
			},
			actor: other, path: "/orgs/acme",
		},
		{
			name: "an Audit policy asks",
			policies: func() []v1alpha1.EgressRoutePolicy {
				p := policy("a", true, v1alpha1.ActorSelector{}, "/**")
				p.Spec.EnforcementMode = v1alpha1.EnforcementModeAudit
				return []v1alpha1.EgressRoutePolicy{p}
			}(),
			actor: research, path: "/orgs/acme", want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustCompile(t, tt.policies)
			r := Request{Actor: tt.actor, Method: "GET", Authority: "api.github.com", Path: tt.path}
			d := s.Decide(r)
			if !d.Allowed || d.LogAllowed != tt.want {
				t.Errorf("Decide() = %+v, want allowed with LogAllowed %v", d, tt.want)
			}
			if ref := referenceDecide(tt.policies, r); ref.LogAllowed != d.LogAllowed {
				t.Errorf("reference LogAllowed = %v, Decide says %v", ref.LogAllowed, d.LogAllowed)
			}
		})
	}
}

func TestDecideSelector(t *testing.T) {
	policy := func(sel v1alpha1.ActorSelector) []v1alpha1.EgressRoutePolicy {
		return []v1alpha1.EgressRoutePolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "p"},
			Spec:       v1alpha1.EgressRoutePolicySpec{ActorSelector: sel, Hosts: []v1alpha1.HostRoutes{{Host: "example.com"}}},
		}}
	}
	tests := []struct {
		name     string
		selector v1alpha1.ActorSelector
		actor    identity.Actor
		selected bool
	}{
		{name: "empty selects all", actor: research, selected: true},
		{name: "exact atespace", selector: v1alpha1.ActorSelector{Atespaces: []string{"research-a"}}, actor: research, selected: true},
		{name: "exact atespace is not a prefix", selector: v1alpha1.ActorSelector{Atespaces: []string{"research"}}, actor: research},
		{name: "glob atespace", selector: v1alpha1.ActorSelector{Atespaces: []string{"research-*"}}, actor: research, selected: true},
		{name: "suffix glob", selector: v1alpha1.ActorSelector{Names: []string{"*-1"}}, actor: research, selected: true},
		{name: "any of several", selector: v1alpha1.ActorSelector{Names: []string{"x", "agent-1"}}, actor: research, selected: true},
		{name: "both must match", selector: v1alpha1.ActorSelector{Atespaces: []string{"research-*"}, Names: []string{"other"}}, actor: research},
		{name: "glob miss", selector: v1alpha1.ActorSelector{Atespaces: []string{"research-*"}}, actor: other},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustCompile(t, policy(tt.selector))
			d := s.Decide(Request{Actor: tt.actor, Method: "GET", Authority: "example.com", Path: "/"})
			if selected := d.Reason != ReasonUnclaimed; selected != tt.selected {
				t.Errorf("selected = %v, want %v (decision %+v)", selected, tt.selected, d)
			}
		})
	}
}

func TestCompileRejects(t *testing.T) {
	valid := func() v1alpha1.EgressRoutePolicySpec {
		return v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{{Host: "example.com", Routes: []v1alpha1.Route{{
			Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/a"},
		}}}}}
	}
	tests := []struct {
		name   string
		mutate func(*v1alpha1.EgressRoutePolicySpec)
		errSub string
	}{
		{name: "bad mode", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.EnforcementMode = "Permissive" }, errSub: "enforcementMode"},
		{name: "no hosts", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts = nil }, errSub: "hosts"},
		{name: "uppercase host", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Host = "Example.com" }, errSub: "hosts[0]"},
		{name: "host with port", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Host = "example.com:443" }, errSub: "hosts[0]"},
		{name: "wildcard host", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Host = "*.example.com" }, errSub: "hosts[0]"},
		{name: "duplicate host", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts = append(s.Hosts, s.Hosts[0]) }, errSub: "listed twice"},
		{name: "no methods", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Routes[0].Methods = nil }, errSub: "methods"},
		{name: "bad method", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Routes[0].Methods = []v1alpha1.Method{"get"} }, errSub: "methods"},
		{name: "no paths", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Routes[0].Paths = nil }, errSub: "paths"},
		{name: "bad path", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Routes[0].Paths = []string{"/a/**/b"} }, errSub: "paths"},
		{name: "escaped path", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Routes[0].Paths = []string{"/a%2Fb"} }, errSub: "paths"},
		{name: "bad glob", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.ActorSelector.Atespaces = []string{"Research"} }, errSub: "actorSelector"},
		{name: "glob with path separator", mutate: func(s *v1alpha1.EgressRoutePolicySpec) { s.ActorSelector.Names = []string{"a/b"} }, errSub: "actorSelector"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := valid()
			tt.mutate(&spec)
			bad := v1alpha1.EgressRoutePolicy{ObjectMeta: metav1.ObjectMeta{Name: "bad", Generation: 7}, Spec: spec}
			good := v1alpha1.EgressRoutePolicy{ObjectMeta: metav1.ObjectMeta{Name: "good"}, Spec: valid()}
			s, results := Compile([]v1alpha1.EgressRoutePolicy{bad, good})
			if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), tt.errSub) {
				t.Fatalf("Compile error = %v, want one mentioning %q", results[0].Err, tt.errSub)
			}
			if results[0].Name != "bad" || results[0].Generation != 7 {
				t.Errorf("result = %+v, want name bad and generation 7", results[0])
			}
			if results[1].Err != nil {
				t.Errorf("valid policy failed to compile: %v", results[1].Err)
			}
			// The rejected policy contributes nothing; the valid one still applies.
			for _, hps := range s.hosts {
				for _, hp := range hps {
					if hp.policy == "bad" {
						t.Errorf("rejected policy is in the snapshot")
					}
				}
			}
			if d := s.Decide(Request{Actor: research, Method: "GET", Authority: "example.com", Path: "/a"}); !d.Allowed || d.Policy != "good" {
				t.Errorf("Decide() = %+v, want allowed by good", d)
			}
		})
	}
}

func TestDecideDoesNotAllocate(t *testing.T) {
	s := mustCompile(t, githubPolicies())
	for _, r := range []Request{
		{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/repos/acme/widget/contents/README.md?ref=main"},
		{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/repos/evil/widget"},
		{Actor: research, Method: "GET", Authority: "pypi.org", Path: "/simple/requests"},
		{Actor: other, Method: "GET", Authority: "registry-1.docker.io", Path: "/v2/"},
	} {
		if allocs := testing.AllocsPerRun(100, func() { s.Decide(r) }); allocs != 0 {
			t.Errorf("Decide(%+v) allocated %v times per call, want 0", r, allocs)
		}
	}
}

// FuzzDecide compares Decide with referenceDecide, a slow implementation
// written to be obviously correct rather than fast.
func FuzzDecide(f *testing.F) {
	f.Add("research-a", "agent-1", "GET", "api.github.com", "/repos/acme/widget")
	f.Add("billing", "x", "POST", "GitHub.com:443", "/acme/w/git-upload-pack")
	f.Add("research-a", "agent-1", "GET", "api.github.com.", "/repos/acme/w/../../evil")
	f.Add("x", "y", "GET", "gitlab.com", "/api/v4/groups/acme/x")
	f.Add("x", "y", "GET", "registry-1.docker.io", "/v2/")
	f.Add("x", "y", "GET", "registry-1.docker.io", "/v2/library/")
	policies := githubPolicies()
	s := mustCompile(f, policies)
	_, live := liveOf(f, policies)
	f.Fuzz(func(t *testing.T, atespace, name, method, authority, rawPath string) {
		r := Request{Actor: identity.Actor{Atespace: atespace, Name: name}, Method: method, Authority: authority, Path: rawPath}
		got := s.Decide(r)
		// Counting a decision must not change it.
		if counted := live.Decide(r); counted != got {
			t.Fatalf("Decide(%+v) = %+v, but %+v when counted", r, got, counted)
		}
		if want := referenceDecide(policies, r); got.Allowed != want.Allowed || got.Audited != want.Audited || got.Reason != want.Reason || got.LogAllowed != want.LogAllowed {
			t.Fatalf("Decide(%+v) = %+v, reference says %+v", r, got, want)
		}
	})
}

func referenceDecide(policies []v1alpha1.EgressRoutePolicy, r Request) Decision {
	host, ok := referenceHost(r.Authority)
	if !ok {
		return Decision{Reason: ReasonAuthority}
	}
	rawPath, _, _ := strings.Cut(r.Path, "?")
	pathOK := referencePathOK(rawPath)

	var enforceClaim, auditClaim, enforceMatch, auditMatch, logAllowed bool
	for _, p := range policies {
		if !referenceSelected(p.Spec.ActorSelector, r.Actor) {
			continue
		}
		audit := p.Spec.EnforcementMode == v1alpha1.EnforcementModeAudit
		for _, h := range p.Spec.Hosts {
			if h.Host != host {
				continue
			}
			if audit {
				auditClaim = true
			} else {
				enforceClaim = true
			}
			logAllowed = logAllowed || p.Spec.LogAllowed
			if !pathOK {
				continue
			}
			for _, rt := range h.Routes {
				for _, m := range rt.Methods {
					if string(m) != r.Method {
						continue
					}
					for _, pat := range rt.Paths {
						if referenceMatch(pat, rawPath, rt.CaseInsensitive) {
							if audit {
								auditMatch = true
							} else {
								enforceMatch = true
							}
						}
					}
				}
			}
		}
	}
	reason := ReasonNoRoute
	if !pathOK {
		reason = ReasonPath
	}
	switch {
	case !enforceClaim && !auditClaim:
		return Decision{Allowed: true, Reason: ReasonUnclaimed}
	case enforceClaim && enforceMatch, !enforceClaim && auditMatch:
		return Decision{Allowed: true, Reason: ReasonRoute, LogAllowed: logAllowed}
	case enforceClaim:
		return Decision{Reason: reason}
	default:
		return Decision{Allowed: true, Audited: true, Reason: reason}
	}
}

func referenceHost(authority string) (string, bool) {
	// Hostnames on the wire are ASCII; Unicode case mapping would turn "İ" into
	// "i".
	for i := 0; i < len(authority); i++ {
		if authority[i] >= 0x80 {
			return "", false
		}
	}
	a := strings.ToLower(authority)
	if strings.HasPrefix(a, "[") {
		end := strings.Index(a, "]")
		if end < 2 || strings.Trim(a[1:end], "0123456789abcdef:.") != "" || !referencePort(a[end+1:]) {
			return "", false
		}
		return a[:end+1], true
	}
	if i := strings.LastIndex(a, ":"); i >= 0 {
		if !referencePort(a[i:]) {
			return "", false
		}
		a = a[:i]
	}
	a = strings.TrimSuffix(a, ".")
	if a == "" || len(a) > 253 || strings.Trim(a, "abcdefghijklmnopqrstuvwxyz0123456789-.") != "" {
		return "", false
	}
	for _, label := range strings.Split(a, ".") {
		if label == "" {
			return "", false
		}
	}
	return a, true
}

func referencePort(s string) bool {
	if s == "" {
		return true
	}
	return len(s) >= 2 && len(s) <= 6 && s[0] == ':' && strings.Trim(s[1:], "0123456789") == ""
}

func referencePathOK(p string) bool {
	if p == "/" {
		return true
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	segs := strings.Split(p[1:], "/")
	if len(segs) > 1 && segs[len(segs)-1] == "" {
		segs = segs[:len(segs)-1] // one trailing slash
	}
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if c == '%' {
				if i+2 >= len(seg) {
					return false
				}
				v, err := strconv.ParseUint(seg[i+1:i+3], 16, 8)
				if err != nil {
					return false
				}
				if v == '/' || v == '\\' || v == '.' || v == '%' || v < 0x20 || v == 0x7f {
					return false
				}
				i += 2
				continue
			}
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@", rune(c)) {
				return false
			}
		}
	}
	return true
}

func referenceSelected(sel v1alpha1.ActorSelector, a identity.Actor) bool {
	matches := func(globs []string, s string) bool {
		if len(globs) == 0 {
			return true
		}
		for _, g := range globs {
			if ok, _ := path.Match(g, s); ok {
				return true
			}
		}
		return false
	}
	return matches(sel.Atespaces, a.Atespace) && matches(sel.Names, a.Name)
}

func referenceMatch(pattern, p string, fold bool) bool {
	if pattern == "/" || p == "/" {
		return pattern == p
	}
	// A trailing slash leaves an empty last segment, which only an empty
	// pattern segment matches: wildcards match non-empty segments.
	ps, xs := strings.Split(pattern[1:], "/"), strings.Split(p[1:], "/")
	for i, seg := range ps {
		if seg == "**" {
			return len(xs) > i && !slices.Contains(xs[i:], "")
		}
		if i >= len(xs) {
			return false
		}
		if seg == "*" {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if fold && !strings.EqualFold(seg, xs[i]) || !fold && seg != xs[i] {
			return false
		}
	}
	return len(ps) == len(xs)
}

func BenchmarkDecide(b *testing.B) {
	s := mustCompile(b, githubPolicies())
	r := Request{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/repos/acme/widget/contents/README.md?ref=main"}
	b.ReportAllocs()
	for b.Loop() {
		s.Decide(r)
	}
}
