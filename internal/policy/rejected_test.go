package policy

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
)

// TestRejectedPolicyStillClaims is the case that used to fail open: a
// lockdown whose only fault is one route on another host.
func TestRejectedPolicyStillClaims(t *testing.T) {
	lockdown := v1alpha1.EgressRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "lockdown"},
		Spec: v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{
			{Host: "api.github.com"},
			{Host: "github.com", Routes: []v1alpha1.Route{{Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/a/**/b"}}}},
		}},
	}
	s, results := Compile([]v1alpha1.EgressRoutePolicy{lockdown})
	if results[0].Err == nil {
		t.Fatal("the policy compiled")
	}
	for _, authority := range []string{"api.github.com", "github.com"} {
		d := s.Decide(Request{Actor: research, Method: "GET", Authority: authority, Path: "/user"})
		if d.Allowed {
			t.Errorf("Decide(%s) = %+v: rejecting the lockdown released the host", authority, d)
		}
	}
}

// TestRejectedPolicyClaims checks what a rejected policy claims, for each way
// of being rejected, and what the decision says about it.
func TestRejectedPolicyClaims(t *testing.T) {
	const enforce, audit = v1alpha1.EnforcementModeEnforce, v1alpha1.EnforcementModeAudit
	route := func(paths ...string) []v1alpha1.Route {
		return []v1alpha1.Route{{Methods: []v1alpha1.Method{"GET"}, Paths: paths}}
	}
	policy := func(name string, mutate func(*v1alpha1.EgressRoutePolicySpec)) v1alpha1.EgressRoutePolicy {
		p := v1alpha1.EgressRoutePolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
		p.Spec.Hosts = []v1alpha1.HostRoutes{{Host: "example.com", Routes: route("/a")}}
		mutate(&p.Spec)
		return p
	}
	badRoute := func(s *v1alpha1.EgressRoutePolicySpec) {
		s.Hosts[0].Routes = append(s.Hosts[0].Routes, route("/a/**/b")...)
	}
	denied := func(policy string) Decision { return Decision{Reason: ReasonInvalidPolicy, Policy: policy} }
	unclaimed := Decision{Allowed: true, Reason: ReasonUnclaimed}
	agent2 := identity.Actor{Atespace: "research-a", Name: "agent-2"}

	tests := []struct {
		name     string
		policies []v1alpha1.EgressRoutePolicy
		// rejected names the policies that must not compile.
		rejected  []string
		actor     identity.Actor
		authority string
		path      string
		want      Decision
		// effect is part of what the rejected policy's Result says it does.
		effect string
	}{
		{
			name:     "a bad route takes the policy's valid routes with it",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", badRoute)},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want:   denied("bad"),
			effect: "denied unless another Enforce policy allows them",
		},
		{
			name: "a bad route on one host keeps the claim on the others",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				badRoute(s)
				s.Hosts = append(s.Hosts, v1alpha1.HostRoutes{Host: "other.example.com", Routes: route("/a")})
			})},
			rejected: []string{"bad"}, actor: research, authority: "other.example.com", path: "/a",
			want: denied("bad"),
		},
		{
			name:     "a refused path is denied for the policy, not the path",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", badRoute)},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a//b",
			want: denied("bad"),
		},
		{
			name: "an unknown mode is Enforce",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.EnforcementMode = "Permissive"
			})},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want:   denied("bad"),
			effect: "Its enforcementMode is read as Enforce.",
		},
		{
			name: "a rejected Audit policy audits and denies nothing",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.EnforcementMode = audit
				badRoute(s)
			})},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want:   Decision{Allowed: true, Audited: true, Reason: ReasonInvalidPolicy, Policy: "bad"},
			effect: "It is an Audit policy, so it denies nothing",
		},
		{
			name: "a bad atespace glob selects every atespace",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.ActorSelector = v1alpha1.ActorSelector{Atespaces: []string{"research-*", "Billing"}, Names: []string{"agent-1"}}
			})},
			rejected: []string{"bad"}, actor: other, authority: "example.com", path: "/a",
			want:   denied("bad"),
			effect: "Its actorSelector.atespaces is read as selecting every atespace.",
		},
		{
			name: "a bad atespace glob leaves the names to narrow the selector",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.ActorSelector = v1alpha1.ActorSelector{Atespaces: []string{"research-*", "Billing"}, Names: []string{"agent-1"}}
			})},
			rejected: []string{"bad"}, actor: agent2, authority: "example.com", path: "/a",
			want: unclaimed,
		},
		{
			name: "a bad name glob selects every name",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.ActorSelector = v1alpha1.ActorSelector{Atespaces: []string{"research-*"}, Names: []string{"a/b"}}
			})},
			rejected: []string{"bad"}, actor: agent2, authority: "example.com", path: "/a",
			want:   denied("bad"),
			effect: "Its actorSelector.names is read as selecting every name.",
		},
		{
			name: "a bad name glob leaves the atespaces to narrow the selector",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.ActorSelector = v1alpha1.ActorSelector{Atespaces: []string{"research-*"}, Names: []string{"a/b"}}
			})},
			rejected: []string{"bad"}, actor: other, authority: "example.com", path: "/a",
			want: unclaimed,
		},
		{
			name: "a host that is not a hostname leaves the others claimed",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.Hosts = append(s.Hosts, v1alpha1.HostRoutes{Host: "*.example.org"})
			})},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want:   denied("bad"),
			effect: "1 of its 2 hosts cannot be claimed",
		},
		{
			name: "a wildcard host claims nothing",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.Hosts = append(s.Hosts, v1alpha1.HostRoutes{Host: "*.example.org"})
			})},
			rejected: []string{"bad"}, actor: research, authority: "api.example.org", path: "/a",
			want: unclaimed,
		},
		{
			name: "a host in another case is claimed as requests name it",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.Hosts[0].Host = "Example.COM"
			})},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want: denied("bad"),
		},
		{
			name: "a host with a port is claimed on every port",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.Hosts[0].Host = "example.com:8443"
			})},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want: denied("bad"),
		},
		{
			// The schema refuses this name, yet a request can carry it.
			name: "a host the schema refuses but a request can name is claimed",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.Hosts[0].Host = "-internal.example.com"
			})},
			rejected: []string{"bad"}, actor: research, authority: "-internal.example.com", path: "/a",
			want: denied("bad"),
		},
		{
			name: "a host listed twice is claimed",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.Hosts = append(s.Hosts, s.Hosts[0])
			})},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want: denied("bad"),
		},
		{
			name: "a policy without hosts has nothing to claim",
			policies: []v1alpha1.EgressRoutePolicy{policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) {
				s.Hosts = nil
			})},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want:   unclaimed,
			effect: "claims no host, so it has no effect",
		},
		{
			name: "another Enforce policy's route still allows",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("bad", badRoute),
				policy("good", func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Routes = route("/b") }),
			},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/b",
			want: Decision{Allowed: true, Reason: ReasonRoute, Policy: "good", Pattern: "/b"},
		},
		{
			// As it was before rejected policies claimed: good denies this.
			name: "beside an accepted Enforce policy the denial is an ordinary one",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("bad", badRoute),
				policy("good", func(s *v1alpha1.EgressRoutePolicySpec) { s.Hosts[0].Routes = route("/b") }),
			},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want: Decision{Reason: ReasonNoRoute, Policy: "bad"},
		},
		{
			name: "an accepted policy that does not select the actor does not make the denial ordinary",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("bad", badRoute),
				policy("good", func(s *v1alpha1.EgressRoutePolicySpec) { s.ActorSelector.Atespaces = []string{"billing"} }),
			},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			want: denied("bad"),
		},
		{
			name: "an Audit policy's route does not allow past a rejected Enforce policy",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("audit", func(s *v1alpha1.EgressRoutePolicySpec) { s.EnforcementMode = audit }),
				policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) { s.EnforcementMode = enforce; badRoute(s) }),
			},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/a",
			// The policy named is the rejected one, not the first claimant.
			want: denied("bad"),
		},
		{
			name: "a rejected Audit policy beside an accepted one audits as that one does",
			policies: []v1alpha1.EgressRoutePolicy{
				policy("bad", func(s *v1alpha1.EgressRoutePolicySpec) { s.EnforcementMode = audit; badRoute(s) }),
				policy("good", func(s *v1alpha1.EgressRoutePolicySpec) { s.EnforcementMode = audit }),
			},
			rejected: []string{"bad"}, actor: research, authority: "example.com", path: "/b",
			want: Decision{Allowed: true, Audited: true, Reason: ReasonNoRoute, Policy: "bad"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, results := Compile(tt.policies)
			for _, r := range results {
				rejected := false
				for _, name := range tt.rejected {
					rejected = rejected || name == r.Name
				}
				if rejected != (r.Err != nil) {
					t.Fatalf("policy %s: Compile error = %v, want rejected = %v", r.Name, r.Err, rejected)
				}
				if rejected && !strings.Contains(r.Effect, tt.effect) {
					t.Errorf("policy %s: effect = %q, want it to say %q", r.Name, r.Effect, tt.effect)
				}
				if rejected && !strings.HasPrefix(r.Effect, "The policy allows nothing") {
					t.Errorf("policy %s: effect = %q, want it to say the policy allows nothing", r.Name, r.Effect)
				}
			}
			r := Request{Actor: tt.actor, Method: "GET", Authority: tt.authority, Path: tt.path}
			if d := s.Decide(r); d != tt.want {
				t.Errorf("Decide() = %+v, want %+v", d, tt.want)
			}
			if allocs := testing.AllocsPerRun(100, func() { s.Decide(r) }); allocs != 0 {
				t.Errorf("Decide() allocated %v times per call, want 0", allocs)
			}
		})
	}
}
