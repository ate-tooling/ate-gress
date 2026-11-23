package policy

import (
	"slices"
	"testing"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
)

func inspectPolicies() []v1alpha1.EgressRoutePolicy {
	p := func(name string, mode v1alpha1.EnforcementMode, sel v1alpha1.ActorSelector, logAllowed bool, hosts ...string) v1alpha1.EgressRoutePolicy {
		out := v1alpha1.EgressRoutePolicy{}
		out.Name = name
		out.Spec = v1alpha1.EgressRoutePolicySpec{EnforcementMode: mode, ActorSelector: sel, LogAllowed: logAllowed}
		for _, h := range hosts {
			out.Spec.Hosts = append(out.Spec.Hosts, v1alpha1.HostRoutes{Host: h})
		}
		return out
	}
	return []v1alpha1.EgressRoutePolicy{
		p("z-lockdown", "", v1alpha1.ActorSelector{}, false, "api.github.com", "github.com"),
		p("a-audit", v1alpha1.EnforcementModeAudit, v1alpha1.ActorSelector{Atespaces: []string{"research-*"}, Names: []string{"agent-1", "bot"}}, true, "api.github.com"),
		p("broken", "", v1alpha1.ActorSelector{}, false, "NOT A HOST"),
	}
}

func TestSnapshotClaims(t *testing.T) {
	s, _ := Compile(inspectPolicies())

	// A rejected policy claims only the hosts a request could name, and
	// "NOT A HOST" is none.
	if got, want := s.Hosts(), []string{"api.github.com", "github.com"}; !slices.Equal(got, want) {
		t.Fatalf("Hosts() = %v, want %v", got, want)
	}
	if got := s.Claims("pypi.org"); got != nil {
		t.Errorf("Claims of an unclaimed host = %v", got)
	}

	claims := s.Claims("api.github.com")
	if len(claims) != 2 || claims[0].Policy != "a-audit" || claims[1].Policy != "z-lockdown" {
		t.Fatalf("Claims() = %+v, want a-audit then z-lockdown, the order Decide considers them in", claims)
	}
	audit, lockdown := claims[0], claims[1]
	if !audit.Audit || !audit.LogAllowed || lockdown.Audit || lockdown.LogAllowed {
		t.Errorf("mode and logAllowed are wrong: %+v", claims)
	}
	if !slices.Equal(audit.Atespaces, []string{"research-*"}) || !slices.Equal(audit.Names, []string{"agent-1", "bot"}) {
		t.Errorf("selector globs = %v, %v", audit.Atespaces, audit.Names)
	}
	if lockdown.Atespaces != nil || lockdown.Names != nil {
		t.Errorf("an empty selector should have nil globs, got %v, %v", lockdown.Atespaces, lockdown.Names)
	}
	if !audit.Selects(research) || audit.Selects(other) || !lockdown.Selects(other) {
		t.Errorf("Selects disagrees with the selector")
	}

	// The view is a copy: writing to it must not reach the snapshot.
	audit.Atespaces[0] = "*"
	if s.Claims("api.github.com")[0].Selects(other) {
		t.Error("changing a Claim changed the snapshot")
	}
}

func TestSnapshotClaimsFor(t *testing.T) {
	s, _ := Compile(inspectPolicies())
	tests := []struct {
		authority string
		actor     identity.Actor
		host      string
		policies  []string
		ok        bool
	}{
		{"api.github.com", research, "api.github.com", []string{"a-audit", "z-lockdown"}, true},
		{"API.GitHub.com:443", research, "api.github.com", []string{"a-audit", "z-lockdown"}, true},
		{"api.github.com.", other, "api.github.com", []string{"z-lockdown"}, true},
		{"pypi.org", research, "pypi.org", nil, true},
		{"user@api.github.com", research, "", nil, false},
	}
	for _, tt := range tests {
		host, claims, ok := s.ClaimsFor(tt.authority, tt.actor)
		var policies []string
		for _, c := range claims {
			policies = append(policies, c.Policy)
		}
		if host != tt.host || ok != tt.ok || !slices.Equal(policies, tt.policies) {
			t.Errorf("ClaimsFor(%q, %v) = %q, %v, %v; want %q, %v, %v", tt.authority, tt.actor, host, policies, ok, tt.host, tt.policies, tt.ok)
		}
		// The claims are the policies Decide consulted: there are none
		// exactly when it calls the host unclaimed.
		d := s.Decide(Request{Actor: tt.actor, Method: "GET", Authority: tt.authority, Path: "/"})
		if tt.ok && (d.Reason == ReasonUnclaimed) != (len(claims) == 0) {
			t.Errorf("ClaimsFor(%q, %v) has %d claims, but Decide's reason is %s", tt.authority, tt.actor, len(claims), d.Reason)
		}
	}
}

func TestSnapshotClaimsRejected(t *testing.T) {
	broken := v1alpha1.EgressRoutePolicy{}
	broken.Name = "broken"
	broken.Spec = v1alpha1.EgressRoutePolicySpec{
		EnforcementMode: "Enforcing",
		ActorSelector:   v1alpha1.ActorSelector{Atespaces: []string{"Research"}, Names: []string{"agent"}},
		Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{
			{Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/a/**/b"}},
		}}},
	}
	s, results := Compile([]v1alpha1.EgressRoutePolicy{broken})
	if results[0].Err == nil {
		t.Fatal("the policy compiled")
	}
	claims := s.Claims("api.github.com")
	if len(claims) != 1 {
		t.Fatalf("Claims() = %+v, want the rejected policy's claim", claims)
	}
	c := claims[0]
	// The claim is read the way that denies more, and says it is rejected.
	if !c.Rejected || c.Audit || c.Atespaces != nil || !slices.Equal(c.Names, []string{"agent"}) {
		t.Errorf("claim = %+v, want a rejected Enforce claim selecting every atespace and the name agent", c)
	}
	if !c.Selects(identity.Actor{Atespace: "billing", Name: "agent"}) || c.Selects(identity.Actor{Atespace: "billing", Name: "bot"}) {
		t.Error("Selects disagrees with the conservative selector")
	}
	d := s.Decide(Request{Actor: identity.Actor{Atespace: "billing", Name: "agent"}, Method: "GET", Authority: "api.github.com", Path: "/a/x/b"})
	if d.Allowed || d.Reason != ReasonInvalidPolicy {
		t.Errorf("Decide = %+v, want a denial with reason %s", d, ReasonInvalidPolicy)
	}
}
