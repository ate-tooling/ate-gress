package policy

import (
	"fmt"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
)

// tallyPolicy claims api.github.com for the actors sel selects, and allows
// GET on paths there.
func tallyPolicy(name string, mode v1alpha1.EnforcementMode, sel v1alpha1.ActorSelector, paths ...string) v1alpha1.EgressRoutePolicy {
	var routes []v1alpha1.Route
	if len(paths) > 0 {
		routes = []v1alpha1.Route{{Methods: []v1alpha1.Method{"GET"}, Paths: paths}}
	}
	return v1alpha1.EgressRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.EgressRoutePolicySpec{
			EnforcementMode: mode, ActorSelector: sel,
			Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: routes}},
		},
	}
}

func liveOf(t testing.TB, policies []v1alpha1.EgressRoutePolicy) (*Store, *Live) {
	t.Helper()
	store := &Store{}
	store.Swap(mustCompile(t, policies))
	return store, store.Live()
}

// nonZero returns the counts that are not all zero.
func nonZero(counts []PolicyCounts) []PolicyCounts {
	return slices.DeleteFunc(counts, func(c PolicyCounts) bool { return c == PolicyCounts{Policy: c.Policy} })
}

func TestTally(t *testing.T) {
	const enforce, audit = v1alpha1.EnforcementModeEnforce, v1alpha1.EnforcementModeAudit
	everyone := v1alpha1.ActorSelector{}
	researchOnly := v1alpha1.ActorSelector{Atespaces: []string{"research-*"}}
	billingOnly := v1alpha1.ActorSelector{Atespaces: []string{"billing"}}
	// broken is a template the compiler rejects, and its policy with it.
	const broken = "/orgs/**/acme"

	tests := []struct {
		name     string
		policies []v1alpha1.EgressRoutePolicy
		// rejected is how many of policies must not compile.
		rejected int
		actor    identity.Actor
		path     string
		// decision is what Decide says, to show where the tallies differ.
		decision Decision
		want     []PolicyCounts
	}{
		{
			name: "an allow counts for the allowing policy alone",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-lockdown", enforce, everyone),
				tallyPolicy("b-acme", enforce, everyone, "/orgs/acme"),
				tallyPolicy("c-everything", enforce, everyone, "/**"),
			},
			actor: research, path: "/orgs/acme",
			decision: Decision{Allowed: true, Reason: ReasonRoute, Policy: "b-acme", Pattern: "/orgs/acme"},
			want:     []PolicyCounts{{Policy: "b-acme", Allow: 1}},
		},
		{
			name: "a denial counts for every Enforce policy that claimed, and no other",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-audit", audit, everyone, "/**"),
				tallyPolicy("b-acme", enforce, everyone, "/orgs/acme"),
				tallyPolicy("c-billing", enforce, billingOnly, "/**"),
				tallyPolicy("d-research", enforce, researchOnly, "/orgs/research"),
			},
			actor: research, path: "/orgs/evil",
			// Decide names the first claimant, which did not deny anything.
			decision: Decision{Reason: ReasonNoRoute, Policy: "a-audit"},
			want:     []PolicyCounts{{Policy: "b-acme", Deny: 1}, {Policy: "d-research", Deny: 1}},
		},
		{
			name: "a refused path is a denial like any other",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a", enforce, everyone, "/**"),
			},
			actor: research, path: "/orgs//acme",
			decision: Decision{Reason: ReasonPath, Policy: "a"},
			want:     []PolicyCounts{{Policy: "a", Deny: 1}},
		},
		{
			name: "an audit counts for every Audit policy without a route",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-acme", audit, everyone, "/orgs/acme"),
				tallyPolicy("b-research", audit, researchOnly, "/orgs/research"),
				tallyPolicy("c-billing", audit, billingOnly),
			},
			actor: research, path: "/orgs/evil",
			decision: Decision{Allowed: true, Audited: true, Reason: ReasonNoRoute, Policy: "a-acme"},
			want:     []PolicyCounts{{Policy: "a-acme", Audit: 1}, {Policy: "b-research", Audit: 1}},
		},
		{
			name: "a request another Audit policy allows is still one this policy would deny",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-acme", audit, everyone, "/orgs/acme"),
				tallyPolicy("b-everything", audit, everyone, "/**"),
				tallyPolicy("c-everything", audit, everyone, "/**"),
			},
			actor: research, path: "/orgs/evil",
			// Not audited: the Audit policies together allow it.
			decision: Decision{Allowed: true, Reason: ReasonRoute, Policy: "b-everything", Pattern: "/**"},
			want:     []PolicyCounts{{Policy: "a-acme", Audit: 1}, {Policy: "b-everything", Allow: 1}},
		},
		{
			name: "an Audit policy counts nothing where an Enforce policy decides",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-audit", audit, everyone),
				tallyPolicy("b-enforce", enforce, everyone, "/**"),
			},
			actor: research, path: "/orgs/acme",
			decision: Decision{Allowed: true, Reason: ReasonRoute, Policy: "b-enforce", Pattern: "/**"},
			want:     []PolicyCounts{{Policy: "b-enforce", Allow: 1}},
		},
		{
			name: "a path refused under Audit counts for every Audit policy",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a", audit, everyone, "/**"),
				tallyPolicy("b", audit, everyone, "/**"),
			},
			actor: research, path: "/orgs/%2e%2e/acme",
			decision: Decision{Allowed: true, Audited: true, Reason: ReasonPath, Policy: "a"},
			want:     []PolicyCounts{{Policy: "a", Audit: 1}, {Policy: "b", Audit: 1}},
		},
		{
			name: "a host no policy claims for the actor counts nowhere",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a", enforce, billingOnly),
			},
			actor: research, path: "/orgs/acme",
			decision: Decision{Allowed: true, Reason: ReasonUnclaimed},
		},
		// A rejected policy is counted as the lockdown it is read as.
		{
			name: "a denial a rejected policy alone causes counts for it",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-audit", audit, everyone, "/**"),
				tallyPolicy("b-broken", enforce, everyone, "/orgs/acme", broken),
			},
			rejected: 1,
			actor:    research, path: "/orgs/acme",
			decision: Decision{Reason: ReasonInvalidPolicy, Policy: "b-broken"},
			want:     []PolicyCounts{{Policy: "b-broken", Deny: 1}},
		},
		{
			name: "a rejected policy shares a denial with the accepted policies that claimed",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-broken", enforce, everyone, "/orgs/evil", broken),
				tallyPolicy("b-lockdown", enforce, everyone),
				tallyPolicy("c-broken", "Sometimes", researchOnly, "/**"),
				tallyPolicy("d-broken", enforce, billingOnly, broken),
			},
			rejected: 3,
			actor:    research, path: "/orgs/evil",
			decision: Decision{Reason: ReasonNoRoute, Policy: "a-broken"},
			want:     []PolicyCounts{{Policy: "a-broken", Deny: 1}, {Policy: "b-lockdown", Deny: 1}, {Policy: "c-broken", Deny: 1}},
		},
		{
			name: "a request another policy allows past a rejected one counts for the other alone",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-broken", enforce, everyone, "/orgs/acme", broken),
				tallyPolicy("b-acme", enforce, everyone, "/orgs/acme"),
			},
			rejected: 1,
			actor:    research, path: "/orgs/acme",
			decision: Decision{Allowed: true, Reason: ReasonRoute, Policy: "b-acme", Pattern: "/orgs/acme"},
			want:     []PolicyCounts{{Policy: "b-acme", Allow: 1}},
		},
		{
			name: "a rejected Audit policy counts every request as one it would deny",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-broken", audit, everyone, "/orgs/acme", broken),
			},
			rejected: 1,
			actor:    research, path: "/orgs/acme",
			decision: Decision{Allowed: true, Audited: true, Reason: ReasonInvalidPolicy, Policy: "a-broken"},
			want:     []PolicyCounts{{Policy: "a-broken", Audit: 1}},
		},
		{
			name: "a rejected Audit policy counts a request an accepted one allows",
			policies: []v1alpha1.EgressRoutePolicy{
				tallyPolicy("a-broken", audit, everyone, "/orgs/acme", broken),
				tallyPolicy("b-acme", audit, everyone, "/orgs/acme"),
			},
			rejected: 1,
			actor:    research, path: "/orgs/acme",
			decision: Decision{Allowed: true, Reason: ReasonRoute, Policy: "b-acme", Pattern: "/orgs/acme"},
			want:     []PolicyCounts{{Policy: "a-broken", Audit: 1}, {Policy: "b-acme", Allow: 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap, results := Compile(tt.policies)
			if n := len(slices.DeleteFunc(results, func(r Result) bool { return r.Err == nil })); n != tt.rejected {
				t.Fatalf("%d policies were rejected, want %d", n, tt.rejected)
			}
			store := &Store{}
			store.Swap(snap)
			live := store.Live()
			r := Request{Actor: tt.actor, Method: "GET", Authority: "api.github.com", Path: tt.path}
			if d := live.Decide(r); d != tt.decision {
				t.Errorf("Decide() = %+v, want %+v", d, tt.decision)
			}
			if got := nonZero(store.PolicyCounts()); !slices.Equal(got, tt.want) {
				t.Errorf("counts = %+v, want %+v", got, tt.want)
			}
			if got := len(store.PolicyCounts()); got != len(tt.policies) {
				t.Errorf("%d policies have a tally, want all %d", got, len(tt.policies))
			}
		})
	}
}

// TestTallyAuditPredictsEnforce checks the audit count against what it
// claims to predict: for every request and every Audit policy, the request
// is counted against the policy exactly when switching that policy, alone,
// to Enforce turns the request from allowed to denied.
func TestTallyAuditPredictsEnforce(t *testing.T) {
	const enforce, audit = v1alpha1.EnforcementModeEnforce, v1alpha1.EnforcementModeAudit
	everyone := v1alpha1.ActorSelector{}
	researchOnly := v1alpha1.ActorSelector{Atespaces: []string{"research-*"}}
	sets := map[string][]v1alpha1.EgressRoutePolicy{
		"audit only": {
			tallyPolicy("a", audit, everyone, "/orgs/acme"),
			tallyPolicy("b", audit, researchOnly, "/orgs/*"),
			tallyPolicy("c", audit, everyone),
		},
		"audit beside enforce": {
			tallyPolicy("a", audit, everyone, "/orgs/acme"),
			tallyPolicy("b", enforce, researchOnly, "/orgs/*"),
			tallyPolicy("c", audit, everyone, "/**"),
		},
	}
	var requests []Request
	for _, actor := range []identity.Actor{research, other} {
		for _, method := range []string{"GET", "POST"} {
			for _, authority := range []string{"api.github.com", "pypi.org", "api.github.com:x"} {
				for _, path := range []string{"/orgs/acme", "/orgs/evil", "/repos/acme/widget", "/orgs//acme"} {
					requests = append(requests, Request{Actor: actor, Method: method, Authority: authority, Path: path})
				}
			}
		}
	}
	for name, policies := range sets {
		t.Run(name, func(t *testing.T) {
			for _, r := range requests {
				store, live := liveOf(t, policies)
				before := live.Decide(r)
				for i, c := range store.PolicyCounts() {
					if policies[i].Name != c.Policy {
						t.Fatalf("counts are not in policy order: %+v", c)
					}
					if policies[i].Spec.EnforcementMode != audit {
						if c.Audit != 0 {
							t.Errorf("%+v: Enforce policy %s has an audit count", r, c.Policy)
						}
						continue
					}
					flipped := slices.Clone(policies)
					flipped[i].Spec.EnforcementMode = enforce
					after := mustCompile(t, flipped).Decide(r)
					if wouldDeny := before.Allowed && !after.Allowed; wouldDeny != (c.Audit == 1) {
						t.Errorf("%+v: enforcing %s alone turns %+v into %+v, but its audit count is %d",
							r, c.Policy, before, after, c.Audit)
					}
				}
			}
		})
	}
}

// TestTallyManyClaimants covers a host more policies claim than decide notes
// in its bit sets.
func TestTallyManyClaimants(t *testing.T) {
	const n = attributionBits + 6
	for _, mode := range []v1alpha1.EnforcementMode{v1alpha1.EnforcementModeEnforce, v1alpha1.EnforcementModeAudit} {
		t.Run(string(mode), func(t *testing.T) {
			// Even policies select the actor; of those, every fourth policy
			// has no route for the request.
			var policies []v1alpha1.EgressRoutePolicy
			var want []PolicyCounts
			for i := range n {
				sel := v1alpha1.ActorSelector{Atespaces: []string{"billing"}}
				if i%2 == 0 {
					sel = v1alpha1.ActorSelector{Atespaces: []string{"research-*"}}
				}
				path := "/orgs/acme"
				if i%4 == 0 {
					path = "/orgs/other"
				}
				name := fmt.Sprintf("p%03d", i)
				policies = append(policies, tallyPolicy(name, mode, sel, path))
				switch {
				case i%2 != 0:
				case mode == v1alpha1.EnforcementModeEnforce:
					want = append(want, PolicyCounts{Policy: name, Deny: 1})
				case i%4 == 0:
					want = append(want, PolicyCounts{Policy: name, Audit: 1})
				case i == 2:
					want = append(want, PolicyCounts{Policy: name, Allow: 1})
				}
			}
			path := "/orgs/acme"
			if mode == v1alpha1.EnforcementModeEnforce {
				path = "/orgs/evil"
			}
			store, live := liveOf(t, policies)
			live.Decide(Request{Actor: research, Method: "GET", Authority: "api.github.com", Path: path})
			if got := nonZero(store.PolicyCounts()); !slices.Equal(got, want) {
				t.Errorf("counts = %+v, want %+v", got, want)
			}
		})
	}
}

func TestStoreCarriesTallies(t *testing.T) {
	const enforce = v1alpha1.EnforcementModeEnforce
	everyone := v1alpha1.ActorSelector{}
	stays, goes := tallyPolicy("stays", enforce, everyone), tallyPolicy("goes", enforce, everyone)
	deny := Request{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/orgs/acme"}

	store := &Store{}
	if store.Live() != nil || store.Load() != nil || store.PolicyCounts() != nil {
		t.Fatal("an empty store has a snapshot")
	}
	store.Swap(mustCompile(t, []v1alpha1.EgressRoutePolicy{goes, stays}))
	old := store.Live()
	old.Decide(deny)
	want := []PolicyCounts{{Policy: "goes", Deny: 1}, {Policy: "stays", Deny: 1}}
	if got := store.PolicyCounts(); !slices.Equal(got, want) {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}

	// A policy that stays keeps its count; one that goes takes its count
	// with it, and a new one starts from zero.
	arrives := tallyPolicy("arrives", enforce, everyone)
	store.Swap(mustCompile(t, []v1alpha1.EgressRoutePolicy{stays, arrives}))
	want = []PolicyCounts{{Policy: "arrives"}, {Policy: "stays", Deny: 1}}
	if got := store.PolicyCounts(); !slices.Equal(got, want) {
		t.Fatalf("counts after the swap = %+v, want %+v", got, want)
	}

	// A request that loaded the previous snapshot before the swap decides
	// after it. It counts for the policy that stayed and cannot bring back
	// the one that went.
	old.Decide(deny)
	want = []PolicyCounts{{Policy: "arrives"}, {Policy: "stays", Deny: 2}}
	if got := store.PolicyCounts(); !slices.Equal(got, want) {
		t.Fatalf("counts after a late decision = %+v, want %+v", got, want)
	}

	// A policy that comes back is a new policy.
	store.Swap(mustCompile(t, []v1alpha1.EgressRoutePolicy{goes, stays, arrives}))
	want = []PolicyCounts{{Policy: "arrives"}, {Policy: "goes"}, {Policy: "stays", Deny: 2}}
	if got := store.PolicyCounts(); !slices.Equal(got, want) {
		t.Fatalf("counts after the policy returned = %+v, want %+v", got, want)
	}

	// A policy that is rejected stays in the snapshot, still claiming, so it
	// keeps its tally and goes on counting the denials it is part of.
	rejected := tallyPolicy("stays", "Sometimes", everyone)
	snap, results := Compile([]v1alpha1.EgressRoutePolicy{rejected, arrives})
	if results[0].Err == nil {
		t.Fatal("the policy compiled")
	}
	store.Swap(snap)
	want = []PolicyCounts{{Policy: "arrives"}, {Policy: "stays", Deny: 2}}
	if got := store.PolicyCounts(); !slices.Equal(got, want) {
		t.Fatalf("counts after a rejection = %+v, want %+v", got, want)
	}
	store.Live().Decide(deny)
	want = []PolicyCounts{{Policy: "arrives", Deny: 1}, {Policy: "stays", Deny: 3}}
	if got := store.PolicyCounts(); !slices.Equal(got, want) {
		t.Fatalf("counts after a denial by the rejected policy = %+v, want %+v", got, want)
	}

	// A rejected policy with nothing to claim has a tally all the same.
	rejected.Spec.Hosts = nil
	snap, _ = Compile([]v1alpha1.EgressRoutePolicy{rejected})
	store.Swap(snap)
	want = []PolicyCounts{{Policy: "stays", Deny: 3}}
	if got := store.PolicyCounts(); !slices.Equal(got, want) {
		t.Fatalf("counts after the policy lost its hosts = %+v, want %+v", got, want)
	}
}

func TestLiveDecideDoesNotAllocate(t *testing.T) {
	_, live := liveOf(t, githubPolicies())
	for _, r := range []Request{
		{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/repos/acme/widget/contents/README.md?ref=main"},
		{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/repos/evil/widget"},
		{Actor: research, Method: "GET", Authority: "pypi.org", Path: "/simple/requests"},
		{Actor: other, Method: "GET", Authority: "registry-1.docker.io", Path: "/v2/"},
	} {
		if allocs := testing.AllocsPerRun(100, func() { live.Decide(r) }); allocs != 0 {
			t.Errorf("Decide(%+v) allocated %v times per call, want 0", r, allocs)
		}
	}
}

// BenchmarkLiveDecide is BenchmarkDecide with the tallies, as the server
// decides.
func BenchmarkLiveDecide(b *testing.B) {
	_, live := liveOf(b, githubPolicies())
	r := Request{Actor: research, Method: "GET", Authority: "api.github.com", Path: "/repos/acme/widget/contents/README.md?ref=main"}
	b.ReportAllocs()
	for b.Loop() {
		live.Decide(r)
	}
}
