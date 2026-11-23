package extproc

import (
	"strings"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

func TestPolicyMetrics(t *testing.T) {
	h := newHarness(t)
	h.reg.MustRegister(NewPolicyCollector(h.store))
	if n := testutil.CollectAndCount(h.reg, "ategress_policy_decisions_total"); n != 0 {
		t.Errorf("%d series before the first snapshot, want none", n)
	}

	githubPolicy := func(name string, mode v1alpha1.EnforcementMode, paths ...string) v1alpha1.EgressRoutePolicy {
		return v1alpha1.EgressRoutePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.EgressRoutePolicySpec{
				EnforcementMode: mode,
				Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
					Methods: []v1alpha1.Method{"GET"}, Paths: paths,
				}}}},
			},
		}
	}
	swap := func(policies ...v1alpha1.EgressRoutePolicy) {
		t.Helper()
		snap, results := policy.Compile(policies)
		for _, r := range results {
			if r.Err != nil {
				t.Fatal(r.Err)
			}
		}
		h.store.Swap(snap)
	}
	send := func(paths ...string) {
		t.Helper()
		for _, p := range paths {
			if _, err := h.roundTrip(t, headersRequest(actorID, get(p)...)); err != nil {
				t.Fatal(err)
			}
		}
	}
	const header = `
# HELP ategress_policy_decisions_total Requests counted against each policy in the snapshot in effect, by outcome: allow (the policy's route allowed the request), deny (the request was denied, and this is an Enforce policy that claimed its host for its actor), audit (the request was allowed, and this Audit policy alone, switched to Enforce, would have denied it). One request can count against several policies.
# TYPE ategress_policy_decisions_total counter
`

	// Two policies rolling out in Audit. The request to /orgs/acme is one
	// acme-repos would deny, though acme-orgs allows it and no log says so.
	swap(githubPolicy("acme-orgs", v1alpha1.EnforcementModeAudit, "/orgs/acme"),
		githubPolicy("acme-repos", v1alpha1.EnforcementModeAudit, "/repos/acme/**"))
	send("/repos/acme/a", "/repos/acme/b", "/orgs/acme", "/orgs/evil")
	want := header + `
ategress_policy_decisions_total{decision="allow",policy="acme-orgs"} 1
ategress_policy_decisions_total{decision="audit",policy="acme-orgs"} 3
ategress_policy_decisions_total{decision="deny",policy="acme-orgs"} 0
ategress_policy_decisions_total{decision="allow",policy="acme-repos"} 2
ategress_policy_decisions_total{decision="audit",policy="acme-repos"} 2
ategress_policy_decisions_total{decision="deny",policy="acme-repos"} 0
`
	if err := testutil.GatherAndCompare(h.reg, strings.NewReader(want), "ategress_policy_decisions_total"); err != nil {
		t.Error(err)
	}

	// acme-repos is switched to Enforce and keeps its counts; acme-orgs is
	// deleted and its series go with it.
	swap(githubPolicy("acme-repos", v1alpha1.EnforcementModeEnforce, "/repos/acme/**"))
	send("/repos/acme/a", "/orgs/acme")
	want = header + `
ategress_policy_decisions_total{decision="allow",policy="acme-repos"} 3
ategress_policy_decisions_total{decision="audit",policy="acme-repos"} 2
ategress_policy_decisions_total{decision="deny",policy="acme-repos"} 1
`
	if err := testutil.GatherAndCompare(h.reg, strings.NewReader(want), "ategress_policy_decisions_total"); err != nil {
		t.Error(err)
	}

	// Requests that never reach a policy count against none.
	for _, req := range []*extprocv3.ProcessingRequest{
		headersRequest("", get("/repos/acme/a")...),
		headersRequest(actorID, ":method", "GET", ":authority", "api.github.com:x", ":path", "/repos/acme/a"),
		headersRequest(actorID, ":method", "GET", ":authority", "pypi.org", ":path", "/simple"),
	} {
		if _, err := h.roundTrip(t, req); err != nil {
			t.Fatal(err)
		}
	}
	if err := testutil.GatherAndCompare(h.reg, strings.NewReader(want), "ategress_policy_decisions_total"); err != nil {
		t.Error(err)
	}
}
