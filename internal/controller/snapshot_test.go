package controller

import (
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// listCache is a cache holding policies, which is all build asks of one.
type listCache struct {
	cache.Cache
	policies []v1alpha1.EgressRoutePolicy
}

func (c *listCache) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	list.(*v1alpha1.EgressRoutePolicyList).Items = slices.Clone(c.policies)
	return nil
}

// replica is a SnapshotBuilder with its own cache and metrics, as each
// ate-gress pod has.
type replica struct {
	cache   *listCache
	builder *SnapshotBuilder
}

func newReplica(policies ...v1alpha1.EgressRoutePolicy) *replica {
	c := &listCache{policies: policies}
	return &replica{cache: c, builder: &SnapshotBuilder{
		Cache: c, Store: &policy.Store{}, Log: slog.New(slog.DiscardHandler),
		Metrics: NewSnapshotMetrics(prometheus.NewRegistry()),
	}}
}

func (r *replica) build(t *testing.T) {
	t.Helper()
	if err := r.builder.build(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func (r *replica) hash() float64 { return testutil.ToFloat64(r.builder.Metrics.policiesHash) }

func storedPolicy(name string, uid types.UID, generation int64) v1alpha1.EgressRoutePolicy {
	p := githubPolicy(name, "/repos/acme/*")
	p.UID, p.Generation = uid, generation
	return *p
}

func TestSnapshotLastBuildMetric(t *testing.T) {
	r := newReplica(storedPolicy("a", "uid-a", 1))
	if got := testutil.ToFloat64(r.builder.Metrics.lastBuild); got != 0 {
		t.Errorf("last build before the first snapshot = %v, want 0", got)
	}
	// The gauge has sub-second precision, the bounds only as much as the
	// clock gives them.
	before := float64(time.Now().UnixNano()) / 1e9
	r.build(t)
	after := float64(time.Now().UnixNano()) / 1e9
	if got := testutil.ToFloat64(r.builder.Metrics.lastBuild); got < before-0.001 || got > after+0.001 {
		t.Errorf("last build = %f, want between %f and %f", got, before, after)
	}
}

func TestSnapshotPoliciesHashMetric(t *testing.T) {
	a, b := storedPolicy("a", "uid-a", 1), storedPolicy("b", "uid-b", 3)
	// The informer cache lists in no particular order.
	fresh, other := newReplica(a, b), newReplica(b, a)
	fresh.build(t)
	other.build(t)
	if fresh.hash() != other.hash() {
		t.Errorf("replicas with the same policies report %v and %v", fresh.hash(), other.hash())
	}
	if fresh.hash() == 0 || fresh.hash() >= 1<<48 || fresh.hash() != float64(uint64(fresh.hash())) {
		t.Errorf("hash = %v, want a non-zero 48-bit integer", fresh.hash())
	}
	same := fresh.hash()

	// A status write changes neither the generation nor the hash.
	withStatus := a
	withStatus.Status.Conditions = []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}}
	withStatus.ResourceVersion = "42"
	fresh.cache.policies = []v1alpha1.EgressRoutePolicy{withStatus, b}
	fresh.build(t)
	if fresh.hash() != same {
		t.Errorf("hash changed from %v to %v on a status write", same, fresh.hash())
	}

	// Anything that changes what the snapshot is built from changes it, so a
	// replica that has not heard of the change stands out.
	changes := map[string][]v1alpha1.EgressRoutePolicy{
		"a spec edit":             {storedPolicy("a", "uid-a", 2), b},
		"a deletion":              {b},
		"a new policy":            {a, b, storedPolicy("c", "uid-c", 1)},
		"a policy replaced":       {storedPolicy("a", "uid-a2", 1), b},
		"no policies":             nil,
		"a rejected policy added": {a, b, {ObjectMeta: metav1.ObjectMeta{Name: "d", UID: "uid-d", Generation: 1}}},
	}
	seen := map[float64]string{same: "the original policies"}
	for name, policies := range changes {
		fresh.cache.policies = policies
		fresh.build(t)
		if prev, dup := seen[fresh.hash()]; dup {
			t.Errorf("%s and %s have the same hash", name, prev)
		}
		seen[fresh.hash()] = name
	}
	if other.hash() != same {
		t.Errorf("the replica that heard of no change now reports %v, not %v", other.hash(), same)
	}
}
