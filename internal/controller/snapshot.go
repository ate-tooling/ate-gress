// Package controller keeps the policy snapshot in step with the cluster's
// EgressRoutePolicy objects, and reports each policy's status.
package controller

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// SnapshotBuilder compiles every EgressRoutePolicy in its cache into a new
// snapshot whenever one changes, and swaps it into Store. Every replica runs
// one, so every replica decides from its own informer cache and the request
// path never waits on the API server.
//
// It rebuilds from the full list rather than patching the previous snapshot:
// policies are few and small, and a snapshot that is a pure function of the
// cache's contents cannot drift from it.
type SnapshotBuilder struct {
	Cache   cache.Cache
	Store   *policy.Store
	Log     *slog.Logger
	Metrics *SnapshotMetrics
	// OnFirstSnapshot, if set, runs once, after the first snapshot is in
	// effect.
	OnFirstSnapshot func()
}

// NeedLeaderElection reports false: every replica serves requests.
func (b *SnapshotBuilder) NeedLeaderElection() bool { return false }

// Start builds the first snapshot once the cache has synced, then rebuilds on
// every change until ctx is done.
func (b *SnapshotBuilder) Start(ctx context.Context) error {
	inf, err := b.Cache.GetInformer(ctx, &v1alpha1.EgressRoutePolicy{})
	if err != nil {
		return fmt.Errorf("getting the EgressRoutePolicy informer: %w", err)
	}
	// A buffer of one coalesces a burst of events into one rebuild: an event
	// arriving while a rebuild is pending is already covered by it.
	changed := make(chan struct{}, 1)
	notify := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	reg, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { notify() },
		UpdateFunc: func(oldObj, newObj any) {
			// Status writes do not change what a policy allows.
			o, ok1 := oldObj.(*v1alpha1.EgressRoutePolicy)
			n, ok2 := newObj.(*v1alpha1.EgressRoutePolicy)
			if !ok1 || !ok2 || o.Generation != n.Generation {
				notify()
			}
		},
		DeleteFunc: func(any) { notify() },
	})
	if err != nil {
		return fmt.Errorf("watching EgressRoutePolicy: %w", err)
	}
	defer func() { _ = inf.RemoveEventHandler(reg) }()

	if !toolscache.WaitForCacheSync(ctx.Done(), reg.HasSynced) {
		return ctx.Err()
	}
	first := true
	for {
		// Drain a notification the initial sync queued; this build covers it.
		select {
		case <-changed:
		default:
		}
		if err := b.build(ctx); err != nil {
			return err
		}
		if first && b.OnFirstSnapshot != nil {
			b.OnFirstSnapshot()
		}
		first = false
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		}
	}
}

func (b *SnapshotBuilder) build(ctx context.Context) error {
	var list v1alpha1.EgressRoutePolicyList
	if err := b.Cache.List(ctx, &list); err != nil {
		return fmt.Errorf("listing EgressRoutePolicy: %w", err)
	}
	slices.SortFunc(list.Items, func(a, b v1alpha1.EgressRoutePolicy) int { return strings.Compare(a.Name, b.Name) })
	snap, results := policy.Compile(list.Items)
	gen := b.Store.Swap(snap)

	rejected := 0
	for _, r := range results {
		if r.Err != nil {
			rejected++
			b.Log.WarnContext(ctx, "policy rejected; it allows nothing",
				slog.String("policy", r.Name), slog.Int64("generation", r.Generation), slog.Any("err", r.Err))
		}
	}
	b.Log.InfoContext(ctx, "policy snapshot in effect",
		slog.Uint64("snapshot", gen), slog.Int("accepted", len(results)-rejected), slog.Int("rejected", rejected))
	if b.Metrics != nil {
		b.Metrics.generation.Set(float64(gen))
		b.Metrics.policies.WithLabelValues("accepted").Set(float64(len(results) - rejected))
		b.Metrics.policies.WithLabelValues("rejected").Set(float64(rejected))
		b.Metrics.lastBuild.SetToCurrentTime()
		b.Metrics.policiesHash.Set(policiesHash(list.Items))
	}
	return nil
}

// policiesHash identifies the objects a snapshot was built from: their
// names, UIDs and generations, which is everything a status write leaves
// alone. Replicas whose caches hold the same policies report the same value
// however long ago each of them built its snapshot, so one that has stopped
// hearing about changes stands out. It is 48 bits, which a float64 gauge
// holds exactly. policies must be sorted by name.
func policiesHash(policies []v1alpha1.EgressRoutePolicy) float64 {
	h := fnv.New64a()
	for i := range policies {
		p := &policies[i]
		// Neither a name nor a UID contains a NUL.
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00", p.Name, p.UID, p.Generation)
	}
	return float64(h.Sum64() >> 16)
}

// SnapshotMetrics describe the snapshot in effect.
type SnapshotMetrics struct {
	generation   prometheus.Gauge
	policies     *prometheus.GaugeVec
	lastBuild    prometheus.Gauge
	policiesHash prometheus.Gauge
}

// NewSnapshotMetrics registers the snapshot metrics with reg.
func NewSnapshotMetrics(reg prometheus.Registerer) *SnapshotMetrics {
	m := &SnapshotMetrics{
		generation: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ategress_snapshot_generation",
			Help: "Snapshots built since the process started; the one in effect.",
		}),
		policies: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ategress_policies",
			Help: "EgressRoutePolicy objects in the snapshot in effect, by state (accepted, rejected).",
		}, []string{"state"}),
		lastBuild: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ategress_snapshot_last_build_timestamp_seconds",
			Help: "When the snapshot in effect was built, in seconds since the epoch; 0 before the first.",
		}),
		policiesHash: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ategress_snapshot_policies_hash",
			Help: "Hash of the names, UIDs and generations of the EgressRoutePolicy objects the snapshot in effect was built from. Replicas serving the same policies report the same value.",
		}),
	}
	reg.MustRegister(m.generation, m.policies, m.lastBuild, m.policiesHash)
	return m
}
