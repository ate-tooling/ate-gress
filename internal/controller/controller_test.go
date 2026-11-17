package controller

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/samueltorres/ate-gress/api/v1alpha1"
	"github.com/samueltorres/ate-gress/internal/identity"
	"github.com/samueltorres/ate-gress/internal/policy"
)

var (
	testCfg    *envtestConfig
	testScheme = runtime.NewScheme()
)

type envtestConfig struct {
	env *envtest.Environment
	cl  client.Client
}

func TestMain(m *testing.M) {
	if err := clientgoscheme.AddToScheme(testScheme); err != nil {
		panic(err)
	}
	if err := v1alpha1.AddToScheme(testScheme); err != nil {
		panic(err)
	}
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Unit tests that need no API server still run; the envtest ones skip.
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
	cl, err := client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		panic(err)
	}
	testCfg = &envtestConfig{env: env, cl: cl}
	code := m.Run()
	if err := env.Stop(); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func needEnvtest(t *testing.T) *envtestConfig {
	t.Helper()
	if testCfg == nil {
		t.Skip("KUBEBUILDER_ASSETS is not set; run through `make test`")
	}
	return testCfg
}

// startManager runs a manager with both controllers, as main does, and
// returns the store it fills.
func startManager(t *testing.T) (*policy.Store, <-chan struct{}) {
	t.Helper()
	tc := needEnvtest(t)
	mgr, err := ctrl.NewManager(tc.env.Config, ctrl.Options{
		Scheme:  testScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Each test starts its own manager, registering the same controller
		// name again in this process.
		Controller: config.Controller{SkipNameValidation: new(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &policy.Store{}
	ready := make(chan struct{})
	if err := mgr.Add(&SnapshotBuilder{
		Cache: mgr.GetCache(), Store: store, Log: slog.New(slog.DiscardHandler),
		Metrics:         NewSnapshotMetrics(prometheus.NewRegistry()),
		OnFirstSnapshot: func() { close(ready) },
	}); err != nil {
		t.Fatal(err)
	}
	if err := (&StatusReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager: %v", err)
		}
	})
	return store, ready
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		<-tick.C
	}
}

func githubPolicy(name string, paths ...string) *v1alpha1.EgressRoutePolicy {
	return &v1alpha1.EgressRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.EgressRoutePolicySpec{
			ActorSelector: v1alpha1.ActorSelector{Atespaces: []string{"research"}},
			Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
				Methods: []v1alpha1.Method{"GET"}, Paths: paths,
			}}}},
		},
	}
}

// setPaths replaces p's paths, retrying when the status writer has updated p
// since it was read.
func setPaths(t *testing.T, p *v1alpha1.EgressRoutePolicy, paths ...string) {
	t.Helper()
	tc := needEnvtest(t)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := tc.cl.Get(t.Context(), client.ObjectKeyFromObject(p), p); err != nil {
			return err
		}
		p.Spec.Hosts[0].Routes[0].Paths = paths
		return tc.cl.Update(t.Context(), p)
	})
	if err != nil {
		t.Fatal(err)
	}
}

var researcher = identity.Actor{Atespace: "research", Name: "agent-1"}

func allowed(store *policy.Store, path string) bool {
	snap := store.Load()
	return snap != nil && snap.Decide(policy.Request{Actor: researcher, Method: "GET", Authority: "api.github.com", Path: path}).Allowed
}

func TestSnapshotFollowsPolicies(t *testing.T) {
	tc := needEnvtest(t)
	ctx := t.Context()
	store, ready := startManager(t)

	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("no first snapshot, though the cache syncs with no policies")
	}
	if !allowed(store, "/repos/acme/widget") {
		t.Fatal("with no policies, the host should be unclaimed and allowed")
	}

	p := githubPolicy("snapshot-follows", "/repos/acme/*")
	if err := tc.cl.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tc.cl.Delete(context.Background(), p) })
	eventually(t, "the policy to deny another org", func() bool { return !allowed(store, "/repos/evil/widget") })
	if !allowed(store, "/repos/acme/widget") {
		t.Error("the policy's route is not allowed")
	}

	setPaths(t, p, "/repos/evil/*")
	eventually(t, "the update to swap the allowed org", func() bool {
		return allowed(store, "/repos/evil/widget") && !allowed(store, "/repos/acme/widget")
	})

	if err := tc.cl.Delete(ctx, p); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the deletion to unclaim the host", func() bool { return allowed(store, "/repos/acme/widget") })
}

func TestStatusAccepted(t *testing.T) {
	tc := needEnvtest(t)
	ctx := t.Context()
	startManager(t)

	p := githubPolicy("status-accepted", "/orgs/acme")
	if err := tc.cl.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tc.cl.Delete(context.Background(), p) })
	accepted := func(gen int64) func() bool {
		return func() bool {
			var got v1alpha1.EgressRoutePolicy
			if err := tc.cl.Get(ctx, client.ObjectKeyFromObject(p), &got); err != nil {
				return false
			}
			c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionAccepted)
			return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == gen && got.Status.ObservedGeneration == gen
		}
	}
	eventually(t, "Accepted=True for generation 1", accepted(1))

	setPaths(t, p, "/orgs/acme", "/orgs/acme/**")
	eventually(t, "Accepted=True for generation 2", accepted(2))
}

// TestSchemaRejects checks that the CRD's schema and CEL rules refuse at
// admission what the compiler would reject, so a bad policy never reaches the
// cluster at all.
func TestSchemaRejects(t *testing.T) {
	tc := needEnvtest(t)
	tests := []struct {
		name   string
		mutate func(*v1alpha1.EgressRoutePolicy)
	}{
		{"no hosts", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts = nil }},
		{"uppercase host", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Host = "API.github.com" }},
		{"host with port", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Host = "api.github.com:443" }},
		{"wildcard host", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Host = "*.github.com" }},
		{"duplicate host", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts = append(p.Spec.Hosts, p.Spec.Hosts[0]) }},
		{"bad mode", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.EnforcementMode = "Permissive" }},
		{"lowercase method", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Methods = []v1alpha1.Method{"get"} }},
		{"no methods", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Methods = nil }},
		{"no paths", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = nil }},
		{"relative path", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"repos/acme"} }},
		{"double slash", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos//acme"} }},
		{"trailing slash", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/acme/"} }},
		{"dot-dot", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/../acme"} }},
		{"dot", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/./acme"} }},
		{"percent", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/acme%2F"} }},
		{"double star not last", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/**/acme"} }},
		{"embedded star", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/ac*"} }},
		{"leading embedded star", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/*cme"} }},
		{"triple star", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/***"} }},
		{"query in path", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.Hosts[0].Routes[0].Paths = []string{"/repos/acme?x=1"} }},
		{"uppercase glob", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.ActorSelector.Atespaces = []string{"Research"} }},
		{"glob with slash", func(p *v1alpha1.EgressRoutePolicy) { p.Spec.ActorSelector.Names = []string{"a/b"} }},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := githubPolicy("schema-reject-"+strings.Repeat("x", i+1), "/repos/acme/*")
			tt.mutate(p)
			if err := tc.cl.Create(t.Context(), p); err == nil {
				_ = tc.cl.Delete(context.Background(), p)
				t.Fatal("the API server accepted the policy")
			}
			// Whatever the schema lets through, the compiler must reject too:
			// both layers have to agree for a rejection to be meaningful.
			if _, results := policy.Compile([]v1alpha1.EgressRoutePolicy{*p}); results[0].Err == nil {
				t.Errorf("the compiler accepts a policy the schema rejects")
			}
		})
	}

	t.Run("lockdown with no routes is valid", func(t *testing.T) {
		p := &v1alpha1.EgressRoutePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "schema-lockdown"},
			Spec:       v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com"}}},
		}
		if err := tc.cl.Create(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		_ = tc.cl.Delete(context.Background(), p)
	})
}

// TestStatusRejected runs the reconciler against a fake client, because a
// policy the compiler rejects cannot get past the CRD schema.
func TestStatusRejected(t *testing.T) {
	p := githubPolicy("bad", "/a/**/b")
	p.Generation = 3
	cl := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(p).WithStatusSubresource(p).Build()
	r := &StatusReconciler{Client: cl}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}); err != nil {
		t.Fatal(err)
	}
	var got v1alpha1.EgressRoutePolicy
	if err := cl.Get(t.Context(), client.ObjectKeyFromObject(p), &got); err != nil {
		t.Fatal(err)
	}
	c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionAccepted)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonInvalid || c.ObservedGeneration != 3 {
		t.Fatalf("Accepted condition = %+v, want False/Invalid at generation 3", c)
	}
	if !strings.Contains(c.Message, `"**" must be the last segment`) {
		t.Errorf("message %q does not say what is wrong", c.Message)
	}

	// A second reconcile with nothing changed writes nothing.
	rv := got.ResourceVersion
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(t.Context(), client.ObjectKeyFromObject(p), &got); err != nil {
		t.Fatal(err)
	}
	if got.ResourceVersion != rv {
		t.Error("an unchanged status was rewritten")
	}
}
