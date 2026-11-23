package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/api/v1beta1"
)

// These tests cover the API as its users see it once v1beta1 is served.
// ate-gress itself reads and writes v1alpha1 only, so the manager's scheme
// does not know v1beta1; the tests reach it through a client of their own.

func betaClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl, err := client.New(needEnvtest(t).env.Config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// asMap returns v as the JSON object it marshals to, so that values of the
// two versions' types compare.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestV1beta1PolicyTakesEffect checks that a policy written as v1beta1
// reaches the snapshot and gets its status, though both controllers watch
// v1alpha1, and that it reads back the same under both versions.
func TestV1beta1PolicyTakesEffect(t *testing.T) {
	tc := needEnvtest(t)
	ctx := t.Context()
	beta := betaClient(t)
	store, _ := startManager(t)

	// Every field is set, so a field missing from either version would show.
	p := &v1beta1.EgressRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "written-as-v1beta1"},
		Spec: v1beta1.EgressRoutePolicySpec{
			EnforcementMode: v1beta1.EnforcementModeEnforce,
			ActorSelector:   v1beta1.ActorSelector{Atespaces: []string{"research"}, Names: []string{"agent-*"}},
			LogAllowed:      true,
			Hosts: []v1beta1.HostRoutes{{Host: "api.github.com", Routes: []v1beta1.Route{{
				Methods: []v1beta1.Method{"GET"}, Paths: []string{"/repos/acme/*", "/v2/"}, CaseInsensitive: true,
			}}}},
		},
	}
	if err := beta.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = beta.Delete(context.Background(), p) })

	eventually(t, "the v1beta1 policy to deny another org", func() bool { return !allowed(store, "/repos/evil/widget") })
	if !allowed(store, "/repos/acme/widget") {
		t.Error("the v1beta1 policy's route is not allowed")
	}

	var asBeta v1beta1.EgressRoutePolicy
	eventually(t, "Accepted=True, read as v1beta1", func() bool {
		if err := beta.Get(ctx, client.ObjectKeyFromObject(p), &asBeta); err != nil {
			return false
		}
		c := meta.FindStatusCondition(asBeta.Status.Conditions, v1beta1.ConditionAccepted)
		return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == 1
	})
	var asAlpha v1alpha1.EgressRoutePolicy
	if err := tc.cl.Get(ctx, client.ObjectKeyFromObject(p), &asAlpha); err != nil {
		t.Fatal(err)
	}
	if asAlpha.UID != asBeta.UID || asAlpha.ResourceVersion != asBeta.ResourceVersion || asAlpha.Generation != asBeta.Generation {
		t.Errorf("the two versions are not the same object: v1alpha1 %s/%s/%d, v1beta1 %s/%s/%d",
			asAlpha.UID, asAlpha.ResourceVersion, asAlpha.Generation, asBeta.UID, asBeta.ResourceVersion, asBeta.Generation)
	}
	if got, want := asMap(t, asAlpha.Spec), asMap(t, p.Spec); !reflect.DeepEqual(got, want) {
		t.Errorf("spec read as v1alpha1 = %v, written as v1beta1 = %v", got, want)
	}
	if got, want := asMap(t, asBeta.Spec), asMap(t, p.Spec); !reflect.DeepEqual(got, want) {
		t.Errorf("spec read as v1beta1 = %v, written = %v", got, want)
	}
	if got, want := asMap(t, asAlpha.Status), asMap(t, asBeta.Status); !reflect.DeepEqual(got, want) {
		t.Errorf("status read as v1alpha1 = %v, as v1beta1 = %v", got, want)
	}

	// An edit through v1alpha1 of an object created as v1beta1.
	setPaths(t, &asAlpha, "/repos/evil/*")
	eventually(t, "the v1alpha1 edit to swap the allowed org", func() bool {
		return allowed(store, "/repos/evil/widget") && !allowed(store, "/repos/acme/widget")
	})
}

// TestSchemaRejectsV1beta1 checks that v1beta1 validates as v1alpha1 does: a
// rule missing from it would let through a policy every replica then rejects.
// TestVersionsAreIdentical in api/ compares the schemas; this is the API
// server applying one.
func TestSchemaRejectsV1beta1(t *testing.T) {
	needEnvtest(t)
	beta := betaClient(t)
	for name, paths := range map[string][]string{
		"double star not last": {"/repos/**/acme"},
		"dot-dot":              {"/repos/../acme"},
		"percent":              {"/repos/acme%2F"},
	} {
		t.Run(name, func(t *testing.T) {
			p := &v1beta1.EgressRoutePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "beta-schema-reject"},
				Spec: v1beta1.EgressRoutePolicySpec{Hosts: []v1beta1.HostRoutes{{Host: "api.github.com", Routes: []v1beta1.Route{{
					Methods: []v1beta1.Method{"GET"}, Paths: paths,
				}}}}},
			}
			if err := beta.Create(t.Context(), p); err == nil {
				_ = beta.Delete(context.Background(), p)
				t.Fatal("the API server accepted the policy as v1beta1")
			}
		})
	}
}

// TestDiscovery pins what clients that name no version get.
func TestDiscovery(t *testing.T) {
	tc := needEnvtest(t)
	dc, err := discovery.NewDiscoveryClientForConfig(tc.env.Config)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := dc.ServerGroups()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(groups.Groups, func(g metav1.APIGroup) bool { return g.Name == v1alpha1.GroupVersion.Group })
	if i < 0 {
		t.Fatalf("group %s is not served", v1alpha1.GroupVersion.Group)
	}
	// The API server orders versions by maturity, not by their order in the
	// CRD or by which is stored. So `kubectl get egressroutepolicies -o yaml`
	// prints v1beta1 from the release that first serves it, for every
	// policy, including those written as v1alpha1.
	if got := groups.Groups[i].PreferredVersion.Version; got != "v1beta1" {
		t.Errorf("preferred version = %s, want v1beta1", got)
	}

	for _, gv := range []string{v1alpha1.GroupVersion.String(), v1beta1.GroupVersion.String()} {
		resources, err := dc.ServerResourcesForGroupVersion(gv)
		if err != nil {
			t.Fatalf("%s: %v", gv, err)
		}
		byName := map[string]metav1.APIResource{}
		for _, r := range resources.APIResources {
			byName[r.Name] = r
		}
		r, ok := byName["egressroutepolicies"]
		if !ok || r.Namespaced || r.Kind != "EgressRoutePolicy" || !slices.Contains(r.ShortNames, "erp") {
			t.Errorf("%s: resource = %+v, want cluster-scoped EgressRoutePolicy with short name erp", gv, r)
		}
		if _, ok := byName["egressroutepolicies/status"]; !ok {
			t.Errorf("%s: no status subresource", gv)
		}
	}
}

// TestPrinterColumns checks that `kubectl get` shows the same columns
// whichever version it asks for.
func TestPrinterColumns(t *testing.T) {
	tc := needEnvtest(t)
	ctx := t.Context()
	p := githubPolicy("printer-columns", "/repos/acme/*")
	p.Spec.EnforcementMode = v1alpha1.EnforcementModeAudit
	if err := tc.cl.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tc.cl.Delete(context.Background(), p) })

	dc, err := discovery.NewDiscoveryClientForConfig(tc.env.Config)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v1alpha1", "v1beta1"} {
		body, err := dc.RESTClient().Get().
			AbsPath("/apis", v1alpha1.GroupVersion.Group, version, "egressroutepolicies", p.Name).
			// What kubectl sends to get a table.
			SetHeader("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io").
			DoRaw(ctx)
		if err != nil {
			t.Fatalf("%s: %v: %s", version, err, body)
		}
		var table metav1.Table
		if err := json.Unmarshal(body, &table); err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		var columns []string
		for _, c := range table.ColumnDefinitions {
			columns = append(columns, c.Name)
		}
		if want := []string{"Name", "Mode", "Accepted", "Age"}; !slices.Equal(columns, want) {
			t.Errorf("%s: columns = %v, want %v", version, columns, want)
		}
		if len(table.Rows) != 1 || len(table.Rows[0].Cells) < 2 || table.Rows[0].Cells[1] != "Audit" {
			t.Errorf("%s: rows = %+v, want one with Mode Audit", version, table.Rows)
		}
	}
}

// TestReapplyingV1alpha1IsANoOp checks that a GitOps tool whose manifests
// still say v1alpha1 neither fights nor rewrites policies once v1beta1 is
// served and preferred: its server-side apply changes nothing, so it sees no
// diff, the generation does not move, and no replica rebuilds its snapshot.
func TestReapplyingV1alpha1IsANoOp(t *testing.T) {
	tc := needEnvtest(t)
	ctx := t.Context()
	// No manager runs here: a status write would change the resourceVersion
	// the test compares.
	manifest := func(version string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": v1alpha1.GroupVersion.Group + "/" + version,
			"kind":       "EgressRoutePolicy",
			"metadata":   map[string]any{"name": "reapplied"},
			// enforcementMode is left out, as most manifests leave it, so the
			// API server's default is part of what must not show as a diff.
			"spec": map[string]any{
				"hosts": []any{map[string]any{
					"host":   "api.github.com",
					"routes": []any{map[string]any{"methods": []any{"GET"}, "paths": []any{"/repos/acme/*"}}},
				}},
			},
		}}
	}
	apply := func(version string, opts ...client.ApplyOption) *unstructured.Unstructured {
		t.Helper()
		u := manifest(version)
		opts = append([]client.ApplyOption{client.FieldOwner("gitops")}, opts...)
		if err := tc.cl.Apply(ctx, client.ApplyConfigurationFromUnstructured(u), opts...); err != nil {
			t.Fatalf("applying as %s: %v", version, err)
		}
		return u
	}

	created := apply("v1alpha1")
	t.Cleanup(func() { _ = tc.cl.Delete(context.Background(), created) })

	// A dry run is how a GitOps tool computes its diff.
	for _, opts := range [][]client.ApplyOption{{client.DryRunAll}, nil} {
		again := apply("v1alpha1", opts...)
		if again.GetResourceVersion() != created.GetResourceVersion() || again.GetGeneration() != 1 {
			t.Errorf("re-applying v1alpha1 (options %v) changed the object: resourceVersion %s -> %s, generation %d",
				opts, created.GetResourceVersion(), again.GetResourceVersion(), again.GetGeneration())
		}
		if !reflect.DeepEqual(again.Object["spec"], created.Object["spec"]) {
			t.Errorf("re-applying v1alpha1 (options %v) shows a diff: %v, was %v", opts, again.Object["spec"], created.Object["spec"])
		}
	}

	// The same manifest moved to v1beta1, as a user migrating it would, and
	// then back, as a rollback of the manifests would. Neither may conflict
	// or change the spec.
	for _, version := range []string{"v1beta1", "v1alpha1"} {
		got := apply(version)
		if got.GetGeneration() != 1 {
			t.Errorf("applying as %s changed the spec: generation %d", version, got.GetGeneration())
		}
		if !reflect.DeepEqual(got.Object["spec"], created.Object["spec"]) {
			t.Errorf("applying as %s: spec = %v, was %v", version, got.Object["spec"], created.Object["spec"])
		}
	}
}
