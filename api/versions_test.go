// Package api_test checks what the generated CRD says about its versions.
package api_test

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const crdFile = "../config/crd/ategress.ate-tooling.github.io_egressroutepolicies.yaml"

func loadCRD(t *testing.T) (spec map[string]any, versions map[string]map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(crdFile)
	if err != nil {
		t.Fatal(err)
	}
	var crd struct {
		Spec map[string]any `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	versions = map[string]map[string]any{}
	for _, v := range crd.Spec["versions"].([]any) {
		v := v.(map[string]any)
		versions[v["name"].(string)] = v
	}
	return crd.Spec, versions
}

// TestVersionsAreIdentical fails when v1alpha1 and v1beta1 differ in anything
// but their name and which of them is stored.
//
// The CRD has no conversion webhook: the API server serves a stored object as
// either version by rewriting its apiVersion and nothing else. So a field in
// only one schema is pruned, without an error, from an object written through
// the other, and a validation rule in only one is bypassed by writing through
// the other. If the versions must diverge, that needs a conversion webhook,
// and this test changed on purpose.
func TestVersionsAreIdentical(t *testing.T) {
	_, versions := loadCRD(t)
	alpha, beta := versions["v1alpha1"], versions["v1beta1"]
	if alpha == nil || beta == nil || len(versions) != 2 {
		t.Fatalf("the CRD has versions %v, want v1alpha1 and v1beta1", keys(versions))
	}
	// Everything else is compared: the schema, the printer columns, the
	// subresources, and any deprecation.
	for _, v := range []map[string]any{alpha, beta} {
		delete(v, "name")
		delete(v, "storage")
	}
	if reflect.DeepEqual(alpha, beta) {
		return
	}
	for _, k := range keys(alpha, beta) {
		if !reflect.DeepEqual(alpha[k], beta[k]) {
			t.Errorf("v1alpha1 and v1beta1 differ in %q", k)
		}
	}
	t.Error("the two versions must be the same: copy the change to the other version's types and run `make generate`")
}

// TestTypesAreCopies gives the plainer failure for the usual mistake, an edit
// to one version's types and not the other's. It also covers what the schema
// does not show, such as constants.
func TestTypesAreCopies(t *testing.T) {
	read := func(version string) string {
		raw, err := os.ReadFile(version + "/egressroutepolicy_types.go")
		if err != nil {
			t.Fatal(err)
		}
		src := strings.Replace(string(raw), "package "+version+"\n", "package api\n", 1)
		// One version is stored, so one file has the marker.
		return strings.Replace(src, "// +kubebuilder:storageversion\n", "", 1)
	}
	if read("v1alpha1") != read("v1beta1") {
		t.Error("api/v1alpha1/egressroutepolicy_types.go and api/v1beta1/egressroutepolicy_types.go must differ only in their package and the storageversion marker; `diff` them")
	}
}

// TestStorageVersion pins the two properties a rollback depends on.
func TestStorageVersion(t *testing.T) {
	spec, versions := loadCRD(t)
	for name, v := range versions {
		if v["served"] != true {
			t.Errorf("%s is not served; manifests and clients that use it would stop working", name)
		}
		// While v1alpha1 is the only version objects were ever stored in, the
		// API server accepts a rollback to a chart whose CRD has only
		// v1alpha1. Storing v1beta1 ends that for good, so it belongs in a
		// later release than the one that first serves it. docs/design.md
		// has the plan.
		if want := name == "v1alpha1"; v["storage"] != want {
			t.Errorf("%s has storage: %v, want %v", name, v["storage"], want)
		}
	}
	// Absent means None. A webhook here would make every read and write of a
	// policy depend on that webhook being up.
	if conv, ok := spec["conversion"].(map[string]any); ok && conv["strategy"] != "None" {
		t.Errorf("conversion strategy is %v, want None", conv["strategy"])
	}
}

// keys returns the sorted union of the maps' keys.
func keys[V any](ms ...map[string]V) []string {
	var out []string
	for _, m := range ms {
		for k := range m {
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}
