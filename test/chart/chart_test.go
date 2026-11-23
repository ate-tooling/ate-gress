// Package chart checks what the Helm chart renders. It needs helm, as
// `make lint` does.
package chart

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const (
	chartDir = "../../charts/ate-gress"
	crdDir   = "../../config/crd"
)

// render returns the documents `helm template` produces, by kind.
func render(t *testing.T, args ...string) map[string][]map[string]any {
	t.Helper()
	cmd := exec.Command("helm", append([]string{"template", "ate-gress", chartDir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, stderr.String())
	}
	byKind := map[string][]map[string]any{}
	for doc := range strings.SplitSeq(string(out), "\n---\n") {
		var obj map[string]any
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("rendered document is not YAML: %v\n%s", err, doc)
		}
		if kind, _ := obj["kind"].(string); kind != "" {
			byKind[kind] = append(byKind[kind], obj)
		}
	}
	return byKind
}

// TestCRDsMatchGenerated checks that the chart installs exactly the CRDs
// controller-gen wrote, plus the annotation that keeps them on uninstall. The
// template is a copy of config/crd passed through Helm's template engine; if
// Helm changed anything in it, the cluster's schema would differ from the one
// the tests and the fuzzer check.
func TestCRDsMatchGenerated(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(crdDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no CRDs in %s: %v", crdDir, err)
	}
	want := map[string]map[string]any{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var crd map[string]any
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		want[crd["metadata"].(map[string]any)["name"].(string)] = crd
	}

	rendered := render(t)["CustomResourceDefinition"]
	if len(rendered) != len(want) {
		t.Fatalf("chart renders %d CRDs, config/crd has %d", len(rendered), len(want))
	}
	for _, got := range rendered {
		meta := got["metadata"].(map[string]any)
		name := meta["name"].(string)
		annotations := meta["annotations"].(map[string]any)
		if annotations["helm.sh/resource-policy"] != "keep" {
			t.Errorf("%s: no helm.sh/resource-policy: keep; uninstalling would delete every policy", name)
		}
		delete(annotations, "helm.sh/resource-policy")
		if !reflect.DeepEqual(got, want[name]) {
			t.Errorf("%s: the chart's CRD differs from config/crd; run `make generate`", name)
		}
	}
}

func TestCRDsCanBeLeftOut(t *testing.T) {
	if crds := render(t, "--set", "crds.install=false")["CustomResourceDefinition"]; len(crds) != 0 {
		t.Fatalf("crds.install=false still renders %d CRDs", len(crds))
	}
}
