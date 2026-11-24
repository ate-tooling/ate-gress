// Package chart checks what the Helm chart renders. It needs helm, as
// `make lint` does.
package chart

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"

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

var update = flag.Bool("update", false, "rewrite testdata/default.yaml from what the chart renders")

// renderErr runs `helm template` and returns its error output, for values the
// chart must refuse.
func renderErr(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("helm", append([]string{"template", "ate-gress", chartDir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("helm template %v succeeded; want it refused", args)
	}
	return string(out)
}

// TestDefaultsUnchanged pins what the chart renders with default values,
// byte for byte, CRDs aside. Every option the chart has beyond the
// deployment it always had is off by default; turning one on must not leak
// into the default install. After an intended change, rerun with -update and
// review the diff.
func TestDefaultsUnchanged(t *testing.T) {
	cmd := exec.Command("helm", "template", "ate-gress", chartDir, "--namespace", "ate-gress", "--set", "crds.install=false")
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template: %v", err)
	}
	golden := filepath.Join("testdata", "default.yaml")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("default render differs from %s; if that is intended, run go test ./test/chart -update and review the diff", golden)
	}
}

func TestOptionalResourcesOffByDefault(t *testing.T) {
	byKind := render(t)
	for _, kind := range []string{"PodMonitor", "ServiceMonitor", "PrometheusRule", "ConfigMap", "HorizontalPodAutoscaler"} {
		if n := len(byKind[kind]); n != 0 {
			t.Errorf("defaults render %d %s", n, kind)
		}
	}
	if n := len(byKind["ClusterRole"]); n != 1 {
		t.Errorf("defaults render %d ClusterRoles, want ate-gress's own", n)
	}
}

func TestPodMonitor(t *testing.T) {
	byKind := render(t, "--namespace", "ate-gress",
		"--set", "podMonitor.enabled=true", "--set", "podMonitor.labels.release=kube-prometheus-stack",
		"--set", "podMonitor.interval=15s", "--set", "metrics.scrapeAnnotations=false")
	pm := one(t, byKind, "PodMonitor")
	if got := dig(pm, "metadata", "labels", "release"); got != "kube-prometheus-stack" {
		t.Errorf("PodMonitor label release = %v", got)
	}
	// The selector must select the pods, and the port must be one they name.
	pod := dig(one(t, byKind, "Deployment"), "spec", "template").(map[string]any)
	podLabels := dig(pod, "metadata", "labels").(map[string]any)
	for k, v := range dig(pm, "spec", "selector", "matchLabels").(map[string]any) {
		if podLabels[k] != v {
			t.Errorf("PodMonitor selects %s=%v, which the pods do not carry", k, v)
		}
	}
	endpoint := dig(pm, "spec", "podMetricsEndpoints").([]any)[0].(map[string]any)
	if endpoint["interval"] != "15s" {
		t.Errorf("interval = %v", endpoint["interval"])
	}
	var ports []any
	for _, c := range dig(pod, "spec", "containers").([]any) {
		for _, p := range c.(map[string]any)["ports"].([]any) {
			ports = append(ports, p.(map[string]any)["name"])
		}
	}
	if !slices.Contains(ports, endpoint["port"]) {
		t.Errorf("PodMonitor scrapes port %v; the container names %v", endpoint["port"], ports)
	}
	if got := dig(pm, "spec", "namespaceSelector", "matchNames"); !reflect.DeepEqual(got, []any{"ate-gress"}) {
		t.Errorf("namespaceSelector = %v", got)
	}
	if a := dig(pod, "metadata", "annotations"); a != nil {
		t.Errorf("scrapeAnnotations=false still renders pod annotations %v", a)
	}

	// The NetworkPolicy must let the scrape in: with metricsFrom empty, the
	// metrics port is open to every peer.
	for _, rule := range dig(one(t, byKind, "NetworkPolicy"), "spec", "ingress").([]any) {
		r := rule.(map[string]any)
		if dig(r, "ports").([]any)[0].(map[string]any)["port"] == "metrics" && r["from"] != nil {
			t.Errorf("with metricsFrom empty, the metrics port admits only %v", r["from"])
		}
	}
}

func TestMetricsFromAdmitsListedPeers(t *testing.T) {
	byKind := render(t, "--set", "networkPolicy.metricsFrom[0].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=monitoring")
	for _, rule := range dig(one(t, byKind, "NetworkPolicy"), "spec", "ingress").([]any) {
		r := rule.(map[string]any)
		if dig(r, "ports").([]any)[0].(map[string]any)["port"] != "metrics" {
			continue
		}
		from := r["from"].([]any)
		if got := dig(from[0].(map[string]any), "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); got != "monitoring" {
			t.Errorf("metrics peers = %v", from)
		}
		return
	}
	t.Fatal("no ingress rule for the metrics port")
}

// TestPrometheusRule checks the rendered alerts against the runbook: every
// alert links to a section that exists, and every alert can be turned off.
// test/rules/alerts_test.yaml checks what they fire on, with promtool.
func TestPrometheusRule(t *testing.T) {
	pr := one(t, render(t, "--namespace", "ate-gress", "--set", "prometheusRule.enabled=true",
		"--set", "prometheusRule.labels.release=kube-prometheus-stack",
		"--set", "prometheusRule.additionalLabels.team=egress"), "PrometheusRule")
	runbook, err := os.ReadFile("../../docs/runbook.md")
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	for line := range strings.SplitSeq(string(runbook), "\n") {
		if strings.HasPrefix(line, "#") {
			anchors[githubAnchor(strings.TrimLeft(line, "# "))] = true
		}
	}
	var alerts []string
	for _, g := range dig(pr, "spec", "groups").([]any) {
		for _, r := range g.(map[string]any)["rules"].([]any) {
			rule := r.(map[string]any)
			name := rule["alert"].(string)
			alerts = append(alerts, name)
			url, _ := dig(rule, "annotations", "runbook_url").(string)
			prefix := "https://github.com/ate-tooling/ate-gress/blob/main/docs/runbook.md#"
			if !strings.HasPrefix(url, prefix) || !anchors[strings.TrimPrefix(url, prefix)] {
				t.Errorf("%s: runbook_url %q is not a section of docs/runbook.md", name, url)
			}
			if dig(rule, "labels", "team") != "egress" || dig(rule, "labels", "severity") == nil {
				t.Errorf("%s: labels %v, want severity and the additional labels", name, rule["labels"])
			}
			if !strings.Contains(rule["expr"].(string), `job="ate-gress/ate-gress"`) {
				t.Errorf("%s: expr does not select the PodMonitor's job:\n%s", name, rule["expr"])
			}
		}
	}
	if len(alerts) == 0 {
		t.Fatal("no alerts")
	}

	values := map[string]any{}
	raw, err := os.ReadFile(filepath.Join(chartDir, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	keys := dig(values, "prometheusRule", "alerts").(map[string]any)
	if len(keys) != len(alerts) {
		t.Errorf("values.yaml has %d alerts, the chart renders %d", len(keys), len(alerts))
	}
	for key := range keys {
		off := render(t, "--namespace", "ate-gress", "--set", "prometheusRule.enabled=true", "--set", "prometheusRule.alerts."+key+".enabled=false")
		n := 0
		for _, g := range dig(one(t, off, "PrometheusRule"), "spec", "groups").([]any) {
			n += len(g.(map[string]any)["rules"].([]any))
		}
		if n != len(alerts)-1 {
			t.Errorf("prometheusRule.alerts.%s.enabled=false renders %d alerts, want %d", key, n, len(alerts)-1)
		}
	}
}

func TestPrometheusRuleSelectorAndThresholds(t *testing.T) {
	pr := one(t, render(t, "--set", "prometheusRule.enabled=true", "--set", `prometheusRule.selector=namespace="egress"`,
		"--set", "prometheusRule.alerts.certificateExpiry.thresholdSeconds=900",
		"--set", "prometheusRule.alerts.denyRateHigh.for=30m"), "PrometheusRule")
	found := 0
	for _, g := range dig(pr, "spec", "groups").([]any) {
		for _, r := range g.(map[string]any)["rules"].([]any) {
			rule := r.(map[string]any)
			if !strings.Contains(rule["expr"].(string), `namespace="egress"`) || strings.Contains(rule["expr"].(string), "job=") {
				t.Errorf("%s: selector not applied:\n%s", rule["alert"], rule["expr"])
			}
			switch rule["alert"] {
			case "AteGressCertificateExpiringSoon":
				found++
				if !strings.HasSuffix(rule["expr"].(string), "< 900") {
					t.Errorf("threshold not applied: %s", rule["expr"])
				}
			case "AteGressDenyRateHigh":
				found++
				if rule["for"] != "30m" {
					t.Errorf("for = %v", rule["for"])
				}
			}
		}
	}
	if found != 2 {
		t.Errorf("found %d of the 2 alerts", found)
	}
}

func TestGrafanaDashboard(t *testing.T) {
	cm := one(t, render(t, "--set", "grafanaDashboard.enabled=true", "--set", "grafanaDashboard.annotations.grafana_folder=Egress"), "ConfigMap")
	if dig(cm, "metadata", "labels", "grafana_dashboard") != "1" {
		t.Errorf("no sidecar label: %v", dig(cm, "metadata", "labels"))
	}
	if dig(cm, "metadata", "annotations", "grafana_folder") != "Egress" {
		t.Errorf("annotations = %v", dig(cm, "metadata", "annotations"))
	}
	want, err := os.ReadFile(filepath.Join(chartDir, "files", "dashboards", "ate-gress.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := dig(cm, "data", "ate-gress.json").(string)
	if got != strings.TrimSpace(string(want)) {
		t.Error("the ConfigMap's dashboard is not files/dashboards/ate-gress.json")
	}
	var dashboard struct {
		UID    string `json:"uid"`
		Panels []struct {
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal([]byte(got), &dashboard); err != nil {
		t.Fatalf("dashboard is not JSON: %v", err)
	}
	if dashboard.UID == "" || len(dashboard.Panels) == 0 {
		t.Errorf("dashboard has uid %q and %d panels", dashboard.UID, len(dashboard.Panels))
	}
}

// TestAggregatedClusterRoles checks who may do what: view reads policies,
// admin writes them, and edit gets nothing beyond what view aggregates into
// it. Nobody but ate-gress writes status.
func TestAggregatedClusterRoles(t *testing.T) {
	roles := render(t, "--set", "rbac.aggregateClusterRoles=true")["ClusterRole"]
	writes := map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true}
	var sawView, sawAdmin bool
	for _, role := range roles {
		labels, _ := dig(role, "metadata", "labels").(map[string]any)
		var aggregates []string
		for k := range labels {
			if after, ok := strings.CutPrefix(k, "rbac.authorization.k8s.io/aggregate-to-"); ok {
				aggregates = append(aggregates, after)
			}
		}
		if len(aggregates) == 0 {
			continue
		}
		for _, r := range role["rules"].([]any) {
			rule := r.(map[string]any)
			writesPolicy := false
			for _, v := range rule["verbs"].([]any) {
				writesPolicy = writesPolicy || writes[v.(string)]
			}
			for _, res := range rule["resources"].([]any) {
				if res == "egressroutepolicies/status" && writesPolicy {
					t.Errorf("%v writes policy status", dig(role, "metadata", "name"))
				}
			}
			switch {
			case writesPolicy && (slices.Contains(aggregates, "edit") || slices.Contains(aggregates, "view")):
				t.Errorf("%v gives edit or view write access to policies", dig(role, "metadata", "name"))
			case writesPolicy:
				sawAdmin = slices.Contains(aggregates, "admin")
			default:
				sawView = slices.Contains(aggregates, "view")
			}
		}
	}
	if !sawView || !sawAdmin {
		t.Errorf("view can read: %v; admin can write: %v", sawView, sawAdmin)
	}
}

func TestPodOptions(t *testing.T) {
	dep := one(t, render(t,
		"--set", "podLabels.team=egress", "--set", "podLabels.app\\.kubernetes\\.io/name=other",
		"--set", "podAnnotations.example\\.com/owner=net",
		"--set", "imagePullSecrets[0].name=registry",
		"--set", "topologySpread.zone=true", "--set", "podAntiAffinity.required=true",
		"--set", "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=pool",
		"--set", "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=Exists",
	), "Deployment")
	pod := dig(dep, "spec", "template").(map[string]any)
	if got := dig(pod, "metadata", "labels", "team"); got != "egress" {
		t.Errorf("podLabels not applied: team=%v", got)
	}
	if got := dig(pod, "metadata", "labels", "app.kubernetes.io/name"); got != "ate-gress" {
		t.Errorf("a podLabel replaced the chart's own app.kubernetes.io/name: %v", got)
	}
	annotations := dig(pod, "metadata", "annotations").(map[string]any)
	if annotations["example.com/owner"] != "net" || annotations["prometheus.io/scrape"] != "true" {
		t.Errorf("annotations = %v", annotations)
	}
	if got := dig(pod, "spec", "imagePullSecrets"); !reflect.DeepEqual(got, []any{map[string]any{"name": "registry"}}) {
		t.Errorf("imagePullSecrets = %v", got)
	}
	var keys []any
	for _, c := range dig(pod, "spec", "topologySpreadConstraints").([]any) {
		keys = append(keys, c.(map[string]any)["topologyKey"])
	}
	if !reflect.DeepEqual(keys, []any{"kubernetes.io/hostname", "topology.kubernetes.io/zone"}) {
		t.Errorf("topology spread keys = %v", keys)
	}
	affinity := dig(pod, "spec", "affinity").(map[string]any)
	if affinity["nodeAffinity"] == nil {
		t.Error("affinity.nodeAffinity was dropped")
	}
	terms := dig(affinity, "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution").([]any)
	term := terms[0].(map[string]any)
	if term["topologyKey"] != "kubernetes.io/hostname" ||
		!reflect.DeepEqual(dig(term, "labelSelector", "matchLabels"), dig(dep, "spec", "selector", "matchLabels")) {
		t.Errorf("required anti-affinity term = %v", term)
	}

	if out := renderErr(t, "--set", "podAntiAffinity.required=true", "--set", "affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].weight=1"); !strings.Contains(out, "cannot be combined") {
		t.Errorf("conflicting anti-affinity: %s", out)
	}
}

// TestSchema checks that values.schema.json refuses what the chart cannot
// use, rather than ignoring it.
func TestSchema(t *testing.T) {
	for _, args := range [][]string{
		{"--set", "replica=3"},
		{"--set", "prometheusRule.alerts.down.for=soon"},
		{"--set", "prometheusRule.alerts.latencyHigh.thresholdSeconds=1"},
		{"--set", "prometheusRule.alerts.noSuchAlert.enabled=true"},
		{"--set", "podMonitor.interval=fast"},
		{"--set", "image.digest=latest"},
		{"--set", "gateway.spiffeIDs[0]=atenet-egress"},
		{"--set", "drainDelay=10"},
		{"--set", "imagePullSecrets[0].secret=x"},
	} {
		if out := renderErr(t, args...); !strings.Contains(out, "values don't meet the specifications of the schema") {
			t.Errorf("%v: refused, but not by the schema: %s", args, out)
		}
	}
}

func one(t *testing.T, byKind map[string][]map[string]any, kind string) map[string]any {
	t.Helper()
	if n := len(byKind[kind]); n != 1 {
		t.Fatalf("rendered %d %s, want 1", n, kind)
	}
	return byKind[kind][0]
}

// dig walks nested maps, returning nil where a key is missing.
func dig(obj any, keys ...string) any {
	for _, k := range keys {
		m, ok := obj.(map[string]any)
		if !ok {
			return nil
		}
		obj = m[k]
	}
	return obj
}

// githubAnchor is the fragment GitHub gives a Markdown heading.
func githubAnchor(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}
