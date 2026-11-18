//go:build envoy

// Package envoy runs ate-gress behind a real Envoy configured as Substrate's
// egress gateway calls it, to pin what unit tests can only assume: the
// attribute key and encoding, the header encoding, mutual TLS with the
// gateway's certificates, and that Envoy fails closed when ate-gress is gone.
//
// It needs Docker, and runs through `make test-envoy`.
package envoy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/extproc"
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/testpki"
	"github.com/ate-tooling/ate-gress/internal/tlsconfig"
)

const (
	serverName = "ate-gress.ate-gress.svc"
	envoyID    = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
	research   = "spiffe://substrate-actor.local/worker-for-actor/research/agent-1"
	billing    = "spiffe://substrate-actor.local/worker-for-actor/billing/agent-1"
)

func policies() []v1alpha1.EgressRoutePolicy {
	return []v1alpha1.EgressRoutePolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "github-lockdown"},
			Spec:       v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com"}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "github-acme"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				ActorSelector: v1alpha1.ActorSelector{Atespaces: []string{"research"}},
				Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
					Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/repos/acme/*", "/repos/acme/*/**"}, CaseInsensitive: true,
				}}}},
			},
		},
	}
}

func TestEnvoy(t *testing.T) {
	image := os.Getenv("ATEGRESS_ENVOY_IMAGE")
	if image == "" {
		image = "envoyproxy/envoy:v1.39.5"
	}
	dir := t.TempDir()
	podidentity := mkdir(t, dir, "podidentity.podcert.ate.dev")
	servicedns := mkdir(t, dir, "servicedns.podcert.ate.dev")
	etc := mkdir(t, dir, "envoy")

	// Envoy's side: its podidentity client certificate, and the servicedns
	// trust bundle it verifies ate-gress against.
	servicednsCA, podidentityCA := testpki.NewCA(t, "servicedns"), testpki.NewCA(t, "podidentity")
	readable(t, testpki.WriteFile(t, podidentity, "credential-bundle.pem", podidentityCA.Client(t, envoyID).Bundle(t)))
	readable(t, testpki.WriteFile(t, servicedns, "trust-bundle.pem", servicednsCA.PEM()))
	sdsDir := filepath.Join(repoRoot(t), "test", "envoy")
	for _, f := range []string{"sds-podidentity-cert.yaml", "sds-servicedns-validation.yaml"} {
		copyFile(t, filepath.Join(sdsDir, f), filepath.Join(etc, f))
	}

	// ate-gress's side, served on the Docker host.
	lis, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := tlsconfig.Server(tlsconfig.Config{
		CredentialBundle: testpki.WriteFile(t, dir, "serving.pem", servicednsCA.Serving(t, serverName).Bundle(t)),
		ClientCAs:        testpki.WriteFile(t, dir, "clients.pem", podidentityCA.PEM()),
		AllowedClientIDs: []string{envoyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &policy.Store{}
	snap, results := policy.Compile(policies())
	for _, r := range results {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	store.Swap(snap)
	parser, err := identity.NewParser(identity.DefaultTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	gs, _ := extproc.NewGRPCServer(tlsCfg, extproc.NewServer(store, parser, log, extproc.NewMetrics(prometheus.NewRegistry())))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	cfg, err := os.ReadFile(filepath.Join(sdsDir, "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(lis.Addr().(*net.TCPAddr).Port)
	readable(t, writeFile(t, filepath.Join(etc, "envoy.yaml"), bytes.ReplaceAll(cfg, []byte("@EXTPROC_PORT@"), []byte(port))))

	base := runEnvoy(t, image, etc, podidentity, servicedns)

	tests := []struct {
		name, actor, method, host, path string
		wantStatus                      int
		wantReason                      string
	}{
		{name: "allowed", actor: research, method: "GET", host: "api.github.com", path: "/repos/acme/widget", wantStatus: 200},
		{name: "allowed with query and case", actor: research, method: "GET", host: "api.github.com", path: "/repos/ACME/widget/contents/x?ref=main", wantStatus: 200},
		{name: "unclaimed host", actor: research, method: "POST", host: "pypi.org", path: "/legacy/", wantStatus: 200},
		{name: "other org", actor: research, method: "GET", host: "api.github.com", path: "/repos/other/widget", wantStatus: 403, wantReason: "no_route"},
		{name: "graphql", actor: research, method: "POST", host: "api.github.com", path: "/graphql", wantStatus: 403, wantReason: "no_route"},
		{name: "write", actor: research, method: "DELETE", host: "api.github.com", path: "/repos/acme/widget", wantStatus: 403, wantReason: "no_route"},
		{name: "encoded traversal", actor: research, method: "GET", host: "api.github.com", path: "/repos/acme/x/..%2f..%2fother", wantStatus: 403, wantReason: "path"},
		{name: "dot-dot", actor: research, method: "GET", host: "api.github.com", path: "/repos/acme/x/../../other/y", wantStatus: 403, wantReason: "path"},
		{name: "authority with port", actor: research, method: "GET", host: "api.github.com:443", path: "/repos/other/widget", wantStatus: 403, wantReason: "no_route"},
		{name: "locked-out atespace", actor: billing, method: "GET", host: "api.github.com", path: "/repos/acme/widget", wantStatus: 403, wantReason: "no_route"},
		{name: "no identity", method: "GET", host: "api.github.com", path: "/repos/acme/widget", wantStatus: 403, wantReason: "identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, reason, body := send(t, base, tt.method, tt.host, tt.path, tt.actor)
			if status != tt.wantStatus || reason != tt.wantReason {
				t.Errorf("got %d (reason %q, body %q), want %d (reason %q)", status, reason, body, tt.wantStatus, tt.wantReason)
			}
			if status == 200 && body != "upstream" {
				t.Errorf("allowed request did not reach the upstream: body %q", body)
			}
		})
	}
	if !strings.Contains(logs.String(), `"actor":"research/agent-1"`) {
		t.Errorf("ate-gress did not see the actor identity Envoy attached:\n%s", logs.String())
	}

	t.Run("fails closed without ate-gress", func(t *testing.T) {
		gs.Stop()
		status, _, body := send(t, base, "GET", "api.github.com", "/repos/acme/widget", research)
		if status == 200 || body == "upstream" {
			t.Fatalf("with ate-gress down, Envoy answered %d %q", status, body)
		}
	})
}

// runEnvoy starts Envoy and returns the base URL of its listener once it
// answers.
func runEnvoy(t *testing.T, image, etc, podidentity, servicedns string) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "-d",
		// Pin the host's IPv4 address: given host-gateway alone, Docker Desktop
		// also maps an IPv6 address, which Envoy prefers and cannot reach.
		"--add-host", "ategress-host:"+hostGatewayIPv4(t, image),
		"-p", "127.0.0.1::10000",
		"-v", etc+":/etc/envoy:ro",
		"-v", podidentity+":/run/podidentity.podcert.ate.dev:ro",
		"-v", servicedns+":/run/servicedns.podcert.ate.dev:ro",
		image, "-c", "/etc/envoy/envoy.yaml", "--log-level", "warn",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("envoy logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})
	out, err = exec.Command("docker", "port", id, "10000/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	base := "http://" + strings.TrimSpace(strings.Split(string(out), "\n")[0])

	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(base + "/")
		if err == nil {
			resp.Body.Close()
			return base
		}
		if time.Now().After(deadline) {
			t.Fatalf("envoy did not start listening: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// hostGatewayIPv4 returns the IPv4 address containers reach the Docker host
// at.
func hostGatewayIPv4(t *testing.T, image string) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", "--add-host", "probe:host-gateway",
		"--entrypoint", "getent", image, "ahostsv4", "probe").Output()
	if err != nil {
		t.Fatalf("resolving the Docker host gateway: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 || net.ParseIP(fields[0]).To4() == nil {
		t.Fatalf("no IPv4 host gateway in %q", out)
	}
	return fields[0]
}

func send(t *testing.T, base, method, host, path, actor string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Opaque keeps net/http from cleaning or re-escaping the path, so Envoy
	// receives the bytes the test case spells.
	req.URL.Opaque = path
	req.Host = host
	if actor != "" {
		req.Header.Set("x-test-actor", actor)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get(extproc.ReasonHeader), string(body)
}

func mkdir(t *testing.T, parent, name string) string {
	t.Helper()
	d := filepath.Join(parent, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	// Envoy runs as an unprivileged user in its image.
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func readable(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, data)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}
