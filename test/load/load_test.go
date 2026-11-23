//go:build load

// Package load measures what one ate-gress replica costs: its throughput,
// latency, CPU and memory at several request rates and policy-set sizes.
// docs/sizing.md reports the results and what they mean for sizing.
//
// It runs the real binary, built from cmd/ate-gress, against an envtest API
// server holding generated policies, and drives it over gRPC with mutual TLS
// the way the egress gateway does: one ext_proc stream per request, carrying
// the request headers and the actor identity attribute, over a few long-lived
// HTTP/2 connections. It does not go through Envoy; docs/sizing.md says why.
//
// Run it with `make load-test`. It is not part of `make test`: it takes
// minutes and its numbers depend on the machine.
//
// Environment:
//
//	LOAD_POLICIES    policy-set sizes, comma-separated (default 10,100,1000)
//	LOAD_RATES       requests a second per step, comma-separated; "max" is a
//	                 closed loop as fast as the server answers (default
//	                 1000,5000,20000,max)
//	LOAD_DURATION    how long each step runs (default 10s)
//	LOAD_GOMAXPROCS  GOMAXPROCS of the ate-gress process, the cores it may use
//	                 (default 1)
//	LOAD_CONNS       gRPC connections, as the gateway's worker threads open
//	                 (default 4)
//	LOAD_OUT         also write the results table to this file
package load

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/extproc"
	"github.com/ate-tooling/ate-gress/internal/testpki"
)

const (
	serverName = "ate-gress.ate-gress.svc"
	gatewayID  = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
	// The name the gateway's filter files the identity attribute under.
	filterName = "envoy.filters.http.ext_proc"
)

func TestLoad(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set; run through `make load-test`")
	}
	sizes := intList(t, env("LOAD_POLICIES", "10,100,1000"))
	rates := env("LOAD_RATES", "1000,5000,20000,max")
	duration, err := time.ParseDuration(env("LOAD_DURATION", "10s"))
	if err != nil {
		t.Fatal(err)
	}
	procs := env("LOAD_GOMAXPROCS", "1")
	conns := intList(t, env("LOAD_CONNS", "4"))[0]

	dir := t.TempDir()
	bin := filepath.Join(dir, "ate-gress")
	if out, err := exec.Command("go", "build", "-trimpath", "-o", bin, "../../cmd/ate-gress").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	scheme := k8sruntime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	apiserver := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd"}, ErrorIfCRDPathMissing: true}
	cfg, err := apiserver.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = apiserver.Stop() })
	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	user, err := apiserver.AddUser(envtest.User{Name: "ate-gress", Groups: []string{"system:masters"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig, err := user.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}
	kubeconfigPath := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfigPath, kubeconfig, 0o600); err != nil {
		t.Fatal(err)
	}

	servicednsCA, podidentityCA := testpki.NewCA(t, "servicedns"), testpki.NewCA(t, "podidentity")
	serving := testpki.WriteFile(t, dir, "serving.pem", servicednsCA.Serving(t, serverName).Bundle(t))
	clientCAs := testpki.WriteFile(t, dir, "clients.pem", podidentityCA.PEM())
	clientCert := podidentityCA.Client(t, gatewayID).TLSCertificate()
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      servicednsCA.Pool(),
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	})

	header := fmt.Sprintf("ate-gress load test: %s/%s, %d CPUs, ate-gress GOMAXPROCS=%s, %d connections, %s steps, %s",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), procs, conns, duration, runtime.Version())
	t.Log(header)
	var table strings.Builder
	fmt.Fprintln(&table, header)
	fmt.Fprintln(&table)
	fmt.Fprintln(&table, "| policies | target req/s | achieved req/s | p50 | p90 | p99 | p99.9 | max | p99 start lag | errors | CPU (cores) | CPU µs/req | RSS MiB | heap MiB |")
	fmt.Fprintln(&table, "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

	for _, n := range sizes {
		ctx := t.Context()
		if err := cl.DeleteAllOf(ctx, &v1alpha1.EgressRoutePolicy{}); err != nil {
			t.Fatal(err)
		}
		for _, p := range policies(n) {
			if err := cl.Create(ctx, &p); err != nil {
				t.Fatal(err)
			}
		}
		srv := start(t, bin, dir, kubeconfigPath, serving, clientCAs, procs, n)
		// What it costs with no requests: informers, leader-election-free
		// housekeeping, the runtime.
		before := srv.scrape(t)
		time.Sleep(5 * time.Second)
		idle := srv.scrape(t)
		fmt.Fprintf(&table, "| %d | idle | | | | | | | | | %.3f | | %.0f | %.1f |\n", n,
			(idle["process_cpu_seconds_total"]-before["process_cpu_seconds_total"])/5,
			idle["process_resident_memory_bytes"]/(1<<20), idle["go_memstats_heap_inuse_bytes"]/(1<<20))

		clients := make([]extprocv3.ExternalProcessorClient, conns)
		for i := range clients {
			cc, err := grpc.NewClient(srv.grpc, grpc.WithTransportCredentials(creds))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cc.Close() })
			clients[i] = extprocv3.NewExternalProcessorClient(cc)
		}
		reqs := requests(n, 4096)
		// Warm up: connections, TLS, and the server's buffers.
		drive(ctx, clients, reqs, 1000, 2*time.Second)

		for _, r := range strings.Split(rates, ",") {
			rate := 0.0
			if r != "max" {
				if rate, err = strconv.ParseFloat(r, 64); err != nil {
					t.Fatal(err)
				}
			}
			before := srv.scrape(t)
			res := drive(ctx, clients, reqs, rate, duration)
			after := srv.scrape(t)
			cpu := (after["process_cpu_seconds_total"] - before["process_cpu_seconds_total"]) / res.elapsed.Seconds()
			achieved := float64(res.done) / res.elapsed.Seconds()
			row := fmt.Sprintf("| %d | %s | %.0f | %s | %s | %s | %s | %s | %s | %d | %.2f | %.1f | %.0f | %.1f |", n, r, achieved,
				us(quantile(res.latencies, 0.5)), us(quantile(res.latencies, 0.9)), us(quantile(res.latencies, 0.99)),
				us(quantile(res.latencies, 0.999)), us(quantile(res.latencies, 1)), us(quantile(res.lags, 0.99)),
				res.errors, cpu, cpu*1e6/achieved,
				after["process_resident_memory_bytes"]/(1<<20), after["go_memstats_heap_inuse_bytes"]/(1<<20))
			t.Log(row)
			fmt.Fprintln(&table, row)
			if res.errors > 0 {
				t.Errorf("%d policies, %s req/s: %d requests failed; first: %v", n, r, res.errors, res.firstErr)
			}
			if res.wrong > 0 {
				t.Errorf("%d policies, %s req/s: %d decisions were not the expected ones", n, r, res.wrong)
			}
		}
		srv.stop(t)
	}
	fmt.Println(table.String())
	if out := os.Getenv("LOAD_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(table.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// policies returns n policies, each claiming its own host for its own
// atespace, with the routes of a read-mostly API.
func policies(n int) []v1alpha1.EgressRoutePolicy {
	ps := make([]v1alpha1.EgressRoutePolicy, n)
	for i := range ps {
		ps[i] = v1alpha1.EgressRoutePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("load-%04d", i)},
			Spec: v1alpha1.EgressRoutePolicySpec{
				ActorSelector: v1alpha1.ActorSelector{Atespaces: []string{fmt.Sprintf("team-%d", i)}},
				Hosts: []v1alpha1.HostRoutes{{
					Host: fmt.Sprintf("svc-%d.example.com", i),
					Routes: []v1alpha1.Route{
						{Methods: []v1alpha1.Method{"GET", "HEAD"}, Paths: []string{"/api/v1/orgs/acme/*", "/api/v1/orgs/acme/*/**"}},
						{Methods: []v1alpha1.Method{"POST"}, Paths: []string{"/api/v1/orgs/acme/*/issues"}},
					},
				}},
			},
		}
	}
	return ps
}

// request is one ext_proc request and the decision it should get.
type request struct {
	msg   *extprocv3.ProcessingRequest
	allow bool
}

// requests returns a mix of requests against n policies: 70% allowed by a
// route, 20% denied (no_route, which logs, under the rate limit), 10% to a
// host no policy claims.
func requests(n, count int) []request {
	rng := rand.New(rand.NewPCG(1, 2))
	out := make([]request, count)
	for i := range out {
		p := rng.IntN(n)
		actor := fmt.Sprintf("spiffe://substrate-actor.local/worker-for-actor/team-%d/agent-%d", p, rng.IntN(8))
		method, host, path, allow := "GET", fmt.Sprintf("svc-%d.example.com", p), "/api/v1/orgs/acme/widget/contents/README.md", true
		switch x := rng.IntN(10); {
		case x < 2:
			method, allow = "DELETE", false
		case x < 3:
			host, path = "pypi.org", "/simple/requests/"
		}
		hs := &corev3.HeaderMap{}
		for _, kv := range [][2]string{
			{":method", method}, {":scheme", "https"}, {":authority", host}, {":path", path},
			{"user-agent", "agent/1.0"}, {"accept", "application/json"},
			{"x-request-id", fmt.Sprintf("%08x-load", i)},
		} {
			hs.Headers = append(hs.Headers, &corev3.HeaderValue{Key: kv[0], RawValue: []byte(kv[1])})
		}
		out[i] = request{
			msg: &extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{Headers: hs, EndOfStream: true}},
				Attributes: map[string]*structpb.Struct{filterName: {Fields: map[string]*structpb.Value{
					extproc.IdentityAttribute: structpb.NewStringValue(actor),
				}}},
			},
			allow: allow,
		}
	}
	return out
}

type result struct {
	// latencies are round trips, from opening the stream to its end. lags
	// are how late each request started against the schedule: near zero
	// until the client or the server cannot keep the rate.
	latencies    []time.Duration
	lags         []time.Duration
	done, errors int
	wrong        int
	firstErr     error
	elapsed      time.Duration
}

func quantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(q*float64(len(sorted)-1))]
}

// drive sends requests for d. At a rate it is an open loop: request k is due
// at start + k/rate whether or not earlier ones were answered, so a server
// that falls behind shows as start lag and a lower achieved rate, not as a
// client that politely waits. A rate of 0 is a closed loop, each worker
// sending as soon as its last request is answered.
func drive(ctx context.Context, clients []extprocv3.ExternalProcessorClient, reqs []request, rate float64, d time.Duration) result {
	const workers = 128
	var (
		next  atomic.Int64
		mu    sync.Mutex
		res   result
		wg    sync.WaitGroup
		start = time.Now()
		end   = start.Add(d)
	)
	for range workers {
		wg.Go(func() {
			var lat, lags []time.Duration
			var errs, wrong int
			var firstErr error
			for {
				k := next.Add(1) - 1
				due := time.Now()
				if rate > 0 {
					due = start.Add(time.Duration(float64(k) * float64(time.Second) / rate))
					if due.After(end) {
						break
					}
					time.Sleep(time.Until(due))
				} else if due.After(end) {
					break
				}
				r := reqs[int(k)%len(reqs)]
				sent := time.Now()
				lags = append(lags, sent.Sub(due))
				allowed, err := roundTrip(ctx, clients[int(k)%len(clients)], r.msg)
				lat = append(lat, time.Since(sent))
				switch {
				case err != nil:
					errs++
					if firstErr == nil {
						firstErr = err
					}
				case allowed != r.allow:
					wrong++
				}
			}
			mu.Lock()
			res.latencies = append(res.latencies, lat...)
			res.lags = append(res.lags, lags...)
			res.errors += errs
			res.wrong += wrong
			if res.firstErr == nil {
				res.firstErr = firstErr
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	res.elapsed = time.Since(start)
	res.done = len(res.latencies) - res.errors
	slices.Sort(res.latencies)
	slices.Sort(res.lags)
	return res
}

// roundTrip is one HTTP request as the gateway's filter makes it: open a
// stream, send the request headers, read the answer, close.
func roundTrip(ctx context.Context, c extprocv3.ExternalProcessorClient, msg *extprocv3.ProcessingRequest) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second) // the gateway's timeout
	defer cancel()
	stream, err := c.Process(ctx)
	if err != nil {
		return false, err
	}
	if err := stream.Send(msg); err != nil {
		return false, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return false, err
	}
	if err := stream.CloseSend(); err != nil {
		return false, err
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("stream did not end after the response: %w", err)
	}
	return resp.GetImmediateResponse() == nil, nil
}

type server struct {
	cmd           *exec.Cmd
	grpc, metrics string
}

// start runs ate-gress and waits until it is ready with all n policies in its
// snapshot.
func start(t *testing.T, bin, dir, kubeconfig, serving, clientCAs, procs string, n int) *server {
	t.Helper()
	s := &server{grpc: freeAddr(t), metrics: freeAddr(t)}
	probes := freeAddr(t)
	logs, err := os.Create(filepath.Join(dir, fmt.Sprintf("ate-gress-%d.log", n)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logs.Close() })
	s.cmd = exec.Command(bin,
		"--grpc-address="+s.grpc, "--metrics-address="+s.metrics, "--health-probe-address="+probes,
		"--credential-bundle="+serving, "--client-ca-file="+clientCAs, "--allowed-client-id="+gatewayID,
		"--leader-elect=false", "--drain-delay=0s", "--stop-timeout=2s")
	s.cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig, "GOMAXPROCS="+procs)
	s.cmd.Stderr = logs
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.cmd.Process.Kill(); _ = s.cmd.Wait() })

	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get("http://" + probes + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && s.scrape(t)[`ategress_policies{state="accepted"}`] == float64(n) {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("ate-gress was not ready with %d policies within 60s; its log is %s", n, logs.Name())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (s *server) stop(t *testing.T) {
	t.Helper()
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	_ = s.cmd.Wait()
}

// scrape reads the server's metrics: unlabeled series by name, labeled ones
// by name and labels as the exposition format spells them.
func (s *server) scrape(t *testing.T) map[string]float64 {
	t.Helper()
	resp, err := http.Get("http://" + s.metrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		out[line[:i]] = v
	}
	for _, m := range []string{"process_cpu_seconds_total", "process_resident_memory_bytes", "go_memstats_heap_inuse_bytes"} {
		if _, ok := out[m]; !ok {
			t.Fatalf("ate-gress does not report %s on %s", m, runtime.GOOS)
		}
	}
	return out
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func us(d time.Duration) string {
	switch {
	case d >= 10*time.Millisecond:
		return fmt.Sprintf("%.0fms", float64(d)/1e6)
	case d >= time.Millisecond:
		return fmt.Sprintf("%.1fms", float64(d)/1e6)
	default:
		return fmt.Sprintf("%.0fµs", float64(d)/1e3)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func intList(t *testing.T, s string) []int {
	t.Helper()
	var out []int
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 {
			t.Fatalf("not a positive number: %q", f)
		}
		out = append(out, n)
	}
	return out
}
