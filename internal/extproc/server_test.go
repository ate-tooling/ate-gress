package extproc

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/testpki"
	"github.com/ate-tooling/ate-gress/internal/tlsconfig"
)

const (
	serverName = "ate-gress.ate-gress.svc"
	envoyID    = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
	actorID    = "spiffe://substrate-actor.local/worker-for-actor/research/agent-1"
	// filterName is the key Envoy files request attributes under: the name
	// of the ext_proc filter that requested them.
	filterName = "envoy.filters.http.ext_proc"
)

type harness struct {
	client  extprocv3.ExternalProcessorClient
	health  healthpb.HealthClient
	store   *policy.Store
	logs    *bytes.Buffer
	reg     *prometheus.Registry
	dial    func(cert *tls.Certificate) (*grpc.ClientConn, error)
	serving func(bool)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	servingCA, clientCA := testpki.NewCA(t, "servicedns"), testpki.NewCA(t, "podidentity")
	dir := t.TempDir()
	tlsCfg, err := tlsconfig.Server(tlsconfig.Config{
		CredentialBundle: testpki.WriteFile(t, dir, "credential-bundle.pem", servingCA.Serving(t, serverName).Bundle(t)),
		ClientCAs:        testpki.WriteFile(t, dir, "trust-bundle.pem", clientCA.PEM()),
		AllowedClientIDs: []string{envoyID},
	})
	if err != nil {
		t.Fatal(err)
	}

	parser, err := identity.NewParser(identity.DefaultTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{store: &policy.Store{}, logs: &bytes.Buffer{}, reg: prometheus.NewRegistry()}
	log := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	gs, hs := NewServer(h.store, parser, log, NewMetrics(h.reg)).GRPCServer(tlsCfg)
	h.serving = func(b bool) { SetServing(hs, b) }

	lis := bufconn.Listen(1 << 20)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	h.dial = func(cert *tls.Certificate) (*grpc.ClientConn, error) {
		cfg := &tls.Config{RootCAs: servingCA.Pool(), ServerName: serverName, MinVersion: tls.VersionTLS13}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	}
	envoy := clientCA.Client(t, envoyID).TLSCertificate()
	conn, err := h.dial(&envoy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	h.client = extprocv3.NewExternalProcessorClient(conn)
	h.health = healthpb.NewHealthClient(conn)
	return h
}

func (h *harness) install(t *testing.T) {
	t.Helper()
	snap, results := policy.Compile([]v1alpha1.EgressRoutePolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec: v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
			Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/repos/acme/**"}, CaseInsensitive: true,
		}}}}},
	}})
	if results[0].Err != nil {
		t.Fatal(results[0].Err)
	}
	h.store.Swap(snap)
}

// headersRequest builds a request-headers message as Envoy sends one: keys
// lowercase, values in raw_value, and the identity attribute filed under the
// filter's name.
func headersRequest(id string, kv ...string) *extprocv3.ProcessingRequest {
	hs := &corev3.HeaderMap{}
	for i := 0; i < len(kv); i += 2 {
		hs.Headers = append(hs.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	req := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{Headers: hs, EndOfStream: true}},
	}
	if id != "" {
		req.Attributes = map[string]*structpb.Struct{filterName: {Fields: map[string]*structpb.Value{
			IdentityAttribute: structpb.NewStringValue(id),
		}}}
	}
	return req
}

func get(path string) []string {
	return []string{":method", "GET", ":scheme", "https", ":authority", "api.github.com", ":path", path}
}

// roundTrip sends one message on a fresh stream and returns the response.
func (h *harness) roundTrip(t *testing.T, req *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, error) {
	t.Helper()
	stream, err := h.client.Process(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(req); err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	_ = stream.CloseSend()
	return resp, err
}

// verdict summarizes a response: "allow", or the denial's status and reason.
func verdict(t *testing.T, resp *extprocv3.ProcessingResponse) string {
	t.Helper()
	if rh := resp.GetRequestHeaders(); rh != nil {
		if rh.GetResponse().GetHeaderMutation() != nil || rh.GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
			t.Fatalf("allow response mutates the request: %v", rh)
		}
		return "allow"
	}
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatalf("response is neither a continue nor an immediate response: %v", resp)
	}
	if ir.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("denial status = %v, want 403", ir.GetStatus().GetCode())
	}
	if string(ir.GetBody()) != deniedBody {
		t.Fatalf("denial body = %q", ir.GetBody())
	}
	for _, hv := range ir.GetHeaders().GetSetHeaders() {
		if hv.GetHeader().GetKey() == ReasonHeader {
			return "deny:" + string(hv.GetHeader().GetRawValue())
		}
	}
	t.Fatalf("denial has no %s header", ReasonHeader)
	return ""
}

func TestProcessRequestHeaders(t *testing.T) {
	h := newHarness(t)
	h.install(t)

	twoIDs := headersRequest(actorID, get("/repos/acme/widget")...)
	twoIDs.Attributes["another.ext_proc"] = &structpb.Struct{Fields: map[string]*structpb.Value{
		IdentityAttribute: structpb.NewStringValue("spiffe://substrate-actor.local/worker-for-actor/other/agent-2"),
	}}
	sameIDTwice := headersRequest(actorID, get("/repos/acme/widget")...)
	sameIDTwice.Attributes["another.ext_proc"] = sameIDTwice.Attributes[filterName]
	valueNotRaw := headersRequest(actorID)
	for _, kv := range [][2]string{{":method", "GET"}, {":authority", "api.github.com"}, {":path", "/repos/acme/widget"}} {
		valueNotRaw.GetRequestHeaders().Headers.Headers = append(valueNotRaw.GetRequestHeaders().Headers.Headers, &corev3.HeaderValue{Key: kv[0], Value: kv[1]})
	}
	nonString := headersRequest("", get("/repos/acme/widget")...)
	nonString.Attributes = map[string]*structpb.Struct{filterName: {Fields: map[string]*structpb.Value{IdentityAttribute: structpb.NewNumberValue(1)}}}

	tests := []struct {
		name string
		req  *extprocv3.ProcessingRequest
		want string
	}{
		{name: "allowed route", req: headersRequest(actorID, get("/repos/acme/widget?per_page=10")...), want: "allow"},
		{name: "headers in value, not raw_value", req: valueNotRaw, want: "allow"},
		{name: "same identity under two filters", req: sameIDTwice, want: "allow"},
		{name: "unclaimed host", req: headersRequest(actorID, ":method", "GET", ":authority", "pypi.org", ":path", "/simple"), want: "allow"},
		{name: "other org", req: headersRequest(actorID, get("/repos/evil/widget")...), want: "deny:no_route"},
		{name: "encoded traversal", req: headersRequest(actorID, get("/repos/acme/x/..%2F..%2Fevil")...), want: "deny:path"},
		{name: "no identity", req: headersRequest("", get("/repos/acme/widget")...), want: "deny:identity"},
		{name: "malformed identity", req: headersRequest("spiffe://substrate-actor.local/actor/research/agent-1", get("/repos/acme/widget")...), want: "deny:identity"},
		{name: "non-string identity", req: nonString, want: "deny:identity"},
		{name: "conflicting identities", req: twoIDs, want: "deny:identity"},
		{name: "missing :path", req: headersRequest(actorID, ":method", "GET", ":authority", "api.github.com"), want: "deny:headers"},
		{name: "empty :method", req: headersRequest(actorID, ":method", "", ":authority", "api.github.com", ":path", "/repos/acme/x"), want: "deny:headers"},
		{name: "repeated :path", req: headersRequest(actorID, append(get("/repos/acme/widget"), ":path", "/repos/evil/widget")...), want: "deny:headers"},
		{name: "repeated :authority", req: headersRequest(actorID, append(get("/repos/acme/widget"), ":authority", "pypi.org")...), want: "deny:headers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := h.roundTrip(t, tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if got := verdict(t, resp); got != tt.want {
				t.Errorf("verdict = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestProcessNotReady(t *testing.T) {
	h := newHarness(t)
	resp, err := h.roundTrip(t, headersRequest(actorID, ":method", "GET", ":authority", "pypi.org", ":path", "/"))
	if err != nil {
		t.Fatal(err)
	}
	if got := verdict(t, resp); got != "deny:not_ready" {
		t.Errorf("verdict before the first snapshot = %s, want deny:not_ready", got)
	}
}

func TestProcessOtherPhases(t *testing.T) {
	h := newHarness(t)
	h.install(t)
	tests := []struct {
		name  string
		req   *extprocv3.ProcessingRequest
		check func(*extprocv3.ProcessingResponse) bool
	}{
		{"request body", &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{RequestBody: &extprocv3.HttpBody{}}},
			func(r *extprocv3.ProcessingResponse) bool { return r.GetRequestBody() != nil }},
		{"request trailers", &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{RequestTrailers: &extprocv3.HttpTrailers{}}},
			func(r *extprocv3.ProcessingResponse) bool { return r.GetRequestTrailers() != nil }},
		{"response headers", &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{}}},
			func(r *extprocv3.ProcessingResponse) bool { return r.GetResponseHeaders() != nil }},
		{"response body", &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{}}},
			func(r *extprocv3.ProcessingResponse) bool { return r.GetResponseBody() != nil }},
		{"response trailers", &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{ResponseTrailers: &extprocv3.HttpTrailers{}}},
			func(r *extprocv3.ProcessingResponse) bool { return r.GetResponseTrailers() != nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := h.roundTrip(t, tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.check(resp) {
				t.Errorf("response %v does not continue the %s phase", resp, tt.name)
			}
		})
	}

	t.Run("empty message", func(t *testing.T) {
		_, err := h.roundTrip(t, &extprocv3.ProcessingRequest{})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("error = %v, want InvalidArgument", err)
		}
	})
}

func TestProcessManyRequestsOnOneStream(t *testing.T) {
	h := newHarness(t)
	h.install(t)
	stream, err := h.client.Process(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/repos/acme/a", "/repos/evil/a", "/repos/acme/b"} {
		if err := stream.Send(headersRequest(actorID, get(p)...)); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("after CloseSend, Recv = %v, want EOF", err)
	}
}

func TestProcessRequiresGatewayCertificate(t *testing.T) {
	h := newHarness(t)
	conn, err := h.dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(t.Context())
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("unauthenticated client got %v, want Unavailable", err)
	}
}

func TestDecisionLogOmitsHeaderValues(t *testing.T) {
	h := newHarness(t)
	h.install(t)
	const secret = "ghs_s3cr3tInjectedBySubstrate"
	req := headersRequest(actorID, append(get("/repos/evil/widget?token=querysecret"),
		"authorization", "Bearer "+secret, "cookie", "session="+secret, "x-request-id", "req-123")...)
	if _, err := h.roundTrip(t, req); err != nil {
		t.Fatal(err)
	}
	logs := h.logs.String()
	for _, leak := range []string{secret, "querysecret"} {
		if strings.Contains(logs, leak) {
			t.Errorf("decision log contains %q:\n%s", leak, logs)
		}
	}
	for _, want := range []string{`"decision":"deny"`, `"reason":"no_route"`, `"actor":"research/agent-1"`, `"path":"/repos/evil/widget"`, `"request_id":"req-123"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("decision log lacks %s:\n%s", want, logs)
		}
	}
}

// TestDecisionLogLevels checks which decisions an Info logger records: an
// allowed request only when a policy claiming it has logAllowed.
func TestDecisionLogLevels(t *testing.T) {
	snap, results := policy.Compile([]v1alpha1.EgressRoutePolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "github"},
			Spec: v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
				Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/repos/acme/**"},
			}}}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "registry"},
			Spec: v1alpha1.EgressRoutePolicySpec{LogAllowed: true, Hosts: []v1alpha1.HostRoutes{{Host: "registry-1.docker.io", Routes: []v1alpha1.Route{{
				Methods: []v1alpha1.Method{"GET", "HEAD"}, Paths: []string{"/v2/", "/**"},
			}}}}},
		},
	})
	for _, r := range results {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	store := &policy.Store{}
	store.Swap(snap)
	parser, err := identity.NewParser(identity.DefaultTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s := NewServer(store, parser, slog.New(slog.NewJSONHandler(&logs, nil)), NewMetrics(prometheus.NewRegistry()))

	tests := []struct {
		name, authority, path string
		logged                []string // fragments of the record; nil for no record
	}{
		{name: "allowed, no logAllowed", authority: "api.github.com", path: "/repos/acme/widget"},
		{name: "unclaimed", authority: "pypi.org", path: "/simple/requests"},
		{name: "denied", authority: "api.github.com", path: "/repos/evil/widget",
			logged: []string{`"decision":"deny"`, `"policy":"github"`}},
		{name: "allowed, logAllowed", authority: "registry-1.docker.io", path: "/v2/?scope=x",
			logged: []string{`"decision":"allow"`, `"reason":"route"`, `"actor":"research/agent-1"`, `"method":"GET"`,
				`"authority":"registry-1.docker.io"`, `"path":"/v2/"`, `"policy":"registry"`, `"pattern":"/v2/"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs.Reset()
			req := headersRequest(actorID, ":method", "GET", ":authority", tt.authority, ":path", tt.path)
			s.requestHeaders(t.Context(), req, req.GetRequestHeaders())
			got := logs.String()
			if tt.logged == nil {
				if got != "" {
					t.Errorf("logged at Info, want nothing:\n%s", got)
				}
				return
			}
			for _, want := range tt.logged {
				if !strings.Contains(got, want) {
					t.Errorf("decision log lacks %s:\n%s", want, got)
				}
			}
			if strings.Contains(got, "scope=x") {
				t.Errorf("decision log contains the query:\n%s", got)
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	h := newHarness(t)
	h.install(t)
	for _, p := range []string{"/repos/acme/a", "/repos/acme/b", "/repos/evil/a"} {
		if _, err := h.roundTrip(t, headersRequest(actorID, get(p)...)); err != nil {
			t.Fatal(err)
		}
	}
	want := `
# HELP ategress_decisions_total Requests decided, by outcome (allow, deny, audit) and reason.
# TYPE ategress_decisions_total counter
ategress_decisions_total{decision="allow",reason="route"} 2
ategress_decisions_total{decision="deny",reason="no_route"} 1
`
	if err := testutil.GatherAndCompare(h.reg, strings.NewReader(want), "ategress_decisions_total"); err != nil {
		t.Error(err)
	}
	if n := testutil.CollectAndCount(h.reg, "ategress_decision_duration_seconds"); n != 1 {
		t.Errorf("duration histogram series = %d, want 1", n)
	}
}

func TestHealth(t *testing.T) {
	h := newHarness(t)
	check := func() healthpb.HealthCheckResponse_ServingStatus {
		t.Helper()
		resp, err := h.health.Check(t.Context(), &healthpb.HealthCheckRequest{Service: extprocv3.ExternalProcessor_ServiceDesc.ServiceName})
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetStatus()
	}
	if got := check(); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("initial status = %v, want NOT_SERVING", got)
	}
	h.serving(true)
	if got := check(); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("status after SetServing(true) = %v, want SERVING", got)
	}
}

func BenchmarkProcess(b *testing.B) {
	parser, err := identity.NewParser(identity.DefaultTrustDomain)
	if err != nil {
		b.Fatal(err)
	}
	store := &policy.Store{}
	snap, _ := policy.Compile([]v1alpha1.EgressRoutePolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec: v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: []v1alpha1.Route{{
			Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/repos/acme/**"},
		}}}}},
	}})
	store.Swap(snap)
	s := NewServer(store, parser, slog.New(slog.DiscardHandler), NewMetrics(prometheus.NewRegistry()))
	req := headersRequest(actorID, append(get("/repos/acme/widget/contents/README.md"),
		"user-agent", "git/2.50", "accept", "*/*", "authorization", "Bearer x")...)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.respond(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}
