package extproc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

const (
	testLogRate  = 1
	testLogBurst = 10
)

// limited is a Server with a clock the test moves, and its logs and metrics.
type limited struct {
	*Server
	logs bytes.Buffer
	reg  *prometheus.Registry
	// now is read by concurrent requests in TestDecisionLogLimitConcurrent,
	// which does not move it.
	now time.Time
}

// newLimited returns a Server logging at level, with the default limit, over
// three policies: "github" enforces, "staging" audits, and "registry" has
// logAllowed.
func newLimited(t *testing.T, level slog.Level) *limited {
	t.Helper()
	route := []v1alpha1.Route{{Methods: []v1alpha1.Method{"GET"}, Paths: []string{"/ok/**"}}}
	snap, results := policy.Compile([]v1alpha1.EgressRoutePolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "github"},
			Spec:       v1alpha1.EgressRoutePolicySpec{Hosts: []v1alpha1.HostRoutes{{Host: "api.github.com", Routes: route}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "staging"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				EnforcementMode: v1alpha1.EnforcementModeAudit,
				Hosts:           []v1alpha1.HostRoutes{{Host: "staging.example.com", Routes: route}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "registry"},
			Spec: v1alpha1.EgressRoutePolicySpec{
				LogAllowed: true,
				Hosts:      []v1alpha1.HostRoutes{{Host: "registry-1.docker.io", Routes: route}},
			},
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
	l := &limited{reg: prometheus.NewRegistry(), now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	log := slog.New(slog.NewJSONHandler(&l.logs, &slog.HandlerOptions{Level: level}))
	l.Server = NewServer(store, parser, log, NewMetrics(l.reg))
	l.Server.now = func() time.Time { return l.now }
	l.LimitDecisionLogs(testLogRate, testLogBurst)
	return l
}

func agent(n int) string {
	return fmt.Sprintf("spiffe://substrate-actor.local/worker-for-actor/research/agent-%d", n)
}

// send decides n requests from id for path on authority.
func (l *limited) send(t *testing.T, n int, id, authority, path string) {
	t.Helper()
	for range n {
		req := headersRequest(id, ":method", "GET", ":authority", authority, ":path", path)
		l.requestHeaders(t.Context(), req, req.GetRequestHeaders())
	}
}

// records returns the decision log written since the last call.
func (l *limited) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(l.logs.String()) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	l.logs.Reset()
	return out
}

func (l *limited) suppressedTotal(t *testing.T) float64 {
	t.Helper()
	return testutil.ToFloat64(l.metrics.suppressedLogs)
}

// suppressed returns the count a record carries, or 0 if it carries none.
func suppressed(rec map[string]any) float64 {
	n, _ := rec["suppressed"].(float64)
	return n
}

func TestDecisionLogLimit(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	const flood = 250

	// A different path each time: the path is not part of the key, so an
	// actor cannot buy a fresh burst by varying it.
	for i := range flood {
		l.send(t, 1, agent(1), "api.github.com", fmt.Sprintf("/denied/%d?token=querysecret", i))
	}
	recs := l.records(t)
	if len(recs) != testLogBurst {
		t.Fatalf("records for %d denials at once = %d, want the burst of %d", flood, len(recs), testLogBurst)
	}
	for i, rec := range recs {
		if rec["decision"] != "deny" || rec["actor"] != "research/agent-1" || rec["path"] != fmt.Sprintf("/denied/%d", i) {
			t.Errorf("record %d = %v, want the %dth denial", i, rec, i)
		}
		if _, ok := rec["suppressed"]; ok {
			t.Errorf("record %d carries a suppressed count before anything was suppressed: %v", i, rec)
		}
	}
	if got := l.suppressedTotal(t); got != flood-testLogBurst {
		t.Errorf("suppressed counter = %v, want %d", got, flood-testLogBurst)
	}

	// Less than a token's worth of time: still nothing.
	l.now = l.now.Add(500 * time.Millisecond)
	l.send(t, 1, agent(1), "api.github.com", "/denied/again")
	if recs := l.records(t); len(recs) != 0 {
		t.Fatalf("records 500ms later = %v, want none", recs)
	}

	// One token: one record, carrying everything suppressed since the last.
	l.now = l.now.Add(500 * time.Millisecond)
	l.send(t, 5, agent(1), "api.github.com", "/denied/again")
	recs = l.records(t)
	if len(recs) != 1 {
		t.Fatalf("records after 1s = %d, want 1", len(recs))
	}
	if got, want := suppressed(recs[0]), float64(flood-testLogBurst+1); got != want {
		t.Errorf("suppressed on the first record after the flood = %v, want %v", got, want)
	}

	// The 4 suppressed just now ride on the next record, not the 241 again.
	l.now = l.now.Add(3 * time.Second)
	l.send(t, 4, agent(1), "api.github.com", "/denied/again")
	recs = l.records(t)
	if len(recs) != 3 {
		t.Fatalf("records after 3 more seconds = %d, want 3", len(recs))
	}
	if got := []float64{suppressed(recs[0]), suppressed(recs[1]), suppressed(recs[2])}; got[0] != 4 || got[1] != 0 || got[2] != 0 {
		t.Errorf("suppressed on the next records = %v, want [4 0 0]", got)
	}

	// Every decision is counted, logged or not.
	const total = flood + 1 + 5 + 4
	want := fmt.Sprintf(`
# HELP ategress_decisions_total Requests decided, by outcome (allow, deny, audit) and reason.
# TYPE ategress_decisions_total counter
ategress_decisions_total{decision="deny",reason="no_route"} %d
# HELP ategress_decision_logs_suppressed_total Denial and audit log records dropped by the decision log rate limit. Their decisions are still counted in ategress_decisions_total.
# TYPE ategress_decision_logs_suppressed_total counter
ategress_decision_logs_suppressed_total %d
`, total, total-testLogBurst-1-3)
	if err := testutil.GatherAndCompare(l.reg, strings.NewReader(want), "ategress_decisions_total", "ategress_decision_logs_suppressed_total"); err != nil {
		t.Error(err)
	}
}

// TestDecisionLogLimitKeys checks what does and does not share a bucket.
func TestDecisionLogLimitKeys(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	l.send(t, 100, agent(1), "api.github.com", "/denied")
	l.records(t)

	tests := []struct {
		name                string
		id, authority, path string
		want                int // records for 100 requests
		decision, reason    string
	}{
		{name: "the same actor, reason and policy", id: agent(1), authority: "api.github.com", path: "/elsewhere", want: 0},
		{name: "another spelling of the authority", id: agent(1), authority: "API.github.com:443", path: "/denied", want: 0},
		{name: "another actor", id: agent(2), authority: "api.github.com", path: "/denied", want: testLogBurst, decision: "deny", reason: "no_route"},
		{name: "another reason", id: agent(1), authority: "api.github.com", path: "/ok/../denied", want: testLogBurst, decision: "deny", reason: "path"},
		{name: "an audit, under another policy", id: agent(1), authority: "staging.example.com", path: "/denied", want: testLogBurst, decision: "audit", reason: "no_route"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l.send(t, 100, tt.id, tt.authority, tt.path)
			recs := l.records(t)
			if len(recs) != tt.want {
				t.Fatalf("records = %d, want %d", len(recs), tt.want)
			}
			for _, rec := range recs {
				if rec["decision"] != tt.decision || rec["reason"] != tt.reason {
					t.Errorf("record = %v, want %s/%s", rec, tt.decision, tt.reason)
				}
				if _, ok := rec["suppressed"]; ok {
					t.Errorf("record carries another key's suppressed count: %v", rec)
				}
			}
		})
	}
}

// TestDecisionLogLimitBeforeIdentity covers the denials made before an actor
// is parsed. What the log calls their actor is whatever string arrived, so
// it must not be what they are limited by.
func TestDecisionLogLimitBeforeIdentity(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	const flood = 500

	for i := range flood {
		// Each is a different malformed identity.
		l.send(t, 1, fmt.Sprintf("spiffe://substrate-actor.local/actor/research/forged-%d", i), "api.github.com", "/ok/x")
	}
	recs := l.records(t)
	if len(recs) != testLogBurst {
		t.Errorf("records for %d distinct malformed identities = %d, want one burst of %d", flood, len(recs), testLogBurst)
	}
	for _, rec := range recs {
		if rec["reason"] != "identity" {
			t.Errorf("record = %v, want reason identity", rec)
		}
	}
	if n := l.limiter.Len(); n != 1 {
		t.Errorf("limiter tracks %d keys after %d malformed identities, want 1", n, flood)
	}

	// No identity at all shares that key.
	l.send(t, flood, "", "api.github.com", "/ok/x")
	if recs := l.records(t); len(recs) != 0 {
		t.Errorf("records for requests with no identity = %d, want 0: the identity bucket is spent", len(recs))
	}

	// Malformed headers are denied before the identity is read, whoever
	// sent them.
	for i := range flood {
		req := headersRequest(agent(i), ":method", "GET", ":authority", "api.github.com")
		l.requestHeaders(t.Context(), req, req.GetRequestHeaders())
	}
	recs = l.records(t)
	if len(recs) != testLogBurst {
		t.Errorf("records for %d requests without :path = %d, want one burst of %d", flood, len(recs), testLogBurst)
	}
	if n := l.limiter.Len(); n != 2 {
		t.Errorf("limiter tracks %d keys, want 2: one for each reason", n)
	}

	// None of that spent an authenticated actor's bucket.
	l.send(t, 1, agent(1), "api.github.com", "/denied")
	if recs := l.records(t); len(recs) != 1 || recs[0]["actor"] != "research/agent-1" {
		t.Errorf("records for an actor's first denial = %v, want it logged", recs)
	}

	l.now = l.now.Add(time.Second)
	l.send(t, 1, "not-a-spiffe-id", "api.github.com", "/ok/x")
	recs = l.records(t)
	if len(recs) != 1 || suppressed(recs[0]) != 2*flood-testLogBurst {
		t.Errorf("next identity record = %v, want one carrying %d suppressed", recs, 2*flood-testLogBurst)
	}
}

func TestDecisionLogLimitSparesLogAllowed(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	const n = 500

	// Spend the actor's denial bucket on the logAllowed policy first, so a
	// limiter that wrongly keyed allowed records in would have nothing left.
	l.send(t, n, agent(1), "registry-1.docker.io", "/denied")
	if recs := l.records(t); len(recs) != testLogBurst {
		t.Fatalf("denial records = %d, want %d", len(recs), testLogBurst)
	}
	before := l.suppressedTotal(t)

	l.send(t, n, agent(1), "registry-1.docker.io", "/ok/blob")
	recs := l.records(t)
	if len(recs) != n {
		t.Fatalf("records for %d allowed requests of a logAllowed policy = %d, want all of them", n, len(recs))
	}
	for _, rec := range recs {
		if rec["decision"] != "allow" || rec["policy"] != "registry" {
			t.Fatalf("record = %v, want an allow under registry", rec)
		}
		if _, ok := rec["suppressed"]; ok {
			t.Fatalf("an allowed record carries a suppressed count: %v", rec)
		}
	}
	if got := l.suppressedTotal(t); got != before {
		t.Errorf("suppressed counter moved from %v to %v on allowed requests", before, got)
	}
	if n := l.limiter.Len(); n != 1 {
		t.Errorf("limiter tracks %d keys, want only the denial's", n)
	}
}

// TestDecisionLogLimitSkipsAllowed checks that requests which log nothing at
// Info never reach the limiter.
func TestDecisionLogLimitSkipsAllowed(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	for i := range 100 {
		l.send(t, 1, agent(i), "api.github.com", "/ok/x") // allowed by a route
		l.send(t, 1, agent(i), "pypi.org", "/simple")     // unclaimed
	}
	if recs := l.records(t); len(recs) != 0 {
		t.Errorf("records = %d, want 0", len(recs))
	}
	if n := l.limiter.Len(); n != 0 {
		t.Errorf("limiter tracks %d keys after only allowed requests, want 0", n)
	}
}

func TestDecisionLogLimitOffAtDebug(t *testing.T) {
	l := newLimited(t, slog.LevelDebug)
	l.send(t, 100, agent(1), "api.github.com", "/denied")
	l.send(t, 100, agent(1), "api.github.com", "/ok/x")
	if recs := l.records(t); len(recs) != 200 {
		t.Errorf("records at Debug = %d, want every one of 200 decisions", len(recs))
	}
	if got := l.suppressedTotal(t); got != 0 {
		t.Errorf("suppressed counter = %v at Debug, want 0", got)
	}
}

func TestDecisionLogLimitDisabled(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	l.LimitDecisionLogs(0, 0)
	l.send(t, 100, agent(1), "api.github.com", "/denied")
	if recs := l.records(t); len(recs) != 100 {
		t.Errorf("records with the limit disabled = %d, want all 100", len(recs))
	}
}

// TestDecisionLogLimitBound sends denials from more actors than the limiter
// tracks. Its table stays at the cap, and the actors beyond it are limited
// together, with their own count, instead of each getting a burst.
func TestDecisionLogLimitBound(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	const extra = 300
	for i := range maxLogKeys + extra {
		l.send(t, 1, agent(i), "api.github.com", "/denied")
		if n := l.limiter.Len(); n > maxLogKeys {
			t.Fatalf("limiter tracks %d keys, want at most %d", n, maxLogKeys)
		}
	}
	if recs := l.records(t); len(recs) != maxLogKeys+testLogBurst {
		t.Errorf("records = %d, want %d: one per tracked actor and one shared burst", len(recs), maxLogKeys+testLogBurst)
	}

	// Every tracked bucket was used within the last second, so none can be
	// forgotten yet for the next new actor.
	l.now = l.now.Add(time.Second)
	for i := range maxLogKeys {
		l.send(t, 1, agent(i), "api.github.com", "/denied")
	}
	l.records(t)
	l.send(t, 1, agent(maxLogKeys+extra), "api.github.com", "/denied")
	recs := l.records(t)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if got := recs[0]["suppressed_untracked"]; got != float64(extra-testLogBurst) {
		t.Errorf("suppressed_untracked = %v, want %d; record %v", got, extra-testLogBurst, recs[0])
	}
	if _, ok := recs[0]["suppressed"]; ok {
		t.Errorf("a shared record attributes the count to its own actor: %v", recs[0])
	}
}

// TestDecisionLogLimitOmitsHeaderValues repeats TestDecisionLogOmitsHeaderValues
// for a record that carries a suppressed count.
func TestDecisionLogLimitOmitsHeaderValues(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	const secret = "ghs_s3cr3tInjectedBySubstrate"
	send := func(n int) {
		for range n {
			req := headersRequest(agent(1), append(get("/repos/evil/widget?token=querysecret"),
				"authorization", "Bearer "+secret, "cookie", "session="+secret)...)
			l.requestHeaders(t.Context(), req, req.GetRequestHeaders())
		}
	}
	send(50)
	l.now = l.now.Add(time.Second)
	send(1)
	logs := l.logs.String()
	for _, leak := range []string{secret, "querysecret"} {
		if strings.Contains(logs, leak) {
			t.Errorf("decision log contains %q:\n%s", leak, logs)
		}
	}
	if !strings.Contains(logs, `"suppressed":40`) {
		t.Errorf("decision log lacks the suppressed count:\n%s", logs)
	}
}

// TestDecisionLogLimitConcurrent floods from many goroutines with the clock
// stopped, so the outcome is exact: each actor logs its burst and no more,
// every other denial is counted as suppressed, and allowed requests of a
// logAllowed policy are all recorded.
func TestDecisionLogLimitConcurrent(t *testing.T) {
	l := newLimited(t, slog.LevelInfo)
	const actors, workersPerActor, perWorker = 8, 4, 250

	var wg sync.WaitGroup
	for a := range actors {
		for range workersPerActor {
			wg.Go(func() {
				for range perWorker {
					for _, target := range [][2]string{
						{"api.github.com", "/denied"},
						{"registry-1.docker.io", "/ok/blob"},
						{"pypi.org", "/simple"},
					} {
						req := headersRequest(agent(a), ":method", "GET", ":authority", target[0], ":path", target[1])
						l.requestHeaders(t.Context(), req, req.GetRequestHeaders())
					}
				}
			})
		}
	}
	wg.Wait()

	denied, allowed := map[any]int{}, 0
	for _, rec := range l.records(t) {
		switch rec["decision"] {
		case "deny":
			denied[rec["actor"]]++
		case "allow":
			allowed++
		default:
			t.Fatalf("unexpected record %v", rec)
		}
	}
	const perActor = workersPerActor * perWorker
	if len(denied) != actors {
		t.Errorf("actors with denial records = %d, want %d", len(denied), actors)
	}
	for actor, n := range denied {
		if n != testLogBurst {
			t.Errorf("%v has %d denial records, want %d", actor, n, testLogBurst)
		}
	}
	if allowed != actors*perActor {
		t.Errorf("logAllowed records = %d, want all %d", allowed, actors*perActor)
	}
	if got, want := l.suppressedTotal(t), float64(actors*(perActor-testLogBurst)); got != want {
		t.Errorf("suppressed counter = %v, want %v", got, want)
	}
}

// BenchmarkProcessDenied is the limiter's cost where it applies: every
// request is a denial from the same actor, on every core, so all but a few
// are suppressed under the one lock.
func BenchmarkProcessDenied(b *testing.B) {
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
	// A handler that formats each record, as the real one does, and discards
	// the bytes.
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := headersRequest(actorID, append(get("/repos/evil/widget/contents/README.md"),
		"user-agent", "git/2.50", "accept", "*/*", "authorization", "Bearer x")...)

	for _, bb := range []struct {
		name string
		rate float64
	}{{"unlimited", 0}, {"limited", testLogRate}} {
		b.Run(bb.name, func(b *testing.B) {
			s := NewServer(store, parser, log, NewMetrics(prometheus.NewRegistry()))
			s.LimitDecisionLogs(bb.rate, testLogBurst)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := s.respond(b.Context(), req); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}
