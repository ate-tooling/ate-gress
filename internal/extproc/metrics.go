package extproc

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ate-tooling/ate-gress/internal/policy"
)

// Metrics are the request-path metrics. Labels are bounded: actors and hosts
// are deliberately absent, and belong in the decision log. Policies are a
// label of one metric only, which PolicyCollector serves.
type Metrics struct {
	// The gRPC server beneath the request path.
	streams           prometheus.Gauge
	handshakeFailures *prometheus.CounterVec

	decisions *prometheus.CounterVec
	duration  prometheus.Histogram

	// suppressedLogs counts the decision log records the rate limit dropped.
	suppressedLogs prometheus.Counter
}

// NewMetrics registers the request-path metrics with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ategress_decisions_total",
			Help: "Requests decided, by outcome (allow, deny, audit) and reason.",
		}, []string{"decision", "reason"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ategress_decision_duration_seconds",
			Help:    "Time to decide a request, from receiving its headers to building the response.",
			Buckets: prometheus.ExponentialBuckets(1e-6, 4, 10), // 1µs to ~260ms
		}),
	}
	reg.MustRegister(m.decisions, m.duration)
	m.registerTransport(reg)
	m.suppressedLogs = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ategress_decision_logs_suppressed_total",
		Help: "Denial and audit log records dropped by the decision log rate limit. Their decisions are still counted in ategress_decisions_total.",
	})
	reg.MustRegister(m.suppressedLogs)
	return m
}

func (m *Metrics) observe(d policy.Decision, took time.Duration) {
	m.decisions.WithLabelValues(outcome(d), string(d.Reason)).Inc()
	m.duration.Observe(took.Seconds())
}

func (m *Metrics) logSuppressed() { m.suppressedLogs.Inc() }
