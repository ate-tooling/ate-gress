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
	transport *transportMetrics
	decisions *prometheus.CounterVec
	duration  prometheus.Histogram
}

// NewMetrics registers the request-path metrics with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		transport: newTransportMetrics(reg),
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
	return m
}

func (m *Metrics) observe(d policy.Decision, took time.Duration) {
	m.decisions.WithLabelValues(outcome(d), string(d.Reason)).Inc()
	m.duration.Observe(took.Seconds())
}
