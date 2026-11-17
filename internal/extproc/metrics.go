package extproc

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/samueltorres/ate-gress/internal/policy"
)

// Metrics are the request-path metrics. Labels are bounded: actors, hosts,
// and policies are deliberately absent, and belong in the decision log.
type Metrics struct {
	decisions *prometheus.CounterVec
	duration  prometheus.Histogram
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
	return m
}

func (m *Metrics) observe(d policy.Decision, took time.Duration) {
	m.decisions.WithLabelValues(outcome(d), string(d.Reason)).Inc()
	m.duration.Observe(took.Seconds())
}
