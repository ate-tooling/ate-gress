package extproc

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ate-tooling/ate-gress/internal/policy"
)

// PolicyCollector serves ategress_policy_decisions_total from the tallies a
// policy.Store keeps.
//
// A policy name is a label here, and nowhere else, because policies are
// cluster-scoped objects an administrator creates: their number is bounded
// in a way actors and hosts are not. The series are read from the store at
// each scrape, not kept in a registry, so the request path does no label
// lookup and a policy that leaves the snapshot takes its series with it. A
// request still deciding on an older snapshot cannot bring them back.
type PolicyCollector struct {
	store *policy.Store
}

// NewPolicyCollector returns a collector that reads store at each scrape, so
// it follows every Swap without being told.
func NewPolicyCollector(store *policy.Store) *PolicyCollector {
	return &PolicyCollector{store: store}
}

var policyDecisionsDesc = prometheus.NewDesc(
	"ategress_policy_decisions_total",
	"Requests counted against each policy in the snapshot in effect, by outcome:"+
		" allow (the policy's route allowed the request),"+
		" deny (the request was denied, and this is an Enforce policy that claimed its host for its actor),"+
		" audit (the request was allowed, and this Audit policy alone, switched to Enforce, would have denied it)."+
		" One request can count against several policies.",
	[]string{"policy", "decision"}, nil,
)

// Describe implements prometheus.Collector.
func (c *PolicyCollector) Describe(ch chan<- *prometheus.Desc) { ch <- policyDecisionsDesc }

// Collect implements prometheus.Collector. Every policy has all three
// series, so that a count of zero is a sample and not an absence.
func (c *PolicyCollector) Collect(ch chan<- prometheus.Metric) {
	for _, pc := range c.store.PolicyCounts() {
		ch <- prometheus.MustNewConstMetric(policyDecisionsDesc, prometheus.CounterValue, float64(pc.Allow), pc.Policy, "allow")
		ch <- prometheus.MustNewConstMetric(policyDecisionsDesc, prometheus.CounterValue, float64(pc.Deny), pc.Policy, "deny")
		ch <- prometheus.MustNewConstMetric(policyDecisionsDesc, prometheus.CounterValue, float64(pc.Audit), pc.Policy, "audit")
	}
}
