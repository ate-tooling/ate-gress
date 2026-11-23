package main

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

// registerBuildInfo registers ategress_build_info, a constant 1 whose labels
// say what is running, so a rollout can be followed and other metrics joined
// to a version.
func registerBuildInfo(reg prometheus.Registerer) error {
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ategress_build_info",
		Help: "Always 1; the labels are the ate-gress version and the Go version it was built with.",
	}, []string{"version", "goversion"})
	info.WithLabelValues(version, runtime.Version()).Set(1)
	return reg.Register(info)
}
