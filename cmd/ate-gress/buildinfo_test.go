package main

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestBuildInfoMetric(t *testing.T) {
	defer func(v string) { version = v }(version)
	version = "1.2.3"
	reg := prometheus.NewRegistry()
	if err := registerBuildInfo(reg); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`
# HELP ategress_build_info Always 1; the labels are the ate-gress version and the Go version it was built with.
# TYPE ategress_build_info gauge
ategress_build_info{goversion=%q,version="1.2.3"} 1
`, runtime.Version())
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "ategress_build_info"); err != nil {
		t.Error(err)
	}
}
