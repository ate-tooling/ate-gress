// Package crd holds the generated EgressRoutePolicy CustomResourceDefinition,
// so that ategressctl can check policies against the schema the API server
// enforces without a cluster. `make generate` rewrites the YAML.
package crd

import _ "embed"

// EgressRoutePolicies is the CustomResourceDefinition manifest.
//
//go:embed ategress.ate-tooling.github.io_egressroutepolicies.yaml
var EgressRoutePolicies []byte
