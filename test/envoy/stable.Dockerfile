# Not built. This pins the newest stable Envoy that `make test-envoy-stable`
# runs the integration test against, in a file Dependabot's docker ecosystem
# reads, so a new Envoy release arrives as a pull request that CI tests.
#
# The Envoy that Substrate's gateway ships is ENVOY_IMAGE in the Makefile. It
# follows Substrate, not Envoy's releases, so Dependabot does not manage it.
FROM envoyproxy/envoy:v1.40.2@sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb
