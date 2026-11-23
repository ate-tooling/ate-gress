#!/usr/bin/env bash
# Checks the chart's alert rules with promtool: that they parse, and that
# they fire when test/rules/alerts_test.yaml says they should.
#
#   hack/test-rules.sh
#
# promtool wants a plain rule file, and the chart renders a PrometheusRule.
# The rule file is that object's spec, so this cuts the spec out of what
# `helm template` renders. It needs helm and Docker.
#
# Environment:
#   PROMETHEUS_IMAGE  image to take promtool from
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
image="${PROMETHEUS_IMAGE:-prom/prometheus:v3.8.0}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
# The image runs as nobody.
chmod 755 "${work}"

# The tests name the job the rules select by default: <namespace>/<release>.
helm template ate-gress "${root}/charts/ate-gress" --namespace ate-gress \
  --set prometheusRule.enabled=true --show-only templates/prometheusrule.yaml |
  sed -n '/^spec:$/,$p' | sed -e '1d' -e 's/^  //' > "${work}/rules.yaml"
if ! grep -q '^groups:$' "${work}/rules.yaml"; then
  echo "could not cut the rule groups out of the rendered PrometheusRule" >&2
  exit 1
fi
cp "${root}/test/rules/alerts_test.yaml" "${work}/"
chmod 644 "${work}"/*.yaml

promtool=(docker run --rm -v "${work}:/rules:ro" -w /rules --entrypoint promtool "${image}")
"${promtool[@]}" check rules rules.yaml
"${promtool[@]}" test rules alerts_test.yaml
