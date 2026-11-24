#!/usr/bin/env bash
# Generates the chart's CRD template from config/crd. `make generate` runs it.
#
# The CRD is a template, not a file in the chart's crds/ directory, because
# Helm installs crds/ once and never upgrades it: a release that added a field
# would leave the old schema in place, and the API server would prune or
# reject the field.
#
#   hack/generate-chart-crds.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${root}/charts/ate-gress/templates/crds.yaml"
tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

{
  echo '{{- /* Generated from config/crd by hack/generate-chart-crds.sh. Do not edit. */ -}}'
  echo '{{- if .Values.crds.install }}'
} >"${tmp}"

for crd in "${root}"/config/crd/*.yaml; do
  # The CRD is copied verbatim, so it must hold nothing Helm would run as a
  # template action. The schema's patterns use single braces only.
  if grep -n '{{' "${crd}" >&2; then
    echo "${crd} contains '{{', which Helm would read as a template action" >&2
    exit 1
  fi
  # controller-gen always writes metadata.annotations, with its version.
  if [[ "$(grep -c '^  annotations:$' "${crd}")" -ne 1 ]]; then
    echo "${crd}: expected exactly one metadata.annotations" >&2
    exit 1
  fi
  # keep: uninstalling the release, or turning crds.install off, must not
  # delete the CRD, which would delete every policy.
  awk '
    { print }
    /^  annotations:$/ { print "    helm.sh/resource-policy: keep" }
  ' "${crd}" >>"${tmp}"
done

echo '{{- end }}' >>"${tmp}"
mv "${tmp}" "${out}"
chmod 644 "${out}"
