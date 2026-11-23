#!/usr/bin/env bash
# Validates what the chart renders, with every option on, against the
# Kubernetes API schemas and the Prometheus Operator's CRD schemas, with
# kubeconform. helm lint checks the templates; this checks that the objects
# they produce are ones the API server would accept, which matters most for
# the PodMonitor and PrometheusRule: nothing else in the repo would notice a
# field the operator does not have.
#
#   hack/validate-chart.sh
#
# It needs helm, Docker, and network access to fetch the schemas, which are
# pinned below.
#
# Environment:
#   KUBECONFORM_IMAGE   image to run kubeconform from
#   KUBERNETES_VERSION  Kubernetes schema version to validate against
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
image="${KUBECONFORM_IMAGE:-ghcr.io/yannh/kubeconform:v0.7.0}"
k8s="${KUBERNETES_VERSION:-1.34.12}"
# datreeio/CRDs-catalog at a fixed commit; its monitoring.coreos.com schemas
# are generated from the Prometheus Operator's CRDs.
catalog="https://raw.githubusercontent.com/datreeio/CRDs-catalog/04af58d740718c4dc719441bf39fb284c784f4a8"

# The CRD is left out: kubeconform has no schema for CustomResourceDefinition,
# and the chart test pins it to config/crd, which envtest loads.
values=(
  --set crds.install=false
  --set podMonitor.enabled=true
  --set podMonitor.interval=30s
  --set podMonitor.scrapeTimeout=10s
  --set prometheusRule.enabled=true
  --set grafanaDashboard.enabled=true
  --set rbac.aggregateClusterRoles=true
  --set topologySpread.zone=true
  --set podAntiAffinity.required=true
  --set podLabels.team=egress
  --set podAnnotations.example\\.com/owner=egress
  --set 'imagePullSecrets[0].name=registry'
  --set priorityClassName=egress-critical
  --set 'networkPolicy.metricsFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=monitoring'
)
helm template ate-gress "${root}/charts/ate-gress" --namespace ate-gress "${values[@]}" |
  docker run --rm -i "${image}" -strict -summary \
    -kubernetes-version "${k8s}" \
    -schema-location default \
    -schema-location "${catalog}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
    -
