{{- define "ate-gress.name" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ate-gress.labels" -}}
app.kubernetes.io/name: ate-gress
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "ate-gress.selectorLabels" -}}
app.kubernetes.io/name: ate-gress
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The pod template's labels: the chart's own, then podLabels. A podLabel cannot
replace one of the chart's, which the selector and the monitors rely on.
*/}}
{{- define "ate-gress.podLabels" -}}
{{- $own := include "ate-gress.labels" . | fromYaml -}}
{{- include "ate-gress.labels" . }}
{{- range $k, $v := .Values.podLabels }}
{{- if not (hasKey $own $k) }}
{{ $k }}: {{ $v | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
The label matchers that select ate-gress's series in the alert rules. The
default is the job label Prometheus gives a PodMonitor's targets.
*/}}
{{- define "ate-gress.metricsSelector" -}}
{{- .Values.prometheusRule.selector | default (printf "job=%q" (printf "%s/%s" .Release.Namespace (include "ate-gress.name" .))) -}}
{{- end -}}

{{/*
What every alert ends with: for, labels and the link to its runbook section.
Takes a list of the root context, the alert's values and the alert's name.
*/}}
{{- define "ate-gress.alertTail" -}}
{{- $root := index . 0 -}}
{{- $alert := index . 1 -}}
for: {{ $alert.for }}
labels:
  severity: {{ $alert.severity }}
  {{- with $root.Values.prometheusRule.additionalLabels }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- end -}}

{{- define "ate-gress.runbook" -}}
{{- $root := index . 0 -}}
runbook_url: {{ printf "%s#%s" $root.Values.prometheusRule.runbookURL (lower (index . 1)) }}
{{- end -}}

{{/* affinity, with the required anti-affinity merged in when it is on. */}}
{{- define "ate-gress.affinity" -}}
{{- $affinity := deepCopy .Values.affinity -}}
{{- if .Values.podAntiAffinity.required -}}
{{- if hasKey $affinity "podAntiAffinity" -}}
{{- fail "podAntiAffinity.required cannot be combined with affinity.podAntiAffinity; set one" -}}
{{- end -}}
{{- $term := dict "topologyKey" "kubernetes.io/hostname" "labelSelector" (dict "matchLabels" (include "ate-gress.selectorLabels" . | fromYaml)) -}}
{{- $_ := set $affinity "podAntiAffinity" (dict "requiredDuringSchedulingIgnoredDuringExecution" (list $term)) -}}
{{- end -}}
{{- if $affinity -}}
{{- toYaml $affinity -}}
{{- end -}}
{{- end -}}

{{/*
The whole seconds in a Go duration as values.schema.json admits it, such as
10s, 1m30s or 500ms, rounded up.
*/}}
{{- define "ate-gress.durationSeconds" -}}
{{- $units := dict "ns" 0.000000001 "us" 0.000001 "ms" 0.001 "s" 1.0 "m" 60.0 "h" 3600.0 -}}
{{- $total := 0.0 -}}
{{- range regexFindAll "[0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h)" . -1 -}}
{{- $n := regexFind "^[0-9]+(\\.[0-9]+)?" . -}}
{{- $total = addf $total (mulf (float64 $n) (get $units (trimPrefix $n .))) -}}
{{- end -}}
{{- ceil $total | int -}}
{{- end -}}
