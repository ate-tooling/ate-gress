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
