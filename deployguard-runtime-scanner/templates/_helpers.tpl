{{- define "deployguard-runtime-scanner.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "deployguard-runtime-scanner.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: deployguard-runtime-scanner
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "deployguard-runtime-scanner.namespace" -}}
{{- default "deployguard" .Values.namespace }}
{{- end }}

{{- define "deployguard-runtime-scanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "deployguard-runtime-scanner.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "deployguard-runtime-scanner.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end }}
