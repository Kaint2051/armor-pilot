{{- define "armor-pilot.name" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "armor-pilot.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if eq .Values.edition "enterprise" -}}
{{- printf "%s-enterprise:%s" .Values.image.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{- define "armor-pilot.labels" -}}
app.kubernetes.io/name: armor-pilot
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
