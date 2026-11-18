{{- define "olympos-agent.labels" -}}
app.kubernetes.io/name: olympos-agent
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "olympos-agent.selector" -}}
app.kubernetes.io/name: olympos-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "olympos-agent.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}
{{- end -}}
{{- end -}}
