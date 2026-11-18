{{- define "olympos-server.labels" -}}
app.kubernetes.io/name: olympos-server
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "olympos-server.selector" -}}
app.kubernetes.io/name: olympos-server
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "olympos-server.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}
{{- end -}}
{{- end -}}
