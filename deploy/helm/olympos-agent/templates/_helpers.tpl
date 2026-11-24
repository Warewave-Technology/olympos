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

{{/*
olympos-probe. Its objects have their own name label, so the agent's
selector never matches probe pods. Every probe value read here has a
fallback equal to its default in values.yaml: an upgrade with
--reuse-values from a release older than the probe keeps that release's
values, which have no probe section (chart_test.go checks the fallbacks).
*/}}
{{- define "olympos-probe.labels" -}}
app.kubernetes.io/name: olympos-probe
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "olympos-probe.selector" -}}
app.kubernetes.io/name: olympos-probe
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{/* "true" unless probe.enabled is false: on by default, also for old values. */}}
{{- define "olympos-probe.enabled" -}}
{{- $p := .Values.probe | default dict -}}
{{- ne (toString (index $p "enabled")) "false" -}}
{{- end -}}
{{- define "olympos-probe.image" -}}
{{- $img := (.Values.probe | default dict).image | default dict -}}
{{- $repo := $img.repository | default "ghcr.io/warewave-technology/olympos-probe" -}}
{{- if $img.digest -}}
{{ $repo }}@{{ $img.digest }}
{{- else -}}
{{ $repo }}:{{ default .Chart.AppVersion $img.tag }}
{{- end -}}
{{- end -}}
