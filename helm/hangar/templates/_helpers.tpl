{{- define "hangar.labels" -}}
app.kubernetes.io/name: {{ .Release.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "hangar.selectorLabels" -}}
app.kubernetes.io/name: {{ .Release.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "hangar.dockerTokenRealm" -}}
https://{{ .Values.ingress.host }}/v2/token
{{- end -}}

{{- define "hangar.publicUrl" -}}
https://{{ .Values.ingress.host }}
{{- end -}}
