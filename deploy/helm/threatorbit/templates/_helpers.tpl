{{/* Base name + fullname (release-scoped). */}}
{{- define "threatorbit.name" -}}
{{- default "threatorbit" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "threatorbit.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "threatorbit.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "threatorbit.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "threatorbit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Per-component selector labels. Call with (dict "root" . "component" "dashboard-api"). */}}
{{- define "threatorbit.selectorLabels" -}}
app.kubernetes.io/name: {{ include "threatorbit.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Fully-qualified image ref. Call with (dict "root" . "repo" .Values.images.x). */}}
{{- define "threatorbit.image" -}}
{{- $reg := .root.Values.image.registry -}}
{{- if $reg -}}{{ printf "%s/%s:%s" $reg .repo .root.Values.image.tag }}{{- else -}}{{ printf "%s:%s" .repo .root.Values.image.tag }}{{- end -}}
{{- end -}}

{{/* The Secret name to pull credentials from (managed here, or an existing one). */}}
{{- define "threatorbit.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}{{- else -}}{{ include "threatorbit.fullname" . }}-secrets{{- end -}}
{{- end -}}

{{- define "threatorbit.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}{{ default (include "threatorbit.fullname" .) .Values.serviceAccount.name }}{{- else -}}{{ default "default" .Values.serviceAccount.name }}{{- end -}}
{{- end -}}
