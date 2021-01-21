{{- define "secrets_operator_role_name" }}
name: {{ .Values.vault_injector_sa.name }}-secrets-operator-role
{{- end }}

{{- define "vault_injector_container" }}
- name: vault-k8s-secrets-injector
  image: {{ .Values.vault_injector.image }}
  workingDir: /injector 
  env:
    - name: VAULT_ADDR
      value: "{{ .Values.vault_auth.url }}"
    - name: VAULT_ROLE
      value: "{{ .Values.vault_auth.role_name }}"
    - name: VAULT_SECRET_CONFIG
      value: "{{ .Values.vault_injector.config_secret }}"
    {{- if .Values.vault_injector.id }}
    - name: VAULT_INJECTOR_ID
      value: {{ .Values.vault_injector.id }}
    {{- end }}
    {{- if .Values.vault_auth.mount }}
    - name: VAULT_K8S_AUTH_MOUNT
      value: {{ .Values.vault_auth.mount }}
    {{- end }}
    {{- if .Values.vault_auth.namespace }}
    - name: VAULT_NAMESPACE
      value: {{ .Values.vault_auth.namespace  }}
    {{- end }}
{{- end }}