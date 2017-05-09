package main

import (
	"html/template"
	"io"
)

// KubeConfigTmpl is a template which can be rendered into kubectl config file
// ready to talk to a tectonic installation.
type KubeConfigTmpl struct {
	clientID     string
	clientSecret string

	k8sURL           string
	k8sCAPEMBase64ed string

	dexURL           string
	dexCAPEMBase64ed string
}

// NewKubeConfigTmpl takes the necessary arguments required to create a KubeConfigTmpl.
func NewKubeConfigTmpl(clientID, clientSecret, k8sURL, dexURL string, k8sCA, dexCA []byte) *KubeConfigTmpl {
	encode := func(b []byte) string {
		if b == nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	return &KubeConfigTmpl{
		clientID:         clientID,
		clientSecret:     clientSecret,
		k8sURL:           k8sURL,
		dexURL:           dexURL,
		k8sCAPEMBase64ed: encode(k8sCA),
		dexCAPEMBase64ed: encode(dexCA),
	}
}

// Execute renders a kubectl config file unqiue to an authentication session.
func (k *KubeConfigTmpl) Execute(w io.Writer, idToken, refreshToken string) error {
	data := kubeConfigTmplData{
		K8sCA:        k.k8sCAPEMBase64ed,
		K8sURL:       k.k8sURL,
		DexCA:        k.dexCAPEMBase64ed,
		DexURL:       k.dexURL,
		ClientID:     k.clientID,
		ClientSecret: k.clientSecret,
		IDToken:      idToken,
		RefreshToken: refreshToken,
	}
	return kubeConfigTmpl.Execute(w, data)
}

type kubeConfigTmplData struct {
	K8sCA, K8sURL          string
	DexCA, DexURL          string
	ClientID, ClientSecret string
	IDToken                string
	RefreshToken           string
}

var kubeConfigTmpl = template.Must(template.New("kubeConfig").Parse(`apiVersion: v1
kind: Config

clusters:
- cluster:
    server: {{ .K8sURL }}{{ if .K8sCA }}
    certificate-authority-data: {{ .K8sCA }}{{ end }}
  name: tectonic

users:
- name: tectonic-oidc
  user:
    auth-provider:
      config:
        client-id: {{ .ClientID }}
        client-secret: {{ .ClientSecret }}
        id-token: {{ .IDToken }}{{ if .DexCA }}
        idp-certificate-authority-data: {{ .DexCA }}{{ end }}
        idp-issuer-url: {{ .DexURL }}{{ if .RefreshToken }}
        refresh-token: {{ .RefreshToken }}{{ end }}
      name: oidc

preferences: {}

contexts:
- context:
    cluster: tectonic
    user: tectonic-oidc
  name: tectonic

current-context: tectonic
`))
