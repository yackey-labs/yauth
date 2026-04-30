package asymjwt

import (
	"encoding/json"
	"net/http"
)

// handleJWKS returns the precomputed JWKS bytes as application/json.
func (p *asymjwtPlugin) handleJWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body, err := p.signer.PublicJWKS()
		if err != nil {
			http.Error(w, "jwks unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}

// jsonMarshalIndent marshals v with the encoding/json package using a
// stable two-space indent. It is a small helper used to keep the JWKS
// doc readable when inspected by humans.
func jsonMarshalIndent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
