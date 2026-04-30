// Package asymjwt implements a yauth-go plugin that loads an asymmetric
// signing keypair (RSA-2048 / RS256 or ECDSA P-256 / ES256) from PEM
// files and registers a plugin.JWTSigner with the host so that other
// plugins (oidc, oauth2-server) can mint and validate signed JWTs.
//
// The plugin also serves the public key as a JWKS document at
// {prefix}/.well-known/jwks.json, suitable for relying parties that
// need to verify tokens out-of-band.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	GET {prefix}/.well-known/jwks.json   single-key JWKS for the loaded public key
//
// Bearer interaction (MVP):
//
// The bearer plugin (#10) captures its HS256 secret at Routes() time and
// does not consult host.JWTSigner() lazily. As a result, loading the
// asymjwt plugin does NOT change how bearer signs its access tokens —
// bearer remains HS256 unless explicitly opted in by a future revision
// of that plugin. The asymjwt plugin is wired so that downstream
// consumers (oidc id_token issuance in #19, oauth2-server) can pick it
// up; bearer parity will be addressed when bearer is re-issued.
package asymjwt

import (
	"fmt"
	"net/http"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes the asymjwt plugin.
type Config struct {
	// KeyType selects the algorithm: "RS256" (RSA-2048+) or "ES256"
	// (ECDSA P-256). Required.
	KeyType string
	// PrivateKeyPath is a filesystem path to the PEM-encoded private
	// key. Required.
	PrivateKeyPath string
	// PublicKeyPath is a filesystem path to the PEM-encoded public key.
	// Required. Loaded separately so the deployment can ship a
	// JWKS-only public-key bundle to verifiers without exposing the
	// private key.
	PublicKeyPath string
	// KID is the JWS "kid" header value. It is also the kid attached
	// to the JWKS entry. Required — chosen by the operator so verifying
	// peers can pin a key id (e.g., "yauth-2026").
	KID string
}

// asymjwtPlugin is the unexported plugin.Plugin implementation.
type asymjwtPlugin struct {
	cfg    Config
	signer *Signer
}

// New constructs the asymjwt plugin and loads the configured keypair.
// Loading happens at construction time (not in Routes) so configuration
// errors surface during build, before HTTP traffic starts.
func New(cfg Config) (plugin.Plugin, error) {
	if cfg.KeyType == "" {
		return nil, fmt.Errorf("asymjwt: KeyType is required (\"RS256\" or \"ES256\")")
	}
	if cfg.PrivateKeyPath == "" || cfg.PublicKeyPath == "" {
		return nil, fmt.Errorf("asymjwt: PrivateKeyPath and PublicKeyPath are required")
	}
	if cfg.KID == "" {
		return nil, fmt.Errorf("asymjwt: KID is required")
	}
	signer, err := NewSigner(cfg)
	if err != nil {
		return nil, err
	}
	return &asymjwtPlugin{cfg: cfg, signer: signer}, nil
}

// Name implements plugin.Plugin.
func (p *asymjwtPlugin) Name() string { return "asymmetric-jwt" }

// Routes implements plugin.Plugin. It registers the loaded signer with
// the host (via SetJWTSigner if the host supports it) and mounts the
// JWKS endpoint.
func (p *asymjwtPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	if setter, ok := host.(interface{ SetJWTSigner(plugin.JWTSigner) }); ok {
		setter.SetJWTSigner(p.signer)
	}
	mux.Handle("GET "+prefix+"/.well-known/jwks.json", http.HandlerFunc(p.handleJWKS()))
}
