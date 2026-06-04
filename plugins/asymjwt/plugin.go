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
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes the asymjwt plugin.
//
// Operators supply the keypair via filesystem paths (PrivateKeyPath /
// PublicKeyPath) OR via inline PEM bytes (PrivateKeyPEM / PublicKeyPEM).
// The two modes are mutually exclusive — passing both for the same key
// is rejected at construction time. Inline bytes are typically fed in
// from a secret manager (Vault, AWS Secrets Manager) that lands the
// value in the process environment rather than on disk.
type Config struct {
	// KeyType selects the algorithm: "RS256" (RSA-2048+) or "ES256"
	// (ECDSA P-256). Required.
	KeyType string
	// PrivateKeyPath is a filesystem path to the PEM-encoded private
	// key. Mutually exclusive with PrivateKeyPEM.
	PrivateKeyPath string
	// PublicKeyPath is a filesystem path to the PEM-encoded public key.
	// Mutually exclusive with PublicKeyPEM. Loaded separately so the
	// deployment can ship a JWKS-only public-key bundle to verifiers
	// without exposing the private key.
	PublicKeyPath string
	// PrivateKeyPEM holds the raw PEM bytes of the private key.
	// Mutually exclusive with PrivateKeyPath.
	PrivateKeyPEM []byte
	// PublicKeyPEM holds the raw PEM bytes of the public key.
	// Mutually exclusive with PublicKeyPath.
	PublicKeyPEM []byte
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
	if cfg.PrivateKeyPath != "" && len(cfg.PrivateKeyPEM) > 0 {
		return nil, fmt.Errorf("asymjwt: PrivateKeyPath and PrivateKeyPEM are mutually exclusive")
	}
	if cfg.PublicKeyPath != "" && len(cfg.PublicKeyPEM) > 0 {
		return nil, fmt.Errorf("asymjwt: PublicKeyPath and PublicKeyPEM are mutually exclusive")
	}
	if cfg.PrivateKeyPath == "" && len(cfg.PrivateKeyPEM) == 0 {
		return nil, fmt.Errorf("asymjwt: PrivateKeyPath or PrivateKeyPEM is required")
	}
	if cfg.PublicKeyPath == "" && len(cfg.PublicKeyPEM) == 0 {
		return nil, fmt.Errorf("asymjwt: PublicKeyPath or PublicKeyPEM is required")
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
func (p *asymjwtPlugin) Routes(host plugin.PluginHost, _ plugin.Router, api huma.API, prefix string) {
	if setter, ok := host.(interface{ SetJWTSigner(plugin.JWTSigner) }); ok {
		setter.SetJWTSigner(p.signer)
	}

	// GET {prefix}/.well-known/jwks.json — public, unauthenticated single-key
	// JWKS for the loaded public key. Clean typed output: the precomputed JWKS
	// bytes are emitted as a json.RawMessage body so no per-request marshalling
	// is needed, and Cache-Control is preserved via a header-tagged field.
	huma.Register(api, huma.Operation{
		OperationID: "asymJWKS",
		Method:      http.MethodGet,
		Path:        prefix + "/.well-known/jwks.json",
		Summary:     "Public JWKS document for the loaded asymmetric signer",
		Description: "Returned even when no caller is authenticated; suited to relying parties verifying tokens out of band.",
		Tags:        []string{"asymmetric-jwt"},
		Security:    []map[string][]string{}, // explicitly public
	}, func(_ context.Context, _ *jwksInput) (*jwksOutput, error) {
		body, err := p.signer.PublicJWKS()
		if err != nil {
			return nil, huma.Error500InternalServerError("jwks unavailable")
		}
		return &jwksOutput{
			CacheControl: "public, max-age=300",
			Body:         json.RawMessage(body),
		}, nil
	})
}

// jwksInput has no fields — GET /.well-known/jwks.json takes no parameters or
// body.
type jwksInput struct{}

// jwksOutput emits the precomputed JWKS document. Body is a json.RawMessage so
// huma writes the JWKS JSON directly (Content-Type application/json) and
// CacheControl maps to the Cache-Control response header.
type jwksOutput struct {
	CacheControl string          `header:"Cache-Control"`
	Body         json.RawMessage `contentType:"application/json"`
}
