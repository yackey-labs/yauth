// discovery.go — OIDC Discovery (RFC 8414 / OpenID Connect Discovery
// 1.0) fetch + parse. Pure read-side; the result is the inputs to the
// authorize/token/JWKS round-trips that follow.
package ssooidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
)

// DiscoveryDocument is the parsed metadata. Only the fields yauth's
// OIDC client uses are decoded; unknown fields are ignored.
type DiscoveryDocument struct {
	Issuer           string   `json:"issuer"`
	AuthorizationURL string   `json:"authorization_endpoint"`
	TokenURL         string   `json:"token_endpoint"`
	UserInfoURL      string   `json:"userinfo_endpoint,omitempty"`
	JWKSURL          string   `json:"jwks_uri"`
	ResponseTypes    []string `json:"response_types_supported,omitempty"`
	GrantTypes       []string `json:"grant_types_supported,omitempty"`
	SubjectTypes     []string `json:"subject_types_supported,omitempty"`
	IDTokenAlgs      []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported  []string `json:"scopes_supported,omitempty"`
	CodeChallengeAlg []string `json:"code_challenge_methods_supported,omitempty"`
}

// errIdPUnreachable marks every failure that came from actually reaching out
// to the configured IdP, as opposed to a failure to understand what came back.
// Handlers collapse it to a fixed string on the wire and log the detail; see
// idpFetchMessage.
var errIdPUnreachable = errors.New("could not reach the IdP")

// urlOrigin returns the scheme://host[:port] of raw, lowercased, with the
// scheme's default port elided so "https://idp.example" and
// "https://idp.example:443" compare equal. Used for the two places that must
// compare "same server" without comparing paths.
func urlOrigin(raw string) (string, error) {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("not a valid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return "", errors.New("URL has no scheme or host")
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	switch {
	case port != "":
		host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"): // bare IPv6 literal
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

// fetchDiscovery GETs the discovery URL and parses the body. The
// caller controls cancellation via ctx.
func fetchDiscovery(ctx context.Context, client *http.Client, discoveryURL string) (*DiscoveryDocument, error) {
	url := strings.TrimSpace(discoveryURL)
	if url == "" {
		return nil, errors.New("ssooidc: discovery_url is empty")
	}
	// The origin the OPERATOR configured, captured before the well-known
	// auto-append below, so the issuer pin at the bottom compares against
	// what was actually typed into the connection row.
	configuredOrigin, originErr := urlOrigin(url)
	// Some IdP admins paste the issuer URL itself; auto-append the
	// well-known path so the call still works.
	if !strings.Contains(url, "/.well-known/") {
		url = strings.TrimRight(url, "/") + "/.well-known/openid-configuration"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// errIdPUnreachable so the admin-facing handlers can collapse this
		// whole class to one fixed sentence. The wrapped error distinguishes
		// refused / timeout / TLS-mismatch / "safehttp refused the dial" per
		// host and port — which is a working network scanner for whoever
		// supplied the URL — and net/url folds the full destination into its
		// text, so it must be logged, never returned.
		return nil, fmt.Errorf("%w: %v", errIdPUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse discovery doc: %w", err)
	}
	if doc.Issuer == "" || doc.AuthorizationURL == "" || doc.TokenURL == "" || doc.JWKSURL == "" {
		return nil, errors.New("ssooidc: discovery doc missing required fields")
	}
	// Pin the claimed issuer to the origin the document was served from
	// (OpenID Connect Discovery 1.0 §4.3 requires them to match).
	//
	// Without this the id_token check downstream is circular: handlers_login
	// passes doc.Issuer in as the expected `iss` and doc.JWKSURL in as the key
	// source, both read out of this same document, so a document served by
	// evil.example that claims `issuer: https://login.microsoftonline.com/...`
	// and points jwks_uri at its own keys validates perfectly. Nothing in that
	// chain ties back to the host the operator configured. (ExternalIdentity
	// rows are keyed on IssuerKeyFromDiscoveryURL — the real origin — so this
	// is conformance and defence in depth, not the only thing standing between
	// a lying issuer and an account takeover.)
	//
	// ORIGIN ONLY, never the path: Azure AD serves
	// .../common/v2.0/.well-known/openid-configuration with issuer
	// https://login.microsoftonline.com/{tenant}/v2.0, and yauth's own OP
	// example serves discovery at /.well-known/... with issuer /api/auth. A
	// path-sensitive comparison would lock out both.
	if originErr != nil {
		return nil, fmt.Errorf("ssooidc: cannot check the discovery document's issuer: discovery_url %v", originErr)
	}
	issuerOrigin, err := urlOrigin(doc.Issuer)
	if err != nil {
		return nil, fmt.Errorf("ssooidc: discovery doc issuer %q is not a valid URL", doc.Issuer)
	}
	if issuerOrigin != configuredOrigin {
		return nil, fmt.Errorf("ssooidc: discovery doc claims issuer %q, which is not served by %s; "+
			"refusing a document that names another origin", doc.Issuer, configuredOrigin)
	}
	return &doc, nil
}
