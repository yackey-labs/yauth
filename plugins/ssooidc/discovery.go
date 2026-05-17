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
	"net/http"
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

// fetchDiscovery GETs the discovery URL and parses the body. The
// caller controls cancellation via ctx.
func fetchDiscovery(ctx context.Context, client *http.Client, discoveryURL string) (*DiscoveryDocument, error) {
	url := strings.TrimSpace(discoveryURL)
	if url == "" {
		return nil, errors.New("ssooidc: discovery_url is empty")
	}
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
		return nil, fmt.Errorf("fetch discovery: %w", err)
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
	return &doc, nil
}
