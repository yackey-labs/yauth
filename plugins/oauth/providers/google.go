// Package providers ships the built-in oauth.Provider implementations
// (Google, GitHub, generic OIDC). They are tiny adapters that produce an
// *oauth2.Config and translate the upstream userinfo response onto an
// oauth.UserInfo.
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"

	"github.com/yackey-labs/yauth/plugins/oauth"
)

// GoogleConfig configures a Google OAuth provider.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes overrides the default openid/email/profile set when non-empty.
	Scopes []string
	// UserInfoURL overrides the default v3 userinfo endpoint. Useful in
	// tests; production callers should leave it empty.
	UserInfoURL string
	// HTTPClient overrides the HTTP client used for userinfo. If nil,
	// http.DefaultClient is used. The token endpoint is still driven by
	// oauth2.Config which uses the context-bound client.
	HTTPClient *http.Client
}

type googleProvider struct {
	cfg GoogleConfig
}

// Google returns a Provider for Google's OAuth/OIDC endpoints.
func Google(cfg GoogleConfig) oauth.Provider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	}
	return &googleProvider{cfg: cfg}
}

func (p *googleProvider) Name() string { return "google" }

func (p *googleProvider) Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURL,
		Scopes:       p.cfg.Scopes,
		Endpoint:     googleoauth.Endpoint,
	}
}

// googleUserInfo mirrors the v3 OpenID Connect userinfo schema we care about.
type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (p *googleProvider) FetchUserInfo(ctx context.Context, tok *oauth2.Token) (*oauth.UserInfo, error) {
	hc := p.cfg.HTTPClient
	// When HTTPClient is nil (production), wrap with the OAuth2 client that
	// auto-attaches the bearer token. When set (tests), use it as-is — test
	// servers may inspect or short-circuit auth themselves.
	if hc == nil {
		hc = p.Config().Client(ctx, tok)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("google: build userinfo request: %w", err)
	}
	if p.cfg.HTTPClient != nil {
		// Test path: still attach the bearer so the mock server can
		// validate it if it wants to.
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google: userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google: userinfo status %d: %s", resp.StatusCode, string(body))
	}
	var u googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("google: decode userinfo: %w", err)
	}
	return &oauth.UserInfo{
		ProviderUserID: u.Sub,
		Email:          u.Email,
		EmailVerified:  u.EmailVerified,
		Name:           u.Name,
		Picture:        u.Picture,
	}, nil
}
