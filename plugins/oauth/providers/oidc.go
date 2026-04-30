package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	"github.com/yackey-labs/yauth-go/plugins/oauth"
)

// OIDCConfig configures a generic OpenID Connect provider.
//
// Endpoints can be supplied either explicitly (AuthURL/TokenURL/UserInfoURL)
// or implicitly via DiscoveryURL — when DiscoveryURL is set and the
// explicit fields are empty, OIDC sniffs the JSON document at /.well-
// known/openid-configuration and fills the gaps. Any explicit value still
// wins over the discovered one.
type OIDCConfig struct {
	// ProviderName is the URL slug used in /oauth/{name}/... routes.
	// Required.
	ProviderName string

	ClientID     string
	ClientSecret string
	RedirectURL  string

	Scopes []string

	// One of (AuthURL, TokenURL, UserInfoURL) or DiscoveryURL must
	// resolve a complete endpoint set.
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	DiscoveryURL string

	HTTPClient *http.Client
}

// oidcDiscovery is the subset of the well-known doc we consume.
type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcProvider struct {
	cfg         OIDCConfig
	resolved    bool
	authURL     string
	tokenURL    string
	userInfoURL string
}

// OIDC builds a generic OpenID Connect provider. Discovery, when
// configured, runs lazily on first Config() / FetchUserInfo() call so the
// constructor itself never performs network I/O.
func OIDC(cfg OIDCConfig) (oauth.Provider, error) {
	if cfg.ProviderName == "" {
		return nil, errors.New("oidc: ProviderName is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	if cfg.AuthURL == "" || cfg.TokenURL == "" {
		if cfg.DiscoveryURL == "" {
			return nil, errors.New("oidc: must supply AuthURL+TokenURL or DiscoveryURL")
		}
	}
	return &oidcProvider{cfg: cfg}, nil
}

// MustOIDC is the panic-on-error variant suited to compile-time-known
// configurations.
func MustOIDC(cfg OIDCConfig) oauth.Provider {
	p, err := OIDC(cfg)
	if err != nil {
		panic(err)
	}
	return p
}

func (p *oidcProvider) Name() string { return p.cfg.ProviderName }

func (p *oidcProvider) ensureResolved(ctx context.Context) error {
	if p.resolved {
		return nil
	}
	p.authURL = p.cfg.AuthURL
	p.tokenURL = p.cfg.TokenURL
	p.userInfoURL = p.cfg.UserInfoURL

	if (p.authURL == "" || p.tokenURL == "" || p.userInfoURL == "") && p.cfg.DiscoveryURL != "" {
		hc := p.cfg.HTTPClient
		if hc == nil {
			hc = http.DefaultClient
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.DiscoveryURL, nil)
		if err != nil {
			return fmt.Errorf("oidc: build discovery request: %w", err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("oidc: discovery: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("oidc: discovery status %d: %s", resp.StatusCode, string(body))
		}
		var d oidcDiscovery
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			return fmt.Errorf("oidc: decode discovery: %w", err)
		}
		if p.authURL == "" {
			p.authURL = d.AuthorizationEndpoint
		}
		if p.tokenURL == "" {
			p.tokenURL = d.TokenEndpoint
		}
		if p.userInfoURL == "" {
			p.userInfoURL = d.UserInfoEndpoint
		}
	}
	if p.authURL == "" || p.tokenURL == "" {
		return errors.New("oidc: missing authorization_endpoint or token_endpoint")
	}
	p.resolved = true
	return nil
}

// Config implements oauth.Provider. It eagerly attempts discovery using
// context.Background so that callers can call AuthCodeURL synchronously.
// Errors during discovery are surfaced via FetchUserInfo / Exchange,
// which require the same metadata.
func (p *oidcProvider) Config() *oauth2.Config {
	_ = p.ensureResolved(context.Background())
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURL,
		Scopes:       p.cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.authURL,
			TokenURL: p.tokenURL,
		},
	}
}

// oidcUserInfo is the subset of the OIDC userinfo claims we consume. The
// "sub" claim is required; everything else is best-effort.
type oidcUserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerifiedRaw  any    `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
}

func (p *oidcProvider) FetchUserInfo(ctx context.Context, tok *oauth2.Token) (*oauth.UserInfo, error) {
	if err := p.ensureResolved(ctx); err != nil {
		return nil, err
	}
	if p.userInfoURL == "" {
		return nil, errors.New("oidc: provider does not expose a userinfo endpoint")
	}

	hc := p.cfg.HTTPClient
	if hc == nil {
		hc = p.Config().Client(ctx, tok)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build userinfo request: %w", err)
	}
	if p.cfg.HTTPClient != nil {
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("oidc: userinfo status %d: %s", resp.StatusCode, string(body))
	}
	var u oidcUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("oidc: decode userinfo: %w", err)
	}

	name := u.Name
	if name == "" {
		name = u.PreferredUsername
	}

	return &oauth.UserInfo{
		ProviderUserID: u.Sub,
		Email:          strings.TrimSpace(u.Email),
		EmailVerified:  parseEmailVerified(u.EmailVerifiedRaw),
		Name:           name,
		Picture:        u.Picture,
	}, nil
}

// parseEmailVerified accepts both the boolean (per spec) and the
// case-insensitive string forms ("true"/"false") that some providers
// emit.
func parseEmailVerified(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}
