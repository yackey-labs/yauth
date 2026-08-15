package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/yackey-labs/yauth/plugins/oauth"
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
	cfg OIDCConfig

	// mu guards every field below it. One *oidcProvider is shared by every
	// request that starts a social login, and Config() re-runs resolution on
	// each call, so concurrent logins are concurrent writers. Resolution also
	// happens UNDER this lock rather than merely publishing under it: that
	// collapses a burst of simultaneous first logins into a single discovery
	// fetch instead of one per request.
	mu          sync.Mutex
	resolved    bool
	authURL     string
	tokenURL    string
	userInfoURL string
}

// oidcEndpoints is an immutable snapshot of the resolved endpoints, returned
// by ensureResolved so callers never read the provider's fields directly.
type oidcEndpoints struct {
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

// ensureResolved resolves the endpoints once and returns a snapshot of them.
//
// It builds the result in LOCALS and publishes to the struct only on success.
// The previous version assigned p.authURL/p.tokenURL/p.userInfoURL from the
// config at the top — resetting them to "" on a discovery-based provider —
// and repopulated them only after the network fetch returned. Any concurrent
// reader in that window saw an empty endpoint, and Config() discards the error
// by design, so the caller was handed an oauth2.Config that redirects nowhere.
// Resolving into locals means the fields are never observable in a partial
// state, whatever the interleaving.
func (p *oidcProvider) ensureResolved(ctx context.Context) (oidcEndpoints, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resolved {
		return oidcEndpoints{authURL: p.authURL, tokenURL: p.tokenURL, userInfoURL: p.userInfoURL}, nil
	}

	authURL := p.cfg.AuthURL
	tokenURL := p.cfg.TokenURL
	userInfoURL := p.cfg.UserInfoURL

	if (authURL == "" || tokenURL == "" || userInfoURL == "") && p.cfg.DiscoveryURL != "" {
		hc := p.cfg.HTTPClient
		if hc == nil {
			hc = http.DefaultClient
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.DiscoveryURL, nil)
		if err != nil {
			return oidcEndpoints{}, fmt.Errorf("oidc: build discovery request: %w", err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return oidcEndpoints{}, fmt.Errorf("oidc: discovery: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			body, _ := io.ReadAll(resp.Body)
			return oidcEndpoints{}, fmt.Errorf("oidc: discovery status %d: %s", resp.StatusCode, string(body))
		}
		var d oidcDiscovery
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			return oidcEndpoints{}, fmt.Errorf("oidc: decode discovery: %w", err)
		}
		if authURL == "" {
			authURL = d.AuthorizationEndpoint
		}
		if tokenURL == "" {
			tokenURL = d.TokenEndpoint
		}
		if userInfoURL == "" {
			userInfoURL = d.UserInfoEndpoint
		}
	}
	if authURL == "" || tokenURL == "" {
		return oidcEndpoints{}, errors.New("oidc: missing authorization_endpoint or token_endpoint")
	}

	p.authURL, p.tokenURL, p.userInfoURL = authURL, tokenURL, userInfoURL
	p.resolved = true
	return oidcEndpoints{authURL: authURL, tokenURL: tokenURL, userInfoURL: userInfoURL}, nil
}

// Config implements oauth.Provider. It eagerly attempts discovery using
// context.Background so that callers can call AuthCodeURL synchronously.
// Errors during discovery are surfaced via FetchUserInfo / Exchange,
// which require the same metadata.
func (p *oidcProvider) Config() *oauth2.Config {
	// Bounded rather than context.Background(): resolution holds p.mu for its
	// duration, so an IdP that accepts the connection and then never answers
	// would otherwise park every concurrent login on the lock indefinitely.
	// http.DefaultClient, the fallback when no HTTPClient is configured, has no
	// timeout of its own.
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	eps, _ := p.ensureResolved(ctx)
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURL,
		Scopes:       p.cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  eps.authURL,
			TokenURL: eps.tokenURL,
		},
	}
}

// discoveryTimeout bounds a lazy discovery fetch started from Config(), which
// has no caller-supplied context to inherit a deadline from.
const discoveryTimeout = 10 * time.Second

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
	eps, err := p.ensureResolved(ctx)
	if err != nil {
		return nil, err
	}
	if eps.userInfoURL == "" {
		return nil, errors.New("oidc: provider does not expose a userinfo endpoint")
	}

	hc := p.cfg.HTTPClient
	if hc == nil {
		hc = p.Config().Client(ctx, tok)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, eps.userInfoURL, nil)
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
