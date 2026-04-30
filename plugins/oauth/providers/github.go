package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"

	"github.com/yackey-labs/yauth-go/plugins/oauth"
)

// GitHubConfig configures a GitHub OAuth provider.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// UserAPI / EmailAPI override the GitHub v3 endpoints; useful in
	// tests, leave empty otherwise.
	UserAPI    string
	EmailAPI   string
	HTTPClient *http.Client
}

type githubProvider struct {
	cfg GitHubConfig
}

// GitHub returns a Provider for GitHub's OAuth endpoints.
func GitHub(cfg GitHubConfig) oauth.Provider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"read:user", "user:email"}
	}
	if cfg.UserAPI == "" {
		cfg.UserAPI = "https://api.github.com/user"
	}
	if cfg.EmailAPI == "" {
		cfg.EmailAPI = "https://api.github.com/user/emails"
	}
	return &githubProvider{cfg: cfg}
}

func (p *githubProvider) Name() string { return "github" }

func (p *githubProvider) Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURL,
		Scopes:       p.cfg.Scopes,
		Endpoint:     githuboauth.Endpoint,
	}
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *githubProvider) FetchUserInfo(ctx context.Context, tok *oauth2.Token) (*oauth.UserInfo, error) {
	hc := p.cfg.HTTPClient
	if hc == nil {
		hc = p.Config().Client(ctx, tok)
	}
	user, err := p.fetchUser(ctx, hc, tok.AccessToken)
	if err != nil {
		return nil, err
	}

	email := strings.TrimSpace(user.Email)
	verified := email != "" // GitHub only puts a primary verified email here.
	if email == "" {
		// Fall back to the emails endpoint to find the primary
		// verified address.
		emails, err := p.fetchEmails(ctx, hc, tok.AccessToken)
		if err == nil {
			for _, e := range emails {
				if e.Primary && e.Verified {
					email = e.Email
					verified = true
					break
				}
			}
			if email == "" {
				for _, e := range emails {
					if e.Verified {
						email = e.Email
						verified = true
						break
					}
				}
			}
		}
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}

	return &oauth.UserInfo{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Email:          email,
		EmailVerified:  verified,
		Name:           name,
		Picture:        user.AvatarURL,
	}, nil
}

func (p *githubProvider) fetchUser(ctx context.Context, hc *http.Client, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("github: build user request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if p.cfg.HTTPClient != nil {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: user: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github: user status %d: %s", resp.StatusCode, string(body))
	}
	var u githubUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("github: decode user: %w", err)
	}
	return &u, nil
}

func (p *githubProvider) fetchEmails(ctx context.Context, hc *http.Client, accessToken string) ([]githubEmail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.EmailAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("github: build emails request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if p.cfg.HTTPClient != nil {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: emails: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github: emails status %d: %s", resp.StatusCode, string(body))
	}
	var out []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("github: decode emails: %w", err)
	}
	return out, nil
}
