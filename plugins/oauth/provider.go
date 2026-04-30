package oauth

import (
	"context"

	"golang.org/x/oauth2"
)

// UserInfo is the normalized profile returned by Provider.FetchUserInfo.
//
// Provider implementations are responsible for adapting the upstream API's
// shape onto this struct. Empty fields are permitted: a provider that does
// not expose a verified-email signal may set EmailVerified=false and the
// callback handler will treat the new account as unverified.
type UserInfo struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	Picture        string
}

// Provider abstracts an OAuth/OIDC identity source. Implementations live in
// plugins/oauth/providers/ and are passed to Config.Providers at build time.
//
// Name is the URL slug used in /oauth/{provider}/... routes. Two providers
// MUST NOT share a name within a single Config.
//
// Config returns the *oauth2.Config used for the authorization-code flow.
// The RedirectURL field must already be set; the plugin does not rewrite
// it.
//
// FetchUserInfo exchanges an issued token for the provider's userinfo /
// profile and normalizes the result onto the UserInfo struct.
type Provider interface {
	Name() string
	Config() *oauth2.Config
	FetchUserInfo(ctx context.Context, tok *oauth2.Token) (*UserInfo, error)
}
