package ssooidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

// Signer signs a JWT from claims (asymjwt.Signer satisfies it). Used to mint a
// software_statement so the RP can federate with NO admin credential.
type Signer interface {
	Sign(claims map[string]any) (string, error)
}

// SignSoftwareStatement builds an RFC 7591 software_statement: a short-lived JWT
// signed by the RP's own key, asserting its issuer + the client metadata it
// wants registered. A trusted-issuer IdP verifies it against the RP's JWKS and
// registers the client with no admin credential or shared secret.
func SignSoftwareStatement(signer Signer, issuer string, redirectURIs []string, clientName, scope string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	return signer.Sign(map[string]any{
		"iss":           issuer,
		"sub":           issuer,
		"iat":           now.Unix(),
		"exp":           now.Add(ttl).Unix(),
		"redirect_uris": redirectURIs,
		"client_name":   clientName,
		"scope":         scope,
	})
}

// FederateInput describes a one-call federation to an upstream yauth/OIDC IdP.
type FederateInput struct {
	// DiscoveryURL is the IdP's OIDC discovery document.
	DiscoveryURL string
	// AdminAPIKey authorizes the dynamic client registration at the IdP
	// (sent as X-Api-Key). Optional when SoftwareStatement is set. In production
	// prefer a short-lived, single-use grant over a long-lived key.
	AdminAPIKey string
	// SoftwareStatement is a JWT signed by THIS app's key (see
	// SignSoftwareStatement). When the IdP trusts this app's issuer, it
	// authorizes confidential registration with no admin credential — the
	// easiest, zero-secret federation. Takes precedence over AdminAPIKey.
	SoftwareStatement string

	OrganizationID         string
	ConnectionName         string
	RedirectURI            string // the RP's callback, e.g. https://app/api/auth/sso/callback
	Scopes                 []string
	JitProvisioningEnabled bool
	DefaultRoleOnJit       string
	GroupToRole            map[string]string

	HTTPClient *http.Client
}

// Federate makes this app a relying party of an upstream OIDC IdP in one call,
// with NO client_secret ever copy-pasted: it reads the IdP's discovery doc,
// dynamically registers a confidential client there (RFC 7591), and seeds the
// local SSO connection with the returned credentials (secret encrypted at rest).
//
// It is the easiest yauth→yauth path: the admin supplies the IdP URL + an admin
// credential; the secret is generated at the IdP and stored server-side.
func Federate(ctx context.Context, repo connectionRepo, key [32]byte, in FederateInput) (domain.SsoConnection, error) {
	hc := in.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile", "groups"}
	}

	// Idempotent: if this org already has a connection to this IdP, return it
	// instead of registering a second client. Safe to call on every boot.
	if existing, err := repo.ListSsoConnectionsByOrg(ctx, in.OrganizationID); err == nil {
		for _, c := range existing {
			if cfg, derr := unmarshalOidcConfig(key, c.Config); derr == nil && cfg.DiscoveryURL == in.DiscoveryURL {
				return *c, nil
			}
		}
	}

	regEndpoint, err := discoverRegistrationEndpoint(ctx, hc, in.DiscoveryURL)
	if err != nil {
		return domain.SsoConnection{}, err
	}

	clientID, clientSecret, err := dynamicRegister(ctx, hc, regEndpoint, in.AdminAPIKey, dcrRequest{
		ClientName:              in.ConnectionName,
		RedirectURIs:            []string{in.RedirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   strings.Join(scopes, " "),
		SoftwareStatement:       in.SoftwareStatement,
	})
	if err != nil {
		return domain.SsoConnection{}, err
	}

	return SeedConnection(ctx, repo, key, SeedConnectionInput{
		OrganizationID:         in.OrganizationID,
		Name:                   in.ConnectionName,
		JitProvisioningEnabled: in.JitProvisioningEnabled,
		DefaultRoleOnJit:       in.DefaultRoleOnJit,
		OIDC: OidcConnectionConfig{
			DiscoveryURL: in.DiscoveryURL,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			// Keep standard claim defaults but carry the caller's group→role map.
			ClaimMappings: ClaimMappings{
				Email:       "email",
				DisplayName: "name",
				Groups:      "groups",
				GroupToRole: in.GroupToRole,
			},
		},
	})
}

func discoverRegistrationEndpoint(ctx context.Context, hc *http.Client, discoveryURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("ssooidc: fetch discovery: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ssooidc: discovery returned %d", res.StatusCode)
	}
	var doc struct {
		RegistrationEndpoint string `json:"registration_endpoint"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("ssooidc: decode discovery: %w", err)
	}
	if doc.RegistrationEndpoint == "" {
		return "", fmt.Errorf("ssooidc: IdP advertises no registration_endpoint (enable DCR)")
	}
	return doc.RegistrationEndpoint, nil
}

type dcrRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	SoftwareStatement       string   `json:"software_statement,omitempty"`
}

func dynamicRegister(ctx context.Context, hc *http.Client, endpoint, apiKey string, body dcrRequest) (clientID, clientSecret string, err error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("ssooidc: dynamic registration: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("ssooidc: dynamic registration returned %d: %s", res.StatusCode, strings.TrimSpace(string(payload)))
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", "", fmt.Errorf("ssooidc: decode registration response: %w", err)
	}
	if out.ClientID == "" || out.ClientSecret == "" {
		return "", "", fmt.Errorf("ssooidc: registration returned no confidential client credentials (is confidential DCR enabled?)")
	}
	return out.ClientID, out.ClientSecret, nil
}
