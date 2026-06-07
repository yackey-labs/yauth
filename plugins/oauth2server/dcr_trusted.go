package oauth2server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// trustedStatement is the verified result of a DCR software_statement.
type trustedStatement struct {
	Issuer       string
	RedirectURIs []string
	ClientName   string
	Scope        string
}

func (p *oauth2Plugin) trustedIssuerClient() *http.Client {
	if p.cfg.DCRTrustedIssuerHTTPClient != nil {
		return p.cfg.DCRTrustedIssuerHTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// verifySoftwareStatement validates a DCR software_statement (RFC 7591): it reads
// the unverified `iss`, requires it to be allow-listed, fetches that issuer's
// JWKS via its OIDC discovery, and verifies the JWT signature + standard claims.
// On success the registrant has proven control of a trusted issuer — no admin
// credential or shared secret required. Returns the attested client metadata.
func (p *oauth2Plugin) verifySoftwareStatement(ctx context.Context, jws string) (*trustedStatement, error) {
	if len(p.cfg.DCRTrustedIssuers) == 0 {
		return nil, errors.New("trusted-issuer DCR is disabled")
	}
	// 1. Unverified read of iss so we know which issuer's keys to trust.
	unverified, err := jwt.Parse([]byte(jws), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("software_statement parse: %w", err)
	}
	iss := strings.TrimSpace(unverified.Issuer())
	if iss == "" || !issuerAllowed(iss, p.cfg.DCRTrustedIssuers) {
		return nil, fmt.Errorf("software_statement issuer %q is not trusted", iss)
	}

	// 2. Resolve the issuer's JWKS via its discovery document.
	jwksURI, err := fetchIssuerJWKSURI(ctx, p.trustedIssuerClient(), iss)
	if err != nil {
		return nil, err
	}
	set, err := jwk.Fetch(ctx, jwksURI, jwk.WithHTTPClient(p.trustedIssuerClient()))
	if err != nil {
		return nil, fmt.Errorf("fetch trusted issuer JWKS: %w", err)
	}

	// 3. Verify signature + standard claims (exp, iss) against that key set.
	tok, err := jwt.Parse([]byte(jws),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(iss),
		jwt.WithAcceptableSkew(60*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("software_statement verification failed: %w", err)
	}

	out := &trustedStatement{Issuer: tok.Issuer()}
	if v, ok := tok.Get("redirect_uris"); ok {
		out.RedirectURIs = toStringSlice(v)
	}
	if v, ok := tok.Get("client_name"); ok {
		if s, ok := v.(string); ok {
			out.ClientName = s
		}
	}
	if v, ok := tok.Get("scope"); ok {
		if s, ok := v.(string); ok {
			out.Scope = s
		}
	}
	return out, nil
}

func issuerAllowed(iss string, allow []string) bool {
	norm := strings.TrimRight(iss, "/")
	for _, a := range allow {
		if strings.TrimRight(strings.TrimSpace(a), "/") == norm {
			return true
		}
	}
	return false
}

func fetchIssuerJWKSURI(ctx context.Context, hc *http.Client, issuer string) (string, error) {
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch trusted issuer discovery: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trusted issuer discovery returned %d", res.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode trusted issuer discovery: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("trusted issuer advertises no jwks_uri")
	}
	return doc.JWKSURI, nil
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
