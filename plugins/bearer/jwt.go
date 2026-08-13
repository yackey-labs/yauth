package bearer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/plugin"
)

// accessClaims is the JWT body for an issued access token. yauth #89
// adds the optional "org" / "role" / "orgs" claims used by the
// active-org subsystem. All three are omitempty so old clients that
// ignore them keep parsing fine, and tokens issued before the
// organizations plugin loads stay backward-compatible.
//
// TokenUse and Scope are NEVER emitted by this plugin — signAccessToken
// leaves both zero. They are parsed because the oauth2-server plugin signs
// its access tokens with the SAME HS256 secret when no asymmetric signer is
// loaded (see oauth2server.signAccessToken), so an OAuth2 access token can
// arrive on this code path and must be recognised as the delegated
// credential it is rather than mistaken for a first-party /token grant.
type accessClaims struct {
	jwt.RegisteredClaims
	Org      string   `json:"org,omitempty"`
	Role     string   `json:"role,omitempty"`
	Orgs     []string `json:"orgs,omitempty"`
	TokenUse string   `json:"token_use,omitempty"`
	Scope    string   `json:"scope,omitempty"`
}

// activeOrgClaims is the trio of additive claims yauth #89 layers on
// top of the standard registered set. Pulled into its own struct so
// callers (mintTokens) can build a value without touching the jwt
// library directly. A zero value emits no claims.
type activeOrgClaims struct {
	Org  string
	Role string
	Orgs []string
}

// signAccessToken issues an HS256 JWT for userID with the given TTL.
// The "sub" claim carries userID; "iss"/"aud" are taken from cfg.
// "jti" is a fresh UUID so revocation lists can target individual
// tokens later. yauth #89 active-org claims are encoded when active
// is non-zero.
func signAccessToken(secret []byte, userID, jti string, cfg Config, now time.Time, active activeOrgClaims) (string, time.Time, error) {
	exp := now.Add(cfg.AccessTTL)
	c := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Org:  active.Org,
		Role: active.Role,
		Orgs: active.Orgs,
		// Stamp what kind of JWT this is. The deployment's HS256 secret also
		// signs id_tokens, DCR registration-access tokens and back-channel
		// logout tokens, none of which are API credentials; a positive marker
		// is what lets verifyAccessToken tell them apart. See the switch there.
		TokenUse: firstPartyTokenUse,
	}
	if cfg.Audience != "" {
		c.Audience = jwt.ClaimStrings{cfg.Audience}
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("bearer: sign access token: %w", err)
	}
	return tok, exp, nil
}

// parsedToken carries the verified claim set returned by
// verifyAccessToken: the user id plus the yauth #89 active-org claims
// so the resolver can hydrate AuthUser without an extra repo lookup
// on the hot path.
//
// Audience/Scope/Delegated carry the OAuth2 dimension. A token minted by
// THIS plugin's /token endpoint is the user's own credential: Delegated is
// false, Scope is empty, and it keeps the full authority it always had. A
// token minted by the oauth2-server plugin for a relying party carries
// `token_use: "access"` and an `aud` naming that client, and is marked
// Delegated unless its audience is one the deployment declared as its own
// (Config.ResourceIdentifiers).
type parsedToken struct {
	UserID    string
	Org       string
	Role      string
	Orgs      []string
	Audience  []string
	Scope     []string
	Delegated bool
}

// verifyAccessToken parses and validates a Bearer JWT against secret and
// cfg. Returns the user ID from "sub" plus the yauth #89 active-org
// claims (empty when not present in the token).
func verifyAccessToken(secret []byte, raw string, cfg Config) (parsedToken, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithExpirationRequired(),
	}
	if cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(cfg.Audience))
	}
	parser := jwt.NewParser(opts...)

	var claims accessClaims
	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return parsedToken{}, err
	}
	if !tok.Valid {
		return parsedToken{}, errors.New("bearer: token not valid")
	}
	if claims.Subject == "" {
		return parsedToken{}, errors.New("bearer: missing sub claim")
	}
	pt := parsedToken{
		UserID:   claims.Subject,
		Org:      claims.Org,
		Role:     claims.Role,
		Orgs:     claims.Orgs,
		Audience: []string(claims.Audience),
	}
	// Decide what KIND of JWT this is, positively, before treating it as a
	// credential. Everything reaching this point was signed with
	// host.JWTSecret() — and on a deployment running oauth2server without
	// asymjwt (the supported HS256 fallback) that same secret also signs
	// id_tokens, DCR registration-access tokens and back-channel logout
	// tokens. None of those is an API credential, and each is deliberately
	// handed to a party that is not the user: the id_token to the relying
	// party and through it the browser, the registration token to whoever
	// called DCR, the logout token to every RP's back-channel endpoint.
	//
	// verifyAsymAccessToken has required a positive `token_use` since #85 for
	// exactly this reason. This is the same gate on the symmetric path.
	switch claims.TokenUse {
	case firstPartyTokenUse:
		// This plugin's own /token credential: the user acting in their own
		// right, full authority, no scope restriction.
	case accessTokenUse:
		// oauth2server's access token. Classify it as the delegated OAuth2
		// credential it is.
		pt.Scope = splitScope(claims.Scope)
		pt.Delegated = !audienceIsSelf(pt.Audience, cfg.ResourceIdentifiers)
	case "":
		// Minted before this plugin stamped a marker. Accepting it keeps the
		// upgrade from logging every active user out, but only where it cannot
		// be one of the foreign kinds: signAccessToken emits `aud` ONLY when
		// Config.Audience is set — and when it is, the parser above already
		// enforced that audience. Every foreign kind, by contrast, always
		// carries a client_id in `aud`. So a marker-less token bearing an
		// audience is a JWT of another kind and is refused.
		//
		// This branch is a migration window, not a permanent allowance: once
		// one AccessTTL has elapsed past the upgrade, no legitimate token
		// reaches it.
		if len(pt.Audience) > 0 {
			return parsedToken{}, errors.New("bearer: not an access token")
		}
	default:
		return parsedToken{}, errors.New("bearer: not an access token")
	}
	return pt, nil
}

// accessTokenUse is the `token_use` value oauth2server stamps on an OAuth2
// access token (oauth2server.signAccessToken).
const accessTokenUse = "access"

// firstPartyTokenUse is the `token_use` value THIS plugin stamps on the
// credential it mints at /token. It is deliberately distinct from
// accessTokenUse: the two carry different authority, and a token that claims
// neither marker is not a credential this resolver will honour.
const firstPartyTokenUse = "yauth_access"

// splitScope splits an RFC 6749 §3.3 space-delimited scope string. Returns
// nil for an empty/whitespace-only value so "no scope claim" and "empty
// scope claim" are indistinguishable — both mean nothing was granted.
func splitScope(s string) []string {
	out := strings.Fields(s)
	if len(out) == 0 {
		return nil
	}
	return out
}

// audienceIsSelf reports whether aud names THIS deployment's own API — i.e.
// whether the token was issued to be presented here rather than to a relying
// party.
//
// With no resource identifiers configured the answer is always false, and
// every OAuth2 access token is therefore delegated. That is the safe default
// and it costs nothing on upgrade: such tokens still authenticate (so
// /userinfo and ordinary application routes are unaffected), they just stop
// counting as the user acting in their own right on the routes that mint
// credentials or change authentication factors. A deployment that genuinely
// issues access tokens FOR its own API — its first-party SPA registered as an
// OAuth client, say — names that audience in Config.ResourceIdentifiers to
// restore full authority for exactly those tokens, and nothing else.
//
// A non-matching audience is not rejected here: OIDC relying parties are
// SUPPOSED to hold tokens audienced at themselves and present them to
// /userinfo. Rejecting them would break the flow the audience is evidence of.
func audienceIsSelf(aud, resourceIdentifiers []string) bool {
	if len(resourceIdentifiers) == 0 || len(aud) == 0 {
		return false
	}
	for _, want := range resourceIdentifiers {
		if want == "" {
			continue
		}
		for _, got := range aud {
			if got == want {
				return true
			}
		}
	}
	return false
}

// verifyAsymAccessToken validates raw against an asymmetric host signer
// (RS256/ES256). It is the path that accepts first-party access tokens minted
// by the oauth2-server plugin, which signs with the shared asymjwt key rather
// than the bearer plugin's HS256 secret. Both token families carry the user id
// in "sub" and the optional yauth #89 active-org claims, so a successful verify
// resolves to the same parsedToken shape.
//
// Only tokens explicitly marked `token_use: "access"` are accepted. That gate
// is what keeps id_tokens and DCR registration-access tokens — signed by the
// same key — from being replayed as API credentials.
//
// Every token that arrives here is an OAuth2 access token by construction, so
// its `aud` and `scope` are recorded and it is marked DELEGATED unless the
// audience is one the deployment declared as its own resource identifier. It
// still resolves to the user — a relying party legitimately acts for them —
// but it is not that user acting in their own right, and
// middleware.RequireUserPrincipalHuma refuses it on the routes where the
// difference matters. Before this, such a token was indistinguishable from a
// session: an app granted "openid profile" could mint the user a permanent
// personal API key and strip their MFA.
func verifyAsymAccessToken(signer plugin.JWTSigner, raw string, cfg Config) (parsedToken, error) {
	claims, err := signer.Verify(raw)
	if err != nil {
		return parsedToken{}, err
	}
	if use, _ := claims["token_use"].(string); use != accessTokenUse {
		return parsedToken{}, errors.New("bearer: not an access token")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return parsedToken{}, errors.New("bearer: missing sub claim")
	}
	pt := parsedToken{UserID: sub}
	if v, ok := claims["org"].(string); ok {
		pt.Org = v
	}
	if v, ok := claims["role"].(string); ok {
		pt.Role = v
	}
	if list, ok := claims["orgs"].([]any); ok {
		for _, o := range list {
			if s, ok := o.(string); ok {
				pt.Orgs = append(pt.Orgs, s)
			}
		}
	}
	if v, ok := claims["scope"].(string); ok {
		pt.Scope = splitScope(v)
	}
	pt.Audience = audienceClaim(claims["aud"])
	pt.Delegated = !audienceIsSelf(pt.Audience, cfg.ResourceIdentifiers)
	return pt, nil
}

// audienceClaim normalises a JWT `aud` claim, which RFC 7519 §4.1.3 allows to
// be either a single string or an array of strings.
func audienceClaim(v any) []string {
	switch aud := v.(type) {
	case string:
		if aud == "" {
			return nil
		}
		return []string{aud}
	case []any:
		out := make([]string, 0, len(aud))
		for _, a := range aud {
			if s, ok := a.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []string:
		return aud
	}
	return nil
}
