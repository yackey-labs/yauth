package bearer

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// accessClaims is the JWT body for an issued access token. yauth #89
// adds the optional "org" / "role" / "orgs" claims used by the
// active-org subsystem. All three are omitempty so old clients that
// ignore them keep parsing fine, and tokens issued before the
// organizations plugin loads stay backward-compatible.
type accessClaims struct {
	jwt.RegisteredClaims
	Org  string   `json:"org,omitempty"`
	Role string   `json:"role,omitempty"`
	Orgs []string `json:"orgs,omitempty"`
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
type parsedToken struct {
	UserID string
	Org    string
	Role   string
	Orgs   []string
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
	return parsedToken{
		UserID: claims.Subject,
		Org:    claims.Org,
		Role:   claims.Role,
		Orgs:   claims.Orgs,
	}, nil
}
