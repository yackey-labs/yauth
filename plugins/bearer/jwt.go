package bearer

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// accessClaims is the JWT body for an issued access token.
type accessClaims struct {
	jwt.RegisteredClaims
}

// signAccessToken issues an HS256 JWT for userID with the given TTL.
// The "sub" claim carries userID; "iss"/"aud" are taken from cfg.
// "jti" is a fresh UUID so revocation lists can target individual
// tokens later.
func signAccessToken(secret []byte, userID, jti string, cfg Config, now time.Time) (string, time.Time, error) {
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

// verifyAccessToken parses and validates a Bearer JWT against secret and
// cfg. Returns the user ID from "sub" on success.
func verifyAccessToken(secret []byte, raw string, cfg Config) (userID string, err error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithExpirationRequired(),
	}
	if cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(cfg.Audience))
	}
	parser := jwt.NewParser(opts...)

	var claims jwt.RegisteredClaims
	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return "", err
	}
	if !tok.Valid {
		return "", errors.New("bearer: token not valid")
	}
	if claims.Subject == "" {
		return "", errors.New("bearer: missing sub claim")
	}
	return claims.Subject, nil
}
