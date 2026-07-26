package asymjwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Signer implements plugin.JWTSigner backed by an asymmetric keypair.
// It is constructed by NewSigner from the Config supplied to the plugin.
type Signer struct {
	algo       string
	kid        string
	method     jwt.SigningMethod
	signingKey any // *rsa.PrivateKey or *ecdsa.PrivateKey
	verifyKey  any // *rsa.PublicKey or *ecdsa.PublicKey
	jwksBytes  []byte
}

// NewSigner loads the private and public PEM material referenced by
// cfg (either filesystem paths or inline byte slices) and produces a
// Signer that can sign+verify JWTs with the configured algorithm. JWKS
// bytes are precomputed at construction time.
func NewSigner(cfg Config) (*Signer, error) {
	privPEM, err := readPEMOrInline(cfg.PrivateKeyPath, cfg.PrivateKeyPEM, "private")
	if err != nil {
		return nil, err
	}
	pubPEM, err := readPEMOrInline(cfg.PublicKeyPath, cfg.PublicKeyPEM, "public")
	if err != nil {
		return nil, err
	}
	priv, err := parsePrivateKeyPEM(privPEM, cfg.KeyType)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKeyPEM(pubPEM, cfg.KeyType)
	if err != nil {
		return nil, err
	}

	var method jwt.SigningMethod
	switch cfg.KeyType {
	case "RS256":
		method = jwt.SigningMethodRS256
	case "ES256":
		method = jwt.SigningMethodES256
	default:
		return nil, fmt.Errorf("asymjwt: unsupported KeyType %q (want RS256 or ES256)", cfg.KeyType)
	}

	jwksBytes, err := buildJWKS(pub, cfg.KeyType, cfg.KID)
	if err != nil {
		return nil, err
	}

	return &Signer{
		algo:       cfg.KeyType,
		kid:        cfg.KID,
		method:     method,
		signingKey: priv,
		verifyKey:  pub,
		jwksBytes:  jwksBytes,
	}, nil
}

// Sign produces a signed JWT carrying the supplied claims. The "kid"
// header is set so verifiers can pick the right key from a JWKS.
func (s *Signer) Sign(claims map[string]any) (string, error) {
	tok := jwt.NewWithClaims(s.method, jwt.MapClaims(claims))
	tok.Header["kid"] = s.kid
	signed, err := tok.SignedString(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("asymjwt: sign: %w", err)
	}
	return signed, nil
}

// Verify parses and validates raw against the loaded public key. The
// signing algorithm is restricted to the algo this signer was built
// for, so a token signed with a different alg is rejected.
func (s *Signer) Verify(raw string) (map[string]any, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{s.algo}))
	var claims jwt.MapClaims
	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (interface{}, error) {
		return s.verifyKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("asymjwt: token not valid")
	}
	return map[string]any(claims), nil
}

// Algo implements plugin.JWTSigner.
func (s *Signer) Algo() string { return s.algo }

// KID implements plugin.JWTSigner.
func (s *Signer) KID() string { return s.kid }

// PublicJWKS implements plugin.JWTSigner. The returned bytes are a
// JSON-encoded JWKS document containing exactly the loaded public key
// with the configured kid and alg.
func (s *Signer) PublicJWKS() ([]byte, error) {
	out := make([]byte, len(s.jwksBytes))
	copy(out, s.jwksBytes)
	return out, nil
}

// readPEMOrInline returns the PEM bytes pointed at by path or, when
// path is empty, the inline payload. Exactly one of path/inline is
// expected; New() enforces the precondition. The kind label is woven
// into error messages so operators can tell which key failed to load.
func readPEMOrInline(path string, inline []byte, kind string) ([]byte, error) {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("asymjwt: read %s key: %w", kind, err)
		}
		return raw, nil
	}
	if len(inline) == 0 {
		return nil, fmt.Errorf("asymjwt: %s key not configured", kind)
	}
	return inline, nil
}

// parsePrivateKeyPEM decodes raw PEM private-key bytes into the
// concrete key type expected for keyType. The supported encodings are
// PKCS8, PKCS1 (RSA), and SEC1 (EC).
func parsePrivateKeyPEM(raw []byte, keyType string) (any, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("asymjwt: private key is not PEM")
	}

	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return validatePrivateKeyType(k, keyType)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return validatePrivateKeyType(k, keyType)
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return validatePrivateKeyType(k, keyType)
	}
	return nil, fmt.Errorf("asymjwt: unrecognized private-key encoding")
}

// parsePublicKeyPEM decodes raw PEM public-key bytes into the concrete
// key type expected for keyType. PKIX is the primary path; PKCS1 RSA
// public keys are accepted as a fallback.
func parsePublicKeyPEM(raw []byte, keyType string) (any, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("asymjwt: public key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if k2, err2 := x509.ParsePKCS1PublicKey(block.Bytes); err2 == nil {
			k = k2
		} else {
			return nil, fmt.Errorf("asymjwt: parse public key: %w", err)
		}
	}
	return validatePublicKeyType(k, keyType)
}

func validatePrivateKeyType(k any, keyType string) (any, error) {
	switch keyType {
	case "RS256":
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("asymjwt: KeyType=RS256 requires an RSA private key")
		}
		if rk.N.BitLen() < 2048 {
			return nil, fmt.Errorf("asymjwt: RS256 requires a >=2048-bit RSA key (got %d)", rk.N.BitLen())
		}
		return rk, nil
	case "ES256":
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("asymjwt: KeyType=ES256 requires an ECDSA private key")
		}
		if ek.Curve.Params().BitSize != 256 {
			return nil, fmt.Errorf("asymjwt: ES256 requires P-256")
		}
		return ek, nil
	}
	return nil, fmt.Errorf("asymjwt: unsupported KeyType %q", keyType)
}

func validatePublicKeyType(k any, keyType string) (any, error) {
	switch keyType {
	case "RS256":
		if _, ok := k.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("asymjwt: KeyType=RS256 requires an RSA public key")
		}
	case "ES256":
		if _, ok := k.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("asymjwt: KeyType=ES256 requires an ECDSA public key")
		}
	default:
		return nil, fmt.Errorf("asymjwt: unsupported KeyType %q", keyType)
	}
	return k, nil
}

// buildJWKS marshals pub into a single-key JWKS document using
// lestrrat-go/jwx/v3/jwk. The kid and alg headers are set so verifiers
// can pin the key.
func buildJWKS(pub any, keyType, kid string) ([]byte, error) {
	key, err := jwk.Import(pub)
	if err != nil {
		return nil, fmt.Errorf("asymjwt: build jwk: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	switch keyType {
	case "RS256":
		if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			return nil, err
		}
	case "ES256":
		if err := key.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
			return nil, err
		}
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, err
	}
	return jsonMarshalIndent(set)
}
