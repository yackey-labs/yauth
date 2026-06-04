// Command oidc-example demonstrates the asymjwt + oidc plugins.
//
// On startup it generates an RSA-2048 keypair under ./.demo-keys/ if
// one does not already exist, builds a YAuth instance with the
// asymjwt + oidc + emailpassword + bearer plugins, and serves it under
// /api/auth/* on :3000.
//
// Try it:
//
//	go run ./examples/oidc
//
//	# Discovery doc:
//	curl -s http://localhost:3000/api/auth/.well-known/openid-configuration | jq .
//
//	# JWKS:
//	curl -s http://localhost:3000/api/auth/.well-known/jwks.json | jq .
//
//	# Register, log in, and hit /userinfo:
//	curl -i -c jar.txt -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//	curl -i -b jar.txt http://localhost:3000/api/auth/userinfo
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"path/filepath"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/repo/gormrepo"
)

const (
	keyDir   = ".demo-keys"
	privFile = "rsa.key"
	pubFile  = "rsa.pub"
)

// ensureRSAKeys writes a fresh RSA-2048 keypair into keyDir if either
// PEM file is missing. Returns the absolute paths to the private and
// public PEM files.
func ensureRSAKeys() (priv, pub string, err error) {
	if mkErr := os.MkdirAll(keyDir, 0o700); mkErr != nil {
		return "", "", mkErr
	}
	priv = filepath.Join(keyDir, privFile)
	pub = filepath.Join(keyDir, pubFile)

	_, errPriv := os.Stat(priv)
	_, errPub := os.Stat(pub)
	if errPriv == nil && errPub == nil {
		return priv, pub, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		return "", "", err
	}
	log.Printf("oidc-example: generated fresh RSA keypair under ./%s/", keyDir)
	return priv, pub, nil
}

func main() {
	priv, pub, err := ensureRSAKeys()
	if err != nil {
		log.Fatalf("ensure rsa keys: %v", err)
	}

	dsn := "file::memory:?cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	r := gormrepo.New(db)

	asym, err := asymjwt.New(asymjwt.Config{
		KeyType:        "RS256",
		PrivateKeyPath: priv,
		PublicKeyPath:  pub,
		KID:            "yauth-demo",
	})
	if err != nil {
		log.Fatalf("asymjwt.New: %v", err)
	}

	jwtSecret := []byte("dev-only-jwt-secret-change-me-please-32b")

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret(jwtSecret).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(asym).
		WithPlugin(oidc.New(oidc.Config{
			Issuer:   "http://localhost:3000",
			BasePath: "/api/auth",
		})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	log.Printf("your IdP is at http://localhost%s", addr)
	log.Printf("  discovery: http://localhost%s/api/auth/.well-known/openid-configuration", addr)
	log.Printf("  jwks:      http://localhost%s/api/auth/.well-known/jwks.json", addr)
	log.Printf("  userinfo:  http://localhost%s/api/auth/userinfo (Bearer-protected)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
