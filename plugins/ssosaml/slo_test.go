package ssosaml

import (
	"github.com/yackey-labs/yauth-go/humaapi"

	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
)

// signedRedirectLogoutRequest builds a SAML HTTP-Redirect-binding LogoutRequest
// query string signed with idpKey (RSA-SHA256), mirroring what a real IdP sends.
func signedRedirectLogoutRequest(t *testing.T, idpKey *rsa.PrivateKey, idpEntityID, nameID string) string {
	t.Helper()
	xmlReq := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + uuid.NewString() + `" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `"><saml:Issuer>` + idpEntityID + `</saml:Issuer><saml:NameID>` + nameID + `</saml:NameID></samlp:LogoutRequest>`

	// DEFLATE + base64 (redirect binding).
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte(xmlReq))
	_ = fw.Close()
	samlRequest := base64.StdEncoding.EncodeToString(buf.Bytes())

	sigAlg := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	// Signed octet string: SAMLRequest=<enc>&SigAlg=<enc> (no RelayState).
	signedStr := "SAMLRequest=" + url.QueryEscape(samlRequest) + "&SigAlg=" + url.QueryEscape(sigAlg)
	digest := sha256.Sum256([]byte(signedStr))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idpKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	return "SAMLRequest=" + url.QueryEscape(samlRequest) +
		"&SigAlg=" + url.QueryEscape(sigAlg) +
		"&Signature=" + url.QueryEscape(sigB64)
}

func sloTestEnv(t *testing.T) (*httptest.Server, *memrepo.Repo, *rsa.PrivateKey, string, *domain.User, string) {
	t.Helper()
	p := newPlugin(t)
	r := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()

	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen idp key: %v", err)
	}
	idpEntityID := "https://idp.example.com/saml/metadata"
	idpCertPEM := pemEncodeCert(selfSignedCert(t, idpKey, "idp.example.com"))

	user, err := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "u@example.com", Role: "user", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	nameID := "user-nameid-1"
	provider := "saml:" + IssuerKeyFromEntityID(idpEntityID)
	if _, err := r.CreateExternalIdentity(ctx, domain.NewExternalIdentity{
		ID: uuid.NewString(), UserID: user.ID, Provider: provider, ExternalID: nameID,
		LinkedAt: now, LastLoginAt: now,
	}); err != nil {
		t.Fatalf("create external identity: %v", err)
	}
	rawSession, _, err := auth.IssueSession(ctx, r, user.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	cfg := SamlConnectionConfig{
		IdpEntityID: idpEntityID,
		IdpSsoURL:   "https://idp.example.com/sso",
		IdpX509Cert: idpCertPEM,
		AttributeMappings: AttributeMappings{
			Email:      "urn:oid:0.9.2342.19200300.100.1.3",
			ExternalID: DefaultExternalIDFromNameID,
		},
	}
	raw, err := marshalSamlConfig(p.cfg.EncryptionKey, cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now})
	if _, err := r.CreateSsoConnection(ctx, domain.NewSsoConnection{
		ID: uuid.NewString(), OrganizationID: org.ID, Kind: domain.ConnectionKindSamlSP,
		Name: "Test SAML", Status: domain.ConnectionStatusActive, Config: raw,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return srv, r, idpKey, idpEntityID, &user, rawSession
}

// TestSamlSLO_VerifiedRequestRevokesSession proves a signed IdP LogoutRequest
// terminates the mapped user's local session server-side.
func TestSamlSLO_VerifiedRequestRevokesSession(t *testing.T) {
	srv, r, idpKey, idpEntityID, _, rawSession := sloTestEnv(t)
	ctx := context.Background()

	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err != nil {
		t.Fatalf("precondition: session must exist: %v", err)
	}

	q := signedRedirectLogoutRequest(t, idpKey, idpEntityID, "user-nameid-1")
	resp, err := http.Get(srv.URL + "/sso/saml/slo?" + q)
	if err != nil {
		t.Fatalf("slo GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 200/302, got %d", resp.StatusCode)
	}

	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err == nil {
		t.Fatal("expected session revoked after verified SAML SLO")
	}
}

// TestSamlSLO_RejectsBadSignature proves a LogoutRequest signed by the wrong key
// is rejected and the session survives.
func TestSamlSLO_RejectsBadSignature(t *testing.T) {
	srv, r, _, idpEntityID, _, rawSession := sloTestEnv(t)
	ctx := context.Background()

	// Sign with an attacker key, not the IdP key.
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	q := signedRedirectLogoutRequest(t, attackerKey, idpEntityID, "user-nameid-1")
	resp, err := http.Get(srv.URL + "/sso/saml/slo?" + q)
	if err != nil {
		t.Fatalf("slo GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad signature, got %d", resp.StatusCode)
	}
	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err != nil {
		t.Fatal("session must NOT be revoked by an unverified LogoutRequest")
	}
}

// TestSamlSLO_RejectsUnsigned proves an unsigned LogoutRequest is refused.
func TestSamlSLO_RejectsUnsigned(t *testing.T) {
	srv, _, _, _, _, _ := sloTestEnv(t)
	resp, err := http.Get(srv.URL + "/sso/saml/slo?SAMLRequest=abc")
	if err != nil {
		t.Fatalf("slo GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsigned request, got %d", resp.StatusCode)
	}
}
