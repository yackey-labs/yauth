// ssosaml_test.go — integration coverage for the SAML SP plugin.
//
// The fixture creates an in-process SAML IdP (crewjam/saml's
// IdentityProvider) that signs assertions with a fresh RSA-2048 keypair.
// Tests drive the SP-initiated flow end-to-end without any external
// network.
//
// Pentest cases (the load-bearing part of this file):
//
//   - signature wrapping: tamper the body of a signed Response → reject
//   - audience mismatch: assertion targets a different SP → reject
//   - recipient mismatch: assertion targets a different ACS → reject
//   - expired assertion (NotOnOrAfter in past) → reject
//   - replay: same assertion ID delivered twice → second is rejected
//   - malformed XML: truncated / not base64 / non-XML → reject
//   - comment injection on NameID → reject
//   - IdP-initiated when off → reject
//   - IdP-initiated when on → accept
//
// Plus happy path: SP-initiated login → ACS → session cookie set,
// admin CRUD, metadata.xml export.
package ssosaml

import (
	"github.com/yackey-labs/yauth/humaapi"
	"log/slog"

	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- Fixture IdP -------------------------------------------------------

// fakeIDP wraps crewjam/saml's IdentityProvider behind an httptest
// server. It is constructed per-test (cheap — a fresh RSA-2048 keypair)
// and exposes signed SAMLResponse hooks that the test driver POSTs to
// the SP's ACS endpoint.
type fakeIDP struct {
	srv          *httptest.Server
	idp          *saml.IdentityProvider
	key          *rsa.PrivateKey
	cert         *x509.Certificate
	certPEM      string
	entityID     string
	ssoURL       string
	sp           *saml.ServiceProvider
	registeredSP *saml.EntityDescriptor
	// Overrides for negative tests.
	overrideAudience  string
	overrideRecipient string
	overrideAssertNBF *time.Time
	overrideAssertNOA *time.Time
	overrideNameID    string
	emailAttr         string
	groupsAttr        string
	groupValues       []string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	cert := selfSignedCert(t, key, "idp.test")
	certPEM := pemEncodeCert(cert)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	idp := &fakeIDP{
		key:      key,
		cert:     cert,
		certPEM:  certPEM,
		srv:      srv,
		entityID: srv.URL + "/metadata",
		ssoURL:   srv.URL + "/sso",
	}

	idp.idp = &saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		Logger:      logger.DefaultLogger,
		MetadataURL: mustParseURL(srv.URL + "/metadata"),
		SSOURL:      mustParseURL(srv.URL + "/sso"),
		ServiceProviderProvider: spProviderFunc(func(_ *http.Request, spID string) (*saml.EntityDescriptor, error) {
			if idp.registeredSP != nil {
				return idp.registeredSP, nil
			}
			return nil, fmt.Errorf("no sp registered: %s", spID)
		}),
		SessionProvider: sessionProviderFunc(func(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
			email := "alice@example.com"
			nameID := email
			if idp.overrideNameID != "" {
				nameID = idp.overrideNameID
			}
			return &saml.Session{
				ID:             "sess-1",
				CreateTime:     time.Now(),
				ExpireTime:     time.Now().Add(time.Hour),
				NameID:         nameID,
				UserName:       "alice",
				UserEmail:      email,
				UserCommonName: "Alice Example",
				Groups:         idp.groupValues,
			}
		}),
	}

	mux.Handle("/metadata", idp.idp.Handler())
	mux.Handle("/sso", idp.idp.Handler())
	return idp
}

// signedResponseFor mints a SAMLResponse that is properly signed for
// the given SP+ACS, with overrides applied for negative tests.
// The response is base64-encoded and ready to POST to ACS.
//
// We bypass the crewjam/saml HTTP handler (which renders an HTML form)
// and call the underlying request lifecycle directly so we can mutate
// the response before signing in tests like the wrapping test.
func (i *fakeIDP) signedResponseFor(t *testing.T, sp *saml.ServiceProvider, requestID, relayState string) (samlResponseB64, returnedRelayState string) {
	t.Helper()
	// Build a synthetic IdpAuthnRequest as if the SP had just POSTed.
	// We simulate the HTTP-Redirect binding: build the URL, then
	// parse it back through the IdP.
	authReq, err := sp.MakeAuthenticationRequest(i.ssoURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatalf("make authn request: %v", err)
	}
	if requestID != "" {
		authReq.ID = requestID
	}
	redirectURL, err := authReq.Redirect(relayState, sp)
	if err != nil {
		t.Fatalf("authn request redirect: %v", err)
	}
	r, _ := http.NewRequest("GET", redirectURL.String(), nil)
	idpReq, err := saml.NewIdpAuthnRequest(i.idp, r)
	if err != nil {
		t.Fatalf("new idp authn request: %v", err)
	}
	if err := idpReq.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// Bind the SP descriptor and session.
	session := i.idp.SessionProvider.GetSession(httptest.NewRecorder(), r, idpReq)
	if session == nil {
		t.Fatalf("session is nil")
	}
	// MakeAssertionEl wires the assertion into the request. We
	// optionally mutate before MakeResponse signs.
	maker := saml.DefaultAssertionMaker{}
	if err := maker.MakeAssertion(idpReq, session); err != nil {
		t.Fatalf("make assertion: %v", err)
	}
	if i.overrideAudience != "" {
		// Patch the assertion's audience to a wrong value before signing.
		for j := range idpReq.Assertion.Conditions.AudienceRestrictions {
			idpReq.Assertion.Conditions.AudienceRestrictions[j].Audience.Value = i.overrideAudience
		}
	}
	if i.overrideRecipient != "" {
		for j := range idpReq.Assertion.Subject.SubjectConfirmations {
			if idpReq.Assertion.Subject.SubjectConfirmations[j].SubjectConfirmationData != nil {
				idpReq.Assertion.Subject.SubjectConfirmations[j].SubjectConfirmationData.Recipient = i.overrideRecipient
			}
		}
	}
	if i.overrideAssertNBF != nil {
		idpReq.Assertion.Conditions.NotBefore = *i.overrideAssertNBF
	}
	if i.overrideAssertNOA != nil {
		idpReq.Assertion.Conditions.NotOnOrAfter = *i.overrideAssertNOA
		for j := range idpReq.Assertion.Subject.SubjectConfirmations {
			if idpReq.Assertion.Subject.SubjectConfirmations[j].SubjectConfirmationData != nil {
				idpReq.Assertion.Subject.SubjectConfirmations[j].SubjectConfirmationData.NotOnOrAfter = *i.overrideAssertNOA
			}
		}
	}
	if i.emailAttr != "" || i.groupsAttr != "" {
		// Replace attribute names on the synthesized attributes.
		// Easiest: rebuild the AttributeStatement.
		if len(idpReq.Assertion.AttributeStatements) > 0 {
			for j := range idpReq.Assertion.AttributeStatements[0].Attributes {
				attr := &idpReq.Assertion.AttributeStatements[0].Attributes[j]
				if i.emailAttr != "" && strings.Contains(strings.ToLower(attr.FriendlyName), "email") {
					attr.Name = i.emailAttr
				}
				if i.groupsAttr != "" && strings.EqualFold(attr.FriendlyName, "eduPersonAffiliation") {
					attr.Name = i.groupsAttr
				}
			}
		}
	}
	if err := idpReq.MakeAssertionEl(); err != nil {
		t.Fatalf("make assertion el: %v", err)
	}
	if err := idpReq.MakeResponse(); err != nil {
		t.Fatalf("make response: %v", err)
	}
	// Serialize and base64-encode.
	doc, err := idpReq.PostBinding()
	if err != nil {
		t.Fatalf("post binding: %v", err)
	}
	return doc.SAMLResponse, doc.RelayState
}

func mustParseURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

type spProviderFunc func(r *http.Request, spID string) (*saml.EntityDescriptor, error)

func (f spProviderFunc) GetServiceProvider(r *http.Request, spID string) (*saml.EntityDescriptor, error) {
	return f(r, spID)
}

type sessionProviderFunc func(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session

func (f sessionProviderFunc) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	return f(w, r, req)
}

func selfSignedCert(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func pemEncodeCert(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// --- yauth host stub --------------------------------------------------

type fakeHost struct {
	repo repo.Repository
	mw   *middleware.Middleware
	base string
}

func newFakeHost(r repo.Repository, base string) *fakeHost {
	return &fakeHost{repo: r, mw: middleware.New(r, middleware.Config{CookieName: "yauth_session"}), base: base}
}

func (h *fakeHost) Repo() repo.Repository                      { return h.repo }
func (h *fakeHost) Middleware() *middleware.Middleware         { return h.mw }
func (h *fakeHost) SessionTTL() time.Duration                  { return time.Hour }
func (h *fakeHost) CookieName() string                         { return "yauth_session" }
func (h *fakeHost) CookieDomain() string                       { return "" }
func (h *fakeHost) CookieSecure() bool                         { return false }
func (h *fakeHost) CookiePath() string                         { return "/" }
func (h *fakeHost) CookieSameSite() http.SameSite              { return http.SameSiteLaxMode }
func (h *fakeHost) SessionBinding() (bool, bool)               { return false, false }
func (h *fakeHost) BaseURL() string                            { return h.base }
func (h *fakeHost) AllowSignups() bool                         { return true }
func (h *fakeHost) AutoAdminFirstUser() bool                   { return false }
func (h *fakeHost) RegisterEventHandler(_ events.Handler)      {}
func (h *fakeHost) RegisterAuthResolver(r plugin.AuthResolver) { h.mw.AddResolver(r) }
func (h *fakeHost) PluginNames() []string                      { return nil }
func (h *fakeHost) JWTSigner() plugin.JWTSigner                { return nil }
func (h *fakeHost) JWTSecret() []byte                          { return nil }
func (h *fakeHost) RegisterMFAVerifier(plugin.MFAVerifier)     {}
func (h *fakeHost) RegisterEventGate(events.Handler)           {}
func (h *fakeHost) MFAVerifier() plugin.MFAVerifier            { return nil }
func (h *fakeHost) Emit(_ context.Context, _ events.AuthEvent) (events.Decision, error) {
	return events.Continue(), nil
}
func (h *fakeHost) RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return middleware.RateLimit(h.repo, name, max, window)
}

var _ plugin.PluginHost = (*fakeHost)(nil)

type stubResolver struct{ user *domain.AuthUser }

func (s *stubResolver) Name() string { return "stub" }
func (s *stubResolver) Resolve(_ *http.Request) (*domain.AuthUser, bool, error) {
	return s.user, true, nil
}

// --- helpers ----------------------------------------------------------

func newPlugin(t *testing.T) *ssoSAMLPlugin {
	if t != nil {
		t.Helper()
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	p, err := New(Config{
		EncryptionKey:   key,
		AuthnRequestTTL: 5 * time.Minute,
		ReplayCacheTTL:  5 * time.Minute,
		ClockSkew:       time.Minute,
	})
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return p.(*ssoSAMLPlugin)
}

func seedAdmin(t *testing.T, r repo.Repository) (domain.User, domain.Organization) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	u, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "admin@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	org, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.CreateMembership(ctx, domain.NewMembership{
		OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
		ID:                  uuid.NewString(), OrganizationID: org.ID, UserID: u.ID,
		Role: auth.RoleOwner, Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u, org
}

func doJSON(t *testing.T, method, urlStr string, body any) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = strings.NewReader(string(buf))
	}
	req, err := http.NewRequest(method, urlStr, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// --- config codec round-trip -----------------------------------------

func TestConfigCodecRoundTrip_NoSpKey(t *testing.T) {
	var key [32]byte
	_, _ = rand.Read(key[:])
	in := SamlConnectionConfig{
		IdpEntityID:             "https://idp.test/saml",
		IdpSsoURL:               "https://idp.test/sso",
		IdpX509Cert:             "-----BEGIN CERTIFICATE-----\nMIIBnzCCAUmgAwIB\n-----END CERTIFICATE-----\n",
		AssertionSignedRequired: true,
		ResponseSignedRequired:  true,
	}
	raw, err := marshalSamlConfig(key, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := unmarshalSamlConfig(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.IdpEntityID != in.IdpEntityID {
		t.Fatalf("entity id mismatch")
	}
	if out.SpPrivateKey != nil {
		t.Fatalf("sp private key should be nil")
	}
}

func TestConfigCodecRoundTrip_WithSpKey(t *testing.T) {
	var key [32]byte
	_, _ = rand.Read(key[:])
	spKey := "-----BEGIN PRIVATE KEY-----\nfake-key-bytes\n-----END PRIVATE KEY-----"
	spCert := "-----BEGIN CERTIFICATE-----\nfake-cert\n-----END CERTIFICATE-----"
	in := SamlConnectionConfig{
		IdpEntityID:             "https://idp.test/saml",
		IdpSsoURL:               "https://idp.test/sso",
		IdpX509Cert:             "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
		SpPrivateKey:            &spKey,
		SpCertificate:           &spCert,
		SignAuthnRequests:       true,
		AssertionSignedRequired: true,
		ResponseSignedRequired:  true,
	}
	raw, err := marshalSamlConfig(key, in)
	if err != nil {
		t.Fatal(err)
	}
	// Plaintext SP key must not appear in the persisted blob.
	if strings.Contains(string(raw), "fake-key-bytes") {
		t.Fatal("plaintext sp_private_key leaked into persisted config")
	}
	out, err := unmarshalSamlConfig(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.SpPrivateKey == nil || *out.SpPrivateKey != spKey {
		t.Fatalf("sp_private_key mismatch")
	}
	// Wrong key fails.
	var bad [32]byte
	_, _ = rand.Read(bad[:])
	if _, err := unmarshalSamlConfig(bad, raw); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}

// --- replay cache ------------------------------------------------------

func TestReplayCache_FirstFalseRepeatTrue(t *testing.T) {
	c := newReplayCache(time.Minute)
	exp := time.Now().Add(time.Minute)
	if c.Seen("idp", "id-1", exp) {
		t.Fatal("first observation should be false")
	}
	if !c.Seen("idp", "id-1", exp) {
		t.Fatal("second observation should be true (replay)")
	}
}

func TestReplayCache_DifferentIssuersIndependent(t *testing.T) {
	c := newReplayCache(time.Minute)
	exp := time.Now().Add(time.Minute)
	if c.Seen("idp1", "id-1", exp) {
		t.Fatal("idp1 first should be false")
	}
	if c.Seen("idp2", "id-1", exp) {
		t.Fatal("idp2 first (same id) should be false")
	}
}

func TestReplayCache_GCAfterExpiry(t *testing.T) {
	c := newReplayCache(time.Millisecond)
	// Insert an entry that has already expired
	past := time.Now().Add(-time.Minute)
	c.Seen("idp", "id-1", past)
	time.Sleep(5 * time.Millisecond)
	// A new Seen() should both re-accept id-1 (gc'd) AND prove gc
	// runs lazily on insert.
	if c.Seen("idp", "id-1", time.Now().Add(time.Minute)) {
		t.Fatal("expected id-1 to have been gc'd")
	}
}

// --- end-to-end: SP-initiated login ----------------------------------

// e2eFixture builds the full SP plugin + fake IdP + memrepo + httptest
// SP server, and seeds a SAML connection ready to drive.
type e2eFixture struct {
	plugin *ssoSAMLPlugin
	repo   repo.Repository
	host   *fakeHost
	srv    *httptest.Server
	idp    *fakeIDP
	org    domain.Organization
	conn   domain.SsoConnection
	sp     *saml.ServiceProvider
}

func newE2E(t *testing.T) *e2eFixture {
	t.Helper()
	r := memrepo.New()
	idp := newFakeIDP(t)
	p := newPlugin(t)
	host := newFakeHost(r, "")
	mux := http.NewServeMux()
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	_, org := seedAdmin(t, r)

	// Build a SAML connection. IdP cert is the fake IdP's cert.
	cfg := SamlConnectionConfig{
		IdpEntityID: idp.entityID,
		// Point SAML SSO at the IdP's httptest server.
		IdpSsoURL:               idp.srv.URL + "/sso",
		IdpX509Cert:             idp.certPEM,
		AssertionSignedRequired: true,
		ResponseSignedRequired:  true,
		AttributeMappings: AttributeMappings{
			Email:      "urn:oid:0.9.2342.19200300.100.1.3",
			ExternalID: DefaultExternalIDFromNameID,
		},
	}
	raw, err := marshalSamlConfig(p.cfg.EncryptionKey, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	conn, err := r.CreateSsoConnection(context.Background(), domain.NewSsoConnection{
		ID:                     uuid.NewString(),
		OrganizationID:         org.ID,
		Kind:                   domain.ConnectionKindSamlSP,
		Name:                   "Test SAML",
		Status:                 domain.ConnectionStatusActive,
		Config:                 raw,
		JitProvisioningEnabled: true,
		DefaultRoleOnJit:       auth.RoleMember,
		CreatedAt:              now,
		UpdatedAt:              now,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := buildServiceProvider(&cfg2, srv.URL, conn.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Register the SP with the IdP fixture so its
	// ServiceProviderProvider returns it on lookup.
	idp.sp = sp
	idp.registeredSP = sp.Metadata()

	return &e2eFixture{
		plugin: p,
		repo:   r,
		host:   host,
		srv:    srv,
		idp:    idp,
		org:    org,
		conn:   conn,
		sp:     sp,
	}
}

func TestE2E_SPInitiatedHappyPath(t *testing.T) {
	f := newE2E(t)

	// Step 1: hit /sso/saml/login → expect 302 to IdP.
	loginURL := f.srv.URL + "/sso/saml/login?connection_id=" + f.conn.ID
	client := newNoRedirectClient()
	resp, err := client.Get(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: status=%d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, f.idp.srv.URL) {
		t.Fatalf("login: location=%q", loc)
	}
	// Pull the SAMLRequest + RelayState out of the location query.
	locURL, _ := url.Parse(loc)
	relayState := locURL.Query().Get("RelayState")
	if relayState == "" {
		t.Fatal("login: no RelayState in redirect")
	}

	// Step 2: pull the state row out of the repo to find the
	// AuthnRequest ID we issued; use it as the InResponseTo.
	st, err := f.repo.ConsumeSsoLoginState(context.Background(), relayState)
	if err != nil || st == nil {
		t.Fatalf("consume state: state=%v err=%v", st, err)
	}
	// Re-insert the state since the ACS handler will consume it.
	if err := f.repo.CreateSsoLoginState(context.Background(), domain.NewSsoLoginState{
		State:        st.State,
		ConnectionID: st.ConnectionID,
		Nonce:        st.Nonce,
		PKCEVerifier: st.PKCEVerifier,
		RedirectURL:  st.RedirectURL,
		CreatedAt:    st.CreatedAt,
		ExpiresAt:    st.ExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}

	// Step 3: mint a signed SAMLResponse with the right InResponseTo.
	respB64, rs := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, relayState)
	if rs != relayState {
		t.Fatalf("relay state mismatch: %q vs %q", rs, relayState)
	}

	// Step 4: POST it to the ACS.
	form := url.Values{}
	form.Set("SAMLResponse", respB64)
	form.Set("RelayState", relayState)
	acsResp, err := client.PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer acsResp.Body.Close()
	body, _ := io.ReadAll(acsResp.Body)
	if acsResp.StatusCode != http.StatusFound {
		t.Fatalf("acs: status=%d body=%s", acsResp.StatusCode, string(body))
	}
	// Session cookie must be set.
	var sessCookie *http.Cookie
	for _, c := range acsResp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("acs: no session cookie set")
	}

	// JIT user was created.
	u, err := f.repo.GetUserByEmail(context.Background(), "alice@example.com")
	if err != nil || u == nil {
		t.Fatalf("jit user not found: err=%v u=%v", err, u)
	}
}

func newNoRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// --- pentest cases ----------------------------------------------------

// TestPentest_AudienceMismatch: assertion targets the wrong SP entity.
// Expected: crewjam/saml rejects → 401 INVALID_ASSERTION.
func TestPentest_AudienceMismatch(t *testing.T) {
	f := newE2E(t)
	f.idp.overrideAudience = "https://attacker.example.com/sp"
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d body=%s", resp.StatusCode, string(body))
	}
}

// TestPentest_RecipientMismatch: SubjectConfirmationData/@Recipient is
// for the wrong ACS URL. Expected: rejected.
func TestPentest_RecipientMismatch(t *testing.T) {
	f := newE2E(t)
	f.idp.overrideRecipient = "https://attacker.example.com/acs"
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d body=%s", resp.StatusCode, string(body))
	}
}

// TestPentest_ExpiredAssertion: NotOnOrAfter is in the past.
func TestPentest_ExpiredAssertion(t *testing.T) {
	f := newE2E(t)
	expired := time.Now().Add(-2 * time.Hour)
	f.idp.overrideAssertNOA = &expired
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d body=%s", resp.StatusCode, string(body))
	}
}

// TestPentest_Replay: deliver the same valid assertion twice; the second
// must be rejected by the replay cache.
func TestPentest_Replay(t *testing.T) {
	f := newE2E(t)
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	// First delivery: should succeed.
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp1, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp1.Body)
		t.Fatalf("first delivery: status=%d body=%s", resp1.StatusCode, string(body))
	}
	// Second delivery: state has been consumed, so we'd already
	// reject for that reason. Re-seed the state so the ONLY failure
	// reason is the replay cache.
	if err := f.repo.CreateSsoLoginState(context.Background(), domain.NewSsoLoginState{
		State:        st.State,
		ConnectionID: st.ConnectionID,
		PKCEVerifier: st.PKCEVerifier,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	resp2, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected replay to be rejected with 401, got %d body=%s", resp2.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "REPLAY") && !strings.Contains(string(body), "replay") {
		// crewjam/saml may itself catch the replay via request-id
		// reuse (the InResponseTo on a fresh state row may differ).
		// Either layer rejecting is acceptable; we just want a 401.
		t.Logf("rejection body (not necessarily REPLAY-coded): %s", string(body))
	}
}

// TestPentest_MalformedXML: not-base64, not-XML, truncated XML.
func TestPentest_MalformedXML(t *testing.T) {
	f := newE2E(t)
	cases := []struct {
		name string
		body string
	}{
		{"not_base64", "@@@not base64@@@"},
		{"not_xml", base64.StdEncoding.EncodeToString([]byte("hello not xml"))},
		{"truncated_xml", base64.StdEncoding.EncodeToString([]byte("<saml:Response>"))},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"SAMLResponse": {tc.body}}
			resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("malformed payload was accepted: status=%d body=%s", resp.StatusCode, string(body))
			}
		})
	}
}

// TestPentest_CommentInjectionOnNameID: a NameID containing an XML
// comment should not be accepted in any form. Even if XML parsers
// strip comments per spec, our validateAssertion has belt-and-
// suspenders rejection of < and > characters in the NameID value.
func TestPentest_CommentInjectionOnNameID(t *testing.T) {
	f := newE2E(t)
	// Set the NameID to include angle brackets.
	f.idp.overrideNameID = "alice@example.com<!--x@attacker.com-->"
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// We expect either:
	//   (a) crewjam/saml's XML parser treats the comment as text
	//       and the NameID round-trips cleanly with < > stripped,
	//       at which point our validateAssertion's
	//       ContainsAny("<>") check on the value rejects.
	//   (b) the XML decoder rejects ill-formed input outright.
	// In both cases the request must fail.
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
		t.Fatalf("comment-injection accepted: status=%d body=%s", resp.StatusCode, string(body))
	}
}

// TestPentest_IdpInitiatedWhenDisabled: an unsolicited response (no
// matching state row) is rejected unless IdpInitiatedSsoAllowed=true.
// Even when the response is valid and signed correctly.
func TestPentest_IdpInitiatedWhenDisabled(t *testing.T) {
	f := newE2E(t)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, "", "")
	form := url.Values{"SAMLResponse": {respB64}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
		t.Fatalf("unsolicited response accepted with IdP-initiated disabled: status=%d body=%s", resp.StatusCode, string(body))
	}
}

// TestE2E_IdpInitiatedAllowed: a connection with IdpInitiatedSsoAllowed=true
// accepts an unsolicited response when RelayState carries a cid:<uuid>
// hint pointing at the connection.
func TestE2E_IdpInitiatedAllowed(t *testing.T) {
	f := newE2E(t)
	// Mutate the connection config to allow IdP-initiated.
	cfg, err := unmarshalSamlConfig(f.plugin.cfg.EncryptionKey, f.conn.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg.IdpInitiatedSsoAllowed = true
	raw, err := marshalSamlConfig(f.plugin.cfg.EncryptionKey, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := f.repo.UpdateSsoConnection(context.Background(), f.conn.ID, domain.UpdateSsoConnection{
		Config:    &raw,
		UpdatedAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	// Rebuild the SP since the connection now allows IdP-initiated;
	// otherwise crewjam/saml's ParseResponse refuses the unsolicited
	// response on the SP side.
	cfg2, err := unmarshalSamlConfig(f.plugin.cfg.EncryptionKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	sp2, err := buildServiceProvider(&cfg2, f.srv.URL, f.conn.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.idp.sp = sp2
	f.idp.registeredSP = sp2.Metadata()

	// Mint an unsolicited (no request ID) response.
	respB64, _ := f.idp.signedResponseFor(t, sp2, "", "")
	relayState := "cid:" + f.conn.ID
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {relayState}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("idp-initiated allowed: status=%d body=%s", resp.StatusCode, string(body))
	}
}

// TestPentest_WrongIdpCert: rotate the IdP's signing cert without
// updating the connection; the next signed assertion must be rejected
// because the configured cert can no longer verify the signature.
func TestPentest_WrongIdpCert(t *testing.T) {
	f := newE2E(t)
	// Swap the IdP's key/cert to a NEW pair WITHOUT updating the
	// connection's configured cert. The signature in the response
	// will be valid against the new key, but the SP will try to
	// verify against the old cert.
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newCert := selfSignedCert(t, newKey, "rogue-idp")
	f.idp.key = newKey
	f.idp.cert = newCert
	f.idp.idp.Key = newKey
	f.idp.idp.Certificate = newCert

	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for signature mismatch, got %d body=%s", resp.StatusCode, string(body))
	}
}

// TestE2E_GroupToRoleMapping: a connection with group_to_role
// configured promotes the JIT'd user to admin when the IdP supplies
// the matching group attribute.
func TestE2E_GroupToRoleMapping(t *testing.T) {
	f := newE2E(t)
	// Mutate the connection: enable group→role mapping.
	cfg, _ := unmarshalSamlConfig(f.plugin.cfg.EncryptionKey, f.conn.Config)
	groupsAttr := "urn:oid:1.3.6.1.4.1.5923.1.1.1.1" // eduPersonAffiliation
	cfg.AttributeMappings.Groups = &groupsAttr
	cfg.AttributeMappings.GroupToRole = map[string]string{"admins": auth.RoleAdmin}
	raw, _ := marshalSamlConfig(f.plugin.cfg.EncryptionKey, cfg)
	now := time.Now().UTC()
	if _, err := f.repo.UpdateSsoConnection(context.Background(), f.conn.ID, domain.UpdateSsoConnection{
		Config:    &raw,
		UpdatedAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	// Configure the IdP to ship "admins" as the group value.
	f.idp.groupValues = []string{"admins"}
	f.idp.groupsAttr = groupsAttr

	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("acs: status=%d body=%s", resp.StatusCode, string(body))
	}
	// Look up the membership; role must be admin.
	u, err := f.repo.GetUserByEmail(context.Background(), "alice@example.com")
	if err != nil || u == nil {
		t.Fatalf("user not found: %v", err)
	}
	m, err := f.repo.GetMembershipByOrgUser(context.Background(), f.org.ID, u.ID)
	if err != nil || m == nil {
		t.Fatalf("membership not found: %v", err)
	}
	if m.Role != auth.RoleAdmin {
		t.Fatalf("expected admin role from group mapping, got %q", m.Role)
	}
}

// TestPentest_SignatureWrapping_TamperBody: the signed Response is
// post-processed to mutate the assertion content (a classic XSW
// pattern). crewjam/saml's signature verifier must catch the mismatch.
//
// We exercise this by base64-decoding the signed response, replacing
// the username inside the assertion, re-encoding, and shipping. The
// signature now covers the original bytes, so the parser must reject.
func TestPentest_SignatureWrapping_TamperBody(t *testing.T) {
	f := newE2E(t)
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	raw, err := base64.StdEncoding.DecodeString(respB64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Replace "alice@example.com" inside the signed assertion with
	// "evil@attacker.com". The cert-bound XML signature now no
	// longer matches the digest.
	mutated := strings.Replace(string(raw), "alice@example.com", "evil@attacker.com", 1)
	if mutated == string(raw) {
		t.Skip("response did not contain expected NameID; cannot mutate")
	}
	tamperedB64 := base64.StdEncoding.EncodeToString([]byte(mutated))
	form := url.Values{"SAMLResponse": {tamperedB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
		t.Fatalf("tampered response was accepted: status=%d body=%s", resp.StatusCode, string(body))
	}
}

// TestPentest_IssuerSwap: change the response's Issuer to something
// unrelated. crewjam/saml's signature verifier sees the cert is fine,
// but our validateAssertion enforces issuer == configured IdpEntityID
// and refuses.
//
// Skipped: tampering the signed body breaks the signature; this is
// already covered by TestPentest_SignatureWrapping_TamperBody. We
// keep the check in the codebase for unit-level confidence.
func TestPentest_IssuerSwap_ValidateAssertion(t *testing.T) {
	assertion := &saml.Assertion{
		ID: "a-1",
		Issuer: saml.Issuer{
			Value: "https://attacker.example.com",
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "alice@example.com"},
		},
	}
	cfg := &SamlConnectionConfig{IdpEntityID: "https://idp.test/saml"}
	p := newPlugin(nil)
	err := p.validateAssertion(assertion, cfg)
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected issuer mismatch error, got %v", err)
	}
}

// TestPentest_MissingNameID: assertion has no Subject/NameID; reject.
func TestPentest_MissingNameID(t *testing.T) {
	assertion := &saml.Assertion{
		ID:     "a-1",
		Issuer: saml.Issuer{Value: "https://idp.test/saml"},
	}
	cfg := &SamlConnectionConfig{IdpEntityID: "https://idp.test/saml"}
	p := newPlugin(nil)
	err := p.validateAssertion(assertion, cfg)
	if err == nil || !strings.Contains(err.Error(), "Subject") {
		t.Fatalf("expected Subject/NameID error, got %v", err)
	}
}

// TestPentest_EmptyAssertionID: assertion with empty ID rejected.
func TestPentest_EmptyAssertionID(t *testing.T) {
	assertion := &saml.Assertion{
		Issuer:  saml.Issuer{Value: "https://idp.test/saml"},
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "alice"}},
	}
	cfg := &SamlConnectionConfig{IdpEntityID: "https://idp.test/saml"}
	p := newPlugin(nil)
	err := p.validateAssertion(assertion, cfg)
	if err == nil || !strings.Contains(err.Error(), "ID") {
		t.Fatalf("expected ID error, got %v", err)
	}
}

// beginLogin runs the /sso/saml/login redirect and returns the
// persisted SsoLoginState row (un-consumed — re-inserted by the helper
// for use in the test).
func beginLogin(t *testing.T, f *e2eFixture) *domain.SsoLoginState {
	t.Helper()
	loginURL := f.srv.URL + "/sso/saml/login?connection_id=" + f.conn.ID
	resp, err := newNoRedirectClient().Get(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login redirect: status=%d", resp.StatusCode)
	}
	locURL, _ := url.Parse(resp.Header.Get("Location"))
	relayState := locURL.Query().Get("RelayState")
	if relayState == "" {
		t.Fatal("login: no RelayState")
	}
	st, err := f.repo.ConsumeSsoLoginState(context.Background(), relayState)
	if err != nil || st == nil {
		t.Fatalf("consume state for re-insert: err=%v state=%v", err, st)
	}
	if err := f.repo.CreateSsoLoginState(context.Background(), domain.NewSsoLoginState{
		State:        st.State,
		ConnectionID: st.ConnectionID,
		PKCEVerifier: st.PKCEVerifier,
		RedirectURL:  st.RedirectURL,
		CreatedAt:    st.CreatedAt,
		ExpiresAt:    st.ExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

// --- admin CRUD --------------------------------------------------------

func TestAdminCRUD_CreateListGetDelete(t *testing.T) {
	p := newPlugin(t)
	r := memrepo.New()
	admin, org := seedAdmin(t, r)
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	// Create.
	idp := newFakeIDP(t)
	createBody := map[string]any{
		"name": "Okta prod",
		"saml": map[string]any{
			"idp_entity_id": idp.entityID,
			"idp_sso_url":   idp.srv.URL + "/sso",
			"idp_x509_cert": idp.certPEM,
			"sp_entity_id":  "",
			"sp_acs_url":    "",
			"attribute_mappings": map[string]any{
				"email":       "urn:oid:0.9.2342.19200300.100.1.3",
				"external_id": DefaultExternalIDFromNameID,
			},
		},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/sso/saml/connections", createBody)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s", resp.StatusCode, string(body))
	}
	var created samlConnectionJSON
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.SAML == nil || created.SAML.IdpEntityID != idp.entityID {
		t.Fatalf("created shape wrong: %+v", created)
	}
	if !created.SAML.AssertionSignedRequired || !created.SAML.ResponseSignedRequired {
		t.Fatal("default signed-required flags should be true on create")
	}
	if strings.Contains(string(body), "BEGIN PRIVATE KEY") {
		t.Fatal("plaintext private key echoed in create response")
	}

	// List.
	resp = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/sso/saml/connections", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status=%d", resp.StatusCode)
	}
	var listed struct {
		Conns []samlConnectionJSON `json:"sso_connections"`
	}
	decode(t, resp, &listed)
	if len(listed.Conns) != 1 {
		t.Fatalf("list count = %d", len(listed.Conns))
	}

	// Metadata.xml (unauthenticated).
	mresp, err := http.Get(srv.URL + "/organizations/" + org.ID + "/sso/saml/connections/" + created.ID + "/metadata.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer mresp.Body.Close()
	if mresp.StatusCode != http.StatusOK {
		mbody, _ := io.ReadAll(mresp.Body)
		t.Fatalf("metadata: status=%d body=%s", mresp.StatusCode, string(mbody))
	}
	mbody, _ := io.ReadAll(mresp.Body)
	if !strings.Contains(string(mbody), "EntityDescriptor") {
		t.Fatalf("metadata.xml missing EntityDescriptor: %s", string(mbody))
	}

	// Delete.
	dresp := doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+org.ID+"/sso/saml/connections/"+created.ID, nil)
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status=%d", dresp.StatusCode)
	}
}

func TestAdminCRUD_RejectsNonAdmin(t *testing.T) {
	p := newPlugin(t)
	r := memrepo.New()
	_, org := seedAdmin(t, r)
	// non-admin user
	ctx := context.Background()
	now := time.Now().UTC()
	nonAdmin, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "user@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// no membership -> 403
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: nonAdmin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp := doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/sso/saml/connections", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-member list: status=%d", resp.StatusCode)
	}
}

// TestAdminCRUD_UnknownBodyKeysReturn422 pins the huma-native Body contract:
// an unknown key — whether at the top level of the create request or inside the
// nested `saml` / `attribute_mappings` blocks — is rejected by huma's schema
// validation with a 422 (additionalProperties:false), BEFORE the handler runs.
// This is the behavior the StashHTTPHuma->native conversion buys; the legacy
// decodeJSON silently ignored unknown keys.
func TestAdminCRUD_UnknownBodyKeysReturn422(t *testing.T) {
	p := newPlugin(t)
	r := memrepo.New()
	admin, org := seedAdmin(t, r)
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	idp := newFakeIDP(t)

	base := func() map[string]any {
		return map[string]any{
			"name": "Okta prod",
			"saml": map[string]any{
				"idp_entity_id": idp.entityID,
				"idp_sso_url":   idp.srv.URL + "/sso",
				"idp_x509_cert": idp.certPEM,
				"attribute_mappings": map[string]any{
					"email": "urn:oid:0.9.2342.19200300.100.1.3",
				},
			},
		}
	}
	url := srv.URL + "/organizations/" + org.ID + "/sso/saml/connections"

	cases := []struct {
		name string
		mut  func(m map[string]any)
	}{
		{"top-level unknown key", func(m map[string]any) { m["bogus"] = true }},
		{"nested saml unknown key", func(m map[string]any) {
			m["saml"].(map[string]any)["bogus"] = "x"
		}},
		{"nested attribute_mappings unknown key", func(m map[string]any) {
			m["saml"].(map[string]any)["attribute_mappings"].(map[string]any)["bogus"] = "x"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := base()
			tc.mut(body)
			resp := doJSON(t, http.MethodPost, url, body)
			rb, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("expected 422 for %s, got %d body=%s", tc.name, resp.StatusCode, string(rb))
			}
		})
	}

	// Sanity: the same base body with NO unknown keys still creates (201),
	// proving the 422s above are caused by the unknown keys, not the fixture.
	resp := doJSON(t, http.MethodPost, url, base())
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("clean body should create: status=%d body=%s", resp.StatusCode, string(rb))
	}
}

func decode(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func (*fakeHost) Logger() *slog.Logger { return slog.Default() }
