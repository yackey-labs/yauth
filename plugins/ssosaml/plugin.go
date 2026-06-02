// Package ssosaml implements yauth-go as a SAML 2.0 Service Provider,
// the sibling protocol to plugins/ssooidc. Port of yauth Rust #94.
//
// SAML SP federation is the single most-asked enterprise SSO protocol
// in 2026 — every Okta / Azure AD / Ping / OneLogin / Auth0 / ADFS
// deployment speaks SAML 2.0, and many enterprise IT security review
// templates assume SAML by name. yauth-go ships this plugin so the
// "would buy if you had SSO" objection has both an OIDC and a SAML
// answer.
//
// The plugin is plugin-flag gated and only meaningful when the
// organizations plugin (yauth-go #11) is registered, because every
// SsoConnection is organization-scoped. Single-user / anonymous
// deployments that never register ssosaml see none of these routes.
//
// Routes registered (relative to the prefix passed in):
//
//	# Admin (per-org)
//	POST   {prefix}/organizations/{id}/sso/saml/connections             — create
//	GET    {prefix}/organizations/{id}/sso/saml/connections             — list
//	GET    {prefix}/organizations/{id}/sso/saml/connections/{cid}       — get
//	PATCH  {prefix}/organizations/{id}/sso/saml/connections/{cid}       — update
//	DELETE {prefix}/organizations/{id}/sso/saml/connections/{cid}       — delete
//	GET    {prefix}/organizations/{id}/sso/saml/connections/{cid}/metadata.xml — SP metadata for IdP import
//
//	# User-facing
//	GET    {prefix}/sso/saml/login                                      — SP-initiated; 302 to IdP
//	POST   {prefix}/sso/saml/acs                                        — assertion consumer service
//	GET    {prefix}/sso/saml/logout                                     — SP-initiated SLO
//	POST   {prefix}/sso/saml/slo                                        — IdP-initiated SLO
//
// Note on route divergence from the ssooidc plugin: SAML lives under
// /sso/saml/connections (not /sso/connections) because both plugins
// must claim distinct routes — Go's http.ServeMux does not allow
// multiple handlers per path. The ssooidc plugin owns the kind-agnostic
// /sso/connections path; ssosaml owns /sso/saml/connections for SAML-
// specific admin (including the metadata.xml export).
//
// At-rest encryption: SamlConnectionConfig may carry an SP signing
// private key (for signing AuthnRequest / decrypting encrypted
// assertions). When present, the plugin AES-256-GCM-encrypts the key
// material with cfg.EncryptionKey before storage and decrypts on read.
// The 32-byte key is supplied by the caller; the zero value is
// rejected by New. The IdP X.509 cert is a *public* artefact and is
// stored in plaintext.
//
// Security posture (decade-old SAML CVEs live here):
//
//   - XML signature verification is delegated to crewjam/saml v0.5.1+,
//     which carries the post-CVE-2022-41912 fix for the multi-
//     Assertion signature-bypass and the post-CVE-2020-27846 fix
//     for the xml-roundtrip-validator class of signature stripping.
//   - We mandate signature validation on the Response (or Assertion)
//     by setting both ResponseSignedRequired and AssertionSignedRequired
//     to true by default. The configuration allows admins to relax
//     these, but the documented default is "both required".
//   - Audience pinning: ServiceProvider.EntityID is set from
//     SpEntityID on the connection. crewjam/saml rejects assertions
//     whose AudienceRestriction does not list this value.
//   - Recipient pinning: ServiceProvider.AcsURL must match the
//     SubjectConfirmationData/@Recipient on the assertion.
//   - NotBefore / NotOnOrAfter: enforced by crewjam/saml against a
//     1-minute clock skew tolerance.
//   - Replay: we track every accepted assertion's ID for the validity
//     window in a process-local cache. A repeat ID inside the window
//     is rejected — defense in depth on top of crewjam/saml's own
//     request-id tracking for SP-initiated flows.
//   - IdP-initiated SSO is OFF by default per connection
//     (IdpInitiatedSsoAllowed=false). The unsolicited-response path
//     skips the request-id check by design; admins must opt in.
//
// Test coverage matrix (see ssosaml_test.go) explicitly enumerates
// the historical SAML attack classes: signature wrapping (XSW1-XSW8
// patterns), audience mismatch, recipient mismatch, expired
// assertion, replay, malformed XML, comment-injection on NameID.
package ssosaml

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes the ssosaml plugin.
type Config struct {
	// EncryptionKey is the 32-byte AES-256-GCM key used to encrypt
	// each SsoConnection's SP private key (when present) at rest.
	// The zero value is rejected by New — callers MUST supply a real
	// key.
	//
	// The key shape matches the ssooidc plugin's EncryptionKey so a
	// deployment using both can reuse the same key material (they are
	// namespaced by the JSON payload format).
	EncryptionKey [32]byte

	// AuthnRequestTTL bounds how long an outbound /sso/saml/login →
	// /sso/saml/acs round-trip may take. Defaults to 10 minutes (the
	// standard SAML clock-skew tolerance window doubled). RequestID
	// rows are single-use regardless.
	AuthnRequestTTL time.Duration

	// AllowedRedirectURLs is the allow-list of post-login redirect
	// targets honored by the redirect_url query parameter on
	// /sso/saml/login. Empty slice means "redirect_url is ignored
	// entirely" — the safest default. Matches the ssooidc plugin's
	// option of the same name.
	AllowedRedirectURLs []string

	// ReplayCacheTTL is the lifetime of an entry in the assertion-ID
	// replay cache. Should be at least the maximum NotOnOrAfter
	// window we accept (default 5 minutes per SAML guidance). Older
	// entries are evicted lazily on the next insert.
	ReplayCacheTTL time.Duration

	// ClockSkew is the allowed wall-clock drift between SP and IdP
	// when validating NotBefore / NotOnOrAfter timestamps. Defaults
	// to 1 minute (crewjam/saml's default).
	ClockSkew time.Duration

	// HTTPClient is the optional HTTP client used for outbound calls
	// to fetch IdP metadata when an admin pastes a URL instead of
	// XML. nil uses http.DefaultClient with a 10s timeout applied
	// per-call. Reserved for future metadata-URL import support; the
	// current MVP requires admins to paste IdpX509Cert directly.
	HTTPClient *http.Client
}

const (
	defaultAuthnRequestTTL = 10 * time.Minute
	defaultReplayCacheTTL  = 5 * time.Minute
	defaultClockSkew       = 1 * time.Minute
)

// ssoSAMLPlugin implements plugin.Plugin.
type ssoSAMLPlugin struct {
	cfg Config

	// replayOnce guards lazy initialization of the per-process
	// assertion-ID replay cache. The cache is shared across every
	// connection in the process — entries are keyed by (issuer,
	// assertion_id) so multi-IdP deployments do not collide.
	replayOnce  sync.Once
	replayCache *replayCache
}

// New constructs the ssosaml plugin. Returns a non-nil error when the
// config is invalid (zero key).
func New(cfg Config) (plugin.Plugin, error) {
	if cfg.EncryptionKey == ([32]byte{}) {
		return nil, errors.New("ssosaml: Config.EncryptionKey is required (zero value rejected)")
	}
	if cfg.AuthnRequestTTL <= 0 {
		cfg.AuthnRequestTTL = defaultAuthnRequestTTL
	}
	if cfg.ReplayCacheTTL <= 0 {
		cfg.ReplayCacheTTL = defaultReplayCacheTTL
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	return &ssoSAMLPlugin{cfg: cfg}, nil
}

// MustNew is the panic-on-error variant of New.
func MustNew(cfg Config) plugin.Plugin {
	p, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return p
}

// Name implements plugin.Plugin.
func (p *ssoSAMLPlugin) Name() string { return "sso_saml" }

// Routes implements plugin.Plugin. The plugin mounts admin CRUD
// unconditionally — the organizations plugin owns the membership/admin
// gates and the SsoConnection rows cascade with the org delete, so
// mounting these routes in a deployment without the organizations
// plugin is harmless (every route 403s on the membership lookup).
func (p *ssoSAMLPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()

	// Admin CRUD (SAML-specific path; see package doc).
	mux.Handle("POST "+prefix+"/organizations/{id}/sso/saml/connections", mw.RequireAuth(http.HandlerFunc(p.handleCreateConnection(host))))
	mux.Handle("GET "+prefix+"/organizations/{id}/sso/saml/connections", mw.RequireAuth(http.HandlerFunc(p.handleListConnections(host))))
	mux.Handle("GET "+prefix+"/organizations/{id}/sso/saml/connections/{cid}", mw.RequireAuth(http.HandlerFunc(p.handleGetConnection(host))))
	mux.Handle("PATCH "+prefix+"/organizations/{id}/sso/saml/connections/{cid}", mw.RequireAuth(http.HandlerFunc(p.handleUpdateConnection(host))))
	mux.Handle("DELETE "+prefix+"/organizations/{id}/sso/saml/connections/{cid}", mw.RequireAuth(http.HandlerFunc(p.handleDeleteConnection(host))))

	// SP metadata export — public, unauthenticated (it's published
	// IdP-side anyway, and every IdP admin needs to fetch it).
	mux.Handle("GET "+prefix+"/organizations/{id}/sso/saml/connections/{cid}/metadata.xml", http.HandlerFunc(p.handleMetadataXML(host)))

	// User-facing login + ACS + SLO.
	mux.Handle("GET "+prefix+"/sso/saml/login", http.HandlerFunc(p.handleSamlLogin(host)))
	mux.Handle("POST "+prefix+"/sso/saml/acs", http.HandlerFunc(p.handleSamlACS(host)))
	mux.Handle("GET "+prefix+"/sso/saml/logout", http.HandlerFunc(p.handleSamlLogout(host)))
	// IdP-initiated Single Logout (HTTP-Redirect binding is GET; some IdPs POST).
	mux.Handle("GET "+prefix+"/sso/saml/slo", http.HandlerFunc(p.handleSamlSLO(host)))
	mux.Handle("POST "+prefix+"/sso/saml/slo", http.HandlerFunc(p.handleSamlSLO(host)))
}

// replay returns the lazily-initialized process-wide replay cache.
func (p *ssoSAMLPlugin) replay() *replayCache {
	p.replayOnce.Do(func() {
		p.replayCache = newReplayCache(p.cfg.ReplayCacheTTL)
	})
	return p.replayCache
}
