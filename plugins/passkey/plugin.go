// Package passkey implements WebAuthn / passkey authentication for yauth-go.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/passkeys/register/begin   (auth)  - obtain CredentialCreation options
//	POST {prefix}/passkeys/register/finish  (auth)  - finalize attestation, store credential
//	POST {prefix}/passkey/login/begin               - obtain CredentialAssertion options
//	POST {prefix}/passkey/login/finish              - verify assertion, issue session
//	GET  {prefix}/passkeys                  (auth)  - list caller's credentials
//	DELETE {prefix}/passkeys/{id}           (auth)  - delete one of caller's credentials
//
// The three routes that ADD or REMOVE an authenticator (register/begin,
// register/finish, delete) refuse an X-Api-Key caller outright — a machine
// credential the account holds must not redefine how the account
// authenticates — and register/begin additionally requires the account's
// CURRENT second factor in the X-MFA-Code header when one is enrolled, since
// a user-verified passkey satisfies MFA by default and would otherwise be a
// permanent way around it. Sessions, first-party bearer tokens and the read
// routes are unaffected.
//
// /passkey/login/finish grades the assertion's integrity signals rather than
// assuming them: the login is credited as second-factor-verified only when
// the authenticator actually set the UV bit, and an assertion whose sign
// counter went BACKWARDS (go-webauthn's CloneWarning, WebAuthn L3 §7.2 step
// 24) is refused outright. Both require the post-assertion credential to be
// written back, which is what repo.UpdatePasskeyCredential is for.
//
// The upstream go-webauthn library does not ship a virtual authenticator, so
// most of this package's tests cover the bits that do not need one: the User
// adapter, JSON round-trips, and the shape of /begin responses.
// assertion_integrity_test.go supplies a small software authenticator for the
// cases that genuinely require a signature-valid assertion.
package passkey

import (
	"github.com/danielgtaylor/huma/v2"

	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// Config tunes passkey behaviour.
type Config struct {
	// RPID is the Relying Party identifier (effective domain), e.g. "localhost"
	// or "example.com". Required.
	RPID string
	// RPOrigins is the list of allowed origins (scheme://host[:port]) the
	// browser may present, e.g. ["http://localhost:3000"]. Required.
	RPOrigins []string
	// RPName is the human-readable display name shown in the platform UI.
	// Defaults to "yauth".
	RPName string

	// SatisfiesMFA declares whether a USER-VERIFIED passkey assertion is
	// itself enough to count as the second factor. nil (the default) means
	// TRUE.
	//
	// Defaulting to "a user-verified passkey satisfies MFA" means
	// /passkey/login/finish reports the login as already
	// second-factor-verified and issues the session in one leg. That is a
	// deliberate product decision, not an oversight —
	//
	//   - a USER-VERIFIED passkey assertion is not a single factor. It is
	//     possession of the authenticator plus a biometric or PIN; NIST SP
	//     800-63B rates a verified WebAuthn authenticator at AAL2/AAL3 and
	//     the major IdPs (Entra, Okta, Google) accept a passkey on its own;
	//   - it is phishing-resistant, which TOTP is not. Chasing a passkey
	//     with a shared-secret code adds the weaker factor's failure modes
	//     (relay, real-time phishing, seed theft) to a flow that had none.
	//
	// The credit is conditional on the assertion's UV flag, and that is the
	// half the code used to skip: an assertion with UV=0 proved POSSESSION
	// ONLY, so it is one factor and never carries the marker no matter how
	// this flag is set. BEHAVIOUR CHANGE: a TOTP-enrolled user whose
	// authenticator does not perform user verification (a PIN-less FIDO2 /
	// U2F key, say) now receives {require_mfa, pending_session_id} with NO
	// Set-Cookie where they previously received a session, so clients must
	// handle the require_mfa response shape. A user with no second factor
	// enrolled is unaffected — mfa's gate answers Continue and the session
	// is issued as before.
	//
	// An operator who disagrees sets SatisfiesMFA to a pointer to false
	// (yauth.yaml: plugins.passkey.satisfies_mfa: false). A TOTP-enrolled
	// user then gets {require_mfa, pending_session_id} with NO Set-Cookie
	// from /passkey/login/finish and completes at POST /mfa/verify. Note
	// that this CHANGES BEHAVIOUR for existing passkey users who have TOTP
	// enrolled: they will be prompted for a code they were never asked for
	// before, so ship the client-side handling of require_mfa first.
	//
	// Independent of this flag, a Block decision (account lockout, an IP
	// deny handler) is ALWAYS honoured and no session is issued.
	SatisfiesMFA *bool
}

// satisfiesMFA reports the effective SatisfiesMFA value, defaulting to
// true when the caller left the pointer nil.
func (c *Config) satisfiesMFA() bool {
	if c.SatisfiesMFA == nil {
		return true
	}
	return *c.SatisfiesMFA
}

// passkeyPlugin is an unexported implementation of plugin.Plugin.
type passkeyPlugin struct {
	cfg Config
	wa  *webauthn.WebAuthn
}

// New constructs the passkey plugin. Returns an error if the configured
// RP identifier / origins are rejected by the underlying webauthn library.
func New(cfg Config) (plugin.Plugin, error) {
	if cfg.RPID == "" {
		return nil, fmt.Errorf("passkey: Config.RPID is required")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, fmt.Errorf("passkey: Config.RPOrigins must contain at least one origin")
	}
	if cfg.RPName == "" {
		cfg.RPName = "yauth"
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     cfg.RPOrigins,
		// ASK for user verification. With the zero-valued
		// AuthenticatorSelection this field was "", go-webauthn omitted
		// userVerification from the emitted options entirely, and the RP
		// therefore never even requested the biometric/PIN that
		// Config.SatisfiesMFA's rationale rests on — the browser fell back
		// to its own default and the authenticator was free to answer UV=0.
		//
		// "preferred", NOT "required": go-webauthn's validateLogin only
		// enforces the UV bit when the session says VerificationRequired, so
		// "required" would hard-fail every UV-incapable / PIN-less security
		// key — a lockout, not a fix. The security property comes from
		// grading the RETURNED flag in completeLogin (a UV=0 assertion no
		// longer counts as the second factor); asking here is what keeps a
		// UV-CAPABLE authenticator from being needlessly downgraded to a
		// TOTP prompt. It lands in the registration options too, which is
		// equally desirable.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: build webauthn: %w", err)
	}

	return &passkeyPlugin{cfg: cfg, wa: wa}, nil
}

// Name implements plugin.Plugin.
func (p *passkeyPlugin) Name() string { return "passkey" }

// Routes registers the passkey operations as huma-native typed handlers on the
// shared huma.API. The mux is retained in the signature for parity with the
// plugin interface but is no longer used directly.
//
// Middleware wiring is per-route. The write-ops now take native huma typed
// Body inputs (request schemas auto-derive; unknown fields → 422), so they no
// longer need StashHTTPHuma to read the raw body. StashHTTPHuma is retained only
// where a route sets a cookie (login/finish) or does custom query parsing
// (list):
//
//   - register/begin — no request body, but a typed input carrying the
//     optional X-MFA-Code step-up header; its WebAuthn options response is a
//     native typed Output (huma's unescaped JSON is semantically identical
//     for the client). Guarded by humanOnlyMw and metered (see below).
//   - register/finish — humanOnlyMw: native Body request (malformed /
//     unknown body → 422; missing required fields still reach the business-400),
//     native 201 Output.
//   - login/begin — public, no middleware: native *pointer* Body (optional, nil
//     for the discoverable empty-body flow), native Output.
//   - login/finish — StashHTTPHuma (public): native Body request, but keeps the
//     stash to Set-Cookie on the response writer on success.
//   - list — RequireAuthHuma + StashHTTPHuma: custom paginationFromQuery tolerates
//     garbage query values (defaults) where huma query ints would 422.
//   - delete {id} — RequireAuthHuma only: path param + 204, no body/cookie. Pure
//     typed huma I/O.
func (p *passkeyPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	// RequireUserPrincipalHuma on both authed chains: registering, listing and
	// deleting passkeys all act on the caller's own account, and an org-scoped
	// API key resolves to the human who MINTED it. Without the gate a service
	// account could enrol its own authenticator on that person's account —
	// a permanent credential, i.e. account takeover.
	authStashMw := huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
		middleware.RequireUserPrincipalHuma(api),
	}
	// Enrolling and removing an authenticator additionally refuses ANY API
	// key, user-scoped included. RequireUserPrincipalHuma above only stops
	// org keys and delegated tokens; a user-scoped key resolves to a plain
	// user principal, so a key leaked from a build log could register the
	// attacker's OWN authenticator on the victim's account. That is a
	// permanent credential, and because Config.SatisfiesMFA defaults true it
	// also logs in past the victim's second factor and yields a cookie
	// session whose Method is "" — laundering the machine credential into a
	// human one that the admin machine-caller gate cannot see. A session (or
	// a native client's first-party /token pair, deliberately still allowed,
	// since mobile enrolment is the main reason this route exists) is what
	// may add or drop an authenticator.
	//
	// A SEPARATE slice, listed explicitly rather than appended onto the list
	// route's chain: GET /passkeys must stay open to a key, and append() on
	// a shared slice is how that would silently stop being true.
	humanOnlyMw := huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
		middleware.RequireUserPrincipalHuma(api),
		middleware.RejectMachineCredentialHuma(api),
	}
	// register/begin is additionally metered on the shared mfa_verify bucket
	// — see handleRegisterBegin, which now accepts an X-MFA-Code and answers
	// 403 on a wrong one. An unmetered route that grades a six-digit code is
	// exactly the oracle the mfa plugin closed on its own step-up routes, and
	// this one guesses the SAME secret, so it shares the same per-IP budget
	// rather than handing an attacker a second one.
	stepUpBeginMw := append(huma.Middlewares{
		middleware.RateLimitHuma(plugin.RateLimitFor(host, plugin.RateLimitMFAVerify, 10, 60*time.Second)),
	}, humanOnlyMw...)
	publicStashMw := huma.Middlewares{
		middleware.StashHTTPHuma(api),
	}
	sec := []map[string][]string{
		{"sessionCookie": {}},
		{"bearer": {}},
		{"apiKey": {}},
	}

	huma.Register(api, huma.Operation{
		OperationID: "passkey-register-begin",
		Method:      http.MethodPost,
		Path:        prefix + "/passkeys/register/begin",
		Summary:     "Start passkey registration; return CredentialCreation options",
		Tags:        []string{"passkey"},
		Security:    sec,
		Middlewares: stepUpBeginMw,
	}, p.handleRegisterBegin(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-register-finish",
		Method:      http.MethodPost,
		Path:        prefix + "/passkeys/register/finish",
		Summary:     "Finalize attestation and store the credential",
		Tags:        []string{"passkey"},
		Security:    sec,
		Middlewares: humanOnlyMw,
	}, p.handleRegisterFinish(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-login-begin",
		Method:      http.MethodPost,
		Path:        prefix + "/passkey/login/begin",
		Summary:     "Start a passkey assertion; supports discoverable flow",
		Tags:        []string{"passkey"},
		Security:    []map[string][]string{},
	}, p.handleLoginBegin(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-login-finish",
		Method:      http.MethodPost,
		Path:        prefix + "/passkey/login/finish",
		Summary:     "Verify assertion and issue a session",
		Description: "A passkey satisfies MFA by default. With Config.SatisfiesMFA=false it returns {require_mfa, pending_session_id} and sets no cookie when the account has a second factor; complete it at /mfa/verify.",
		Tags:        []string{"passkey"},
		Security:    []map[string][]string{},
		Middlewares: publicStashMw,
	}, p.handleLoginFinish(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-list",
		Method:      http.MethodGet,
		Path:        prefix + "/passkeys",
		Summary:     "List the caller's passkeys",
		Tags:        []string{"passkey"},
		Security:    sec,
		Middlewares: authStashMw,
	}, p.handleList(host))

	huma.Register(api, huma.Operation{
		OperationID:   "passkey-delete",
		Method:        http.MethodDelete,
		Path:          prefix + "/passkeys/{id}",
		Summary:       "Delete one of the caller's passkeys",
		Tags:          []string{"passkey"},
		Security:      sec,
		DefaultStatus: http.StatusNoContent,
		Middlewares:   humanOnlyMw,
	}, p.handleDelete(host))
}
