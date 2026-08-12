package yauthcfg

import (
	"fmt"
	"strings"
)

// MinJWTSecretBytes is the shortest HS256 signing secret yauth will start with.
//
// RFC 7518 §3.2 is explicit: "A key of the same size as the hash output (for
// instance, 256 bits for HS256) or larger MUST be used with this algorithm."
// Below that the secret is recoverable offline from any single token yauth has
// ever issued, and every bearer access token, refresh binding and machine
// credential in the deployment is forged from there.
const MinJWTSecretBytes = 32

// validateSecurity holds the config to the invariants that were previously
// only documented — or not even that. It runs as part of [Config.Validate].
//
// Each rule here REJECTS rather than warns, and each earns that separately:
// a warning is the right answer for a setting that is dangerous in production
// and correct in development (see [Config.SecurityWarnings]), but not for one
// that is either impossible to hold safely or already broken as written.
func (c *Config) validateSecurity() error {
	// SameSite=None + Secure=false is not merely insecure, it does not work:
	// every current browser REFUSES to store a SameSite=None cookie that is not
	// Secure (Chrome 80+, Firefox 96+, Safari 13+). A deployment configured
	// this way has an authentication system that never keeps a session. Failing
	// at startup replaces an unexplainable "login does nothing" with a sentence
	// naming the two fields.
	if strings.EqualFold(c.Session.CookieSameSite, "none") && !c.Session.CookieSecure {
		return fmt.Errorf("session.cookie_same_site=none requires session.cookie_secure=true — browsers refuse to store a SameSite=None cookie without the Secure attribute, so no session would ever persist")
	}

	// "*" plus credentials is forbidden by the Fetch standard precisely because
	// it lets ANY origin make credentialed requests and READ the response —
	// full cross-site read of every authenticated endpoint. The middleware
	// works around the literal-"*" prohibition by reflecting the request's
	// Origin, which is the same hole with the spec's guard removed.
	//
	// This is rejected here, on the declarative surface, rather than changed in
	// middleware/cors.go: the middleware's behaviour is deliberate and
	// test-locked, and a Go caller who assembles CORSConfig by hand can still
	// choose it. What was missing is that yaml/env could reach it with nothing
	// to stop them, and no combination of the two is legitimate — listing the
	// origins you actually serve is always available.
	if c.Server.CORS.AllowCredentials {
		for _, o := range c.Server.CORS.AllowedOrigins {
			if strings.TrimSpace(o) == "*" {
				return fmt.Errorf(`server.cors.allowed_origins contains "*" with server.cors.allow_credentials=true — that reflects EVERY origin back with Access-Control-Allow-Credentials, letting any site read authenticated responses. List the origins you serve instead`)
			}
		}
	}

	return nil
}

// SecurityWarnings returns advisories for settings that are dangerous in
// production but legitimate — often necessary — in development, so they are
// permitted and said out loud rather than rejected. The precedent is the
// console mailer, which writes password-reset tokens to the log and announces
// itself once at startup.
//
// Surfaced by NewBuilderFromConfig at startup and by `yauth check`/`status`.
// Never fatal.
func (c *Config) SecurityWarnings() []string {
	var w []string

	// The one that got away. CookieSecure defaults to false and nothing said
	// so: a deployment that never sets it ships session cookies that any
	// network position can read off a single plaintext request. yauth cannot
	// detect TLS termination (it is usually a proxy hop away), so it cannot
	// reject this — but "you are shipping session cookies over cleartext" is
	// not something to leave to a doc comment.
	if !c.Session.CookieSecure {
		w = append(w, "session.cookie_secure=false — session cookies will be sent over plaintext HTTP and are readable by anything on the path. This is for local development only; set it true anywhere reachable over a network")
	}

	return w
}
