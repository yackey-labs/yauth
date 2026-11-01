package middleware

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CORSConfig is the cross-origin policy applied to an http.Handler. An
// empty AllowedOrigins disables the middleware (the wrapped handler is
// returned unchanged).
type CORSConfig struct {
	// AllowedOrigins is the list of origins permitted to call the API.
	// "*" matches any origin, but ONLY without credentials: the
	// combination "*"+AllowCredentials is rejected (whose reflection
	// would have let any site read credentialed responses) — in
	// credentials mode the wildcard entry is ignored and only explicitly
	// listed origins are honoured. The declarative config surface
	// (yauthcfg) refuses it outright.
	AllowedOrigins []string
	// AllowedMethods is the value of Access-Control-Allow-Methods on
	// preflight responses.
	AllowedMethods []string
	// AllowedHeaders is the value of Access-Control-Allow-Headers on
	// preflight responses.
	AllowedHeaders []string
	// AllowCredentials toggles Access-Control-Allow-Credentials.
	AllowCredentials bool
	// MaxAge is the value of Access-Control-Max-Age on preflight.
	MaxAge time.Duration
}

// CORS returns middleware that applies cfg to every request:
//
//   - Preflight (OPTIONS with Access-Control-Request-Method) is answered
//     directly with 204 + the configured headers when the Origin is
//     allowed, or 403 when it is not.
//   - Non-preflight requests have ACAO and (optionally) ACAC set when
//     the Origin is allowed; disallowed origins simply pass through
//     without ACAO so the browser blocks the response.
//
// An empty AllowedOrigins disables the middleware entirely.
func CORS(cfg CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(cfg.AllowedOrigins) == 0 {
			return next
		}
		methods := cfg.AllowedMethods
		if len(methods) == 0 {
			methods = []string{
				http.MethodGet, http.MethodHead, http.MethodPost,
				http.MethodPut, http.MethodPatch, http.MethodDelete,
			}
		}
		headers := cfg.AllowedHeaders
		if len(headers) == 0 {
			headers = []string{"Content-Type", "Authorization"}
		}
		methodsHeader := strings.Join(methods, ", ")
		headersHeader := strings.Join(headers, ", ")
		maxAge := strconv.Itoa(int(cfg.MaxAge.Seconds()))

		// "*" plus credentials would reflect every origin back with
		// Access-Control-Allow-Credentials, letting any site read
		// authenticated responses. The middleware refuses to do that —
		// the wildcard entry is ignored in credentials mode — and the
		// misconfiguration gets a loud warn here, because the magic
		// quirk means an operator (or an embedder hand-assembling
		// CORSConfig) sometimes ACQUIRES this combination by accident.
		if cfg.AllowCredentials {
			for _, o := range cfg.AllowedOrigins {
				if strings.TrimSpace(o) == "*" {
					slog.Warn("yauth: CORS configured with allowed_origins [\"*\"] and allow_credentials=true — " +
						"the wildcard is ignored in credentials mode (it would reflect every origin); " +
						"list the origins you actually serve")
					break
				}
			}
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			isPreflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""

			if origin == "" {
				if isPreflight {
					// Preflight without Origin is malformed.
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			allowOrigin, ok := matchOrigin(cfg, origin)
			if !ok {
				if isPreflight {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				// Non-preflight: do not set ACAO, let the request through
				// so same-origin (browser-extension, server-to-server, …)
				// callers are unaffected.
				next.ServeHTTP(w, r)
				return
			}

			h := w.Header()
			h.Set("Access-Control-Allow-Origin", allowOrigin)
			if allowOrigin != "*" {
				h.Add("Vary", "Origin")
			}
			if cfg.AllowCredentials {
				h.Set("Access-Control-Allow-Credentials", "true")
			}

			if isPreflight {
				h.Set("Access-Control-Allow-Methods", methodsHeader)
				h.Set("Access-Control-Allow-Headers", headersHeader)
				if cfg.MaxAge > 0 {
					h.Set("Access-Control-Max-Age", maxAge)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// matchOrigin returns the value to send in Access-Control-Allow-Origin
// for the given request origin, plus a bool indicating whether the
// origin is permitted. A literal "*" permits every origin but is
// honoured only WITHOUT credentials: with AllowCredentials=true the
// wildcard is ignored (an explicit origin list is required), because
// accepting a wildcard in credentials mode is how any origin on the
// internet gets to read credentialed responses.
func matchOrigin(cfg CORSConfig, origin string) (string, bool) {
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			if cfg.AllowCredentials {
				continue
			}
			return "*", true
		}
		if strings.EqualFold(o, origin) {
			return origin, true
		}
	}
	return "", false
}
