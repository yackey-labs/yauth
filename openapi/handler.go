package openapi

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Handler returns an http.Handler that serves the spec at /openapi.json
// and a Stoplight Elements documentation page at /docs. Embedders mount
// it alongside their main router, e.g.:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
//	mux.Handle("/", openapi.Handler())
//
// The spec is built once and cached for the lifetime of the process.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /openapi.json", specHandler())
	mux.Handle("GET /docs", docsHandler())
	return mux
}

// YAuth is a thin alias for Handler that takes the yauth instance as a
// parameter to mirror the API style of the rest of the library
// (constructors taking a *yauth.YAuth). Today the spec is fully static —
// the parameter exists so we can later embed runtime fields (e.g.
// loaded plugin names in the Info description) without a breaking
// change.
//
// The parameter type is `any` so this package can be imported without
// pulling the yauth root in (and without creating an import cycle when
// callers wire it up).
func YAuth(_ any) http.Handler { return Handler() }

// specBytesOnce builds the spec on first invocation and caches it. The
// build is deterministic so caching is safe across requests.
var specBytesOnce = sync.OnceValues(func() ([]byte, error) {
	return json.Marshal(Build())
})

// specHandler returns an http.HandlerFunc that emits the cached
// /openapi.json bytes. We hand-roll caching here rather than using
// huma.Adapter because we author the spec by hand instead of via huma's
// reflection-based operation registration.
func specHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body, err := specBytesOnce()
		if err != nil {
			http.Error(w, "openapi: marshal failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}

// docsPage is a minimal HTML wrapper that loads Stoplight Elements from
// the public CDN and points it at /openapi.json. Self-hosting the
// Elements bundle would buy stability at the cost of vendoring a few
// hundred kilobytes of JS — for a docs page this is the right tradeoff.
const docsPage = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>yauth-go API</title>
    <link rel="stylesheet" href="https://unpkg.com/@stoplight/elements/styles.min.css" />
    <script src="https://unpkg.com/@stoplight/elements/web-components.min.js"></script>
    <style>html,body,elements-api{height:100%;margin:0;}</style>
  </head>
  <body>
    <elements-api apiDescriptionUrl="./openapi.json" router="hash" layout="sidebar" />
  </body>
</html>
`

// docsHandler serves the Stoplight Elements landing page at /docs.
func docsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(docsPage))
	}
}
