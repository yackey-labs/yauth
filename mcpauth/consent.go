package mcpauth

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	yauth "github.com/yackey-labs/yauth"
)

// ConsentConfig tunes the server-rendered consent page.
type ConsentConfig struct {
	Config

	// LoginPath is where an unauthenticated browser is redirected, with a
	// redirect_to back to the consent URL. Default "/login".
	LoginPath string

	// AppName is shown in the consent page heading. Default "this server".
	AppName string
}

// HTMLConsentHandler returns a handler for Config.ConsentPath that renders a
// server-rendered OAuth consent page — the fallback for non-SPA servers, where
// there is no SolidJS/Vue ConsentScreen to mount. It implements the same
// two-step flow the SPA components do:
//
//	GET  {AuthBasePath}/oauth/authorize?<params>  -> JSON consent payload
//	POST {AuthBasePath}/oauth2/consent            -> { redirect_url }
//
// On approval/denial the page POSTs the signed request_id + csrf_token and
// follows redirect_url. Scope rows show Config.Scopes descriptions when a
// requested scope is in the catalog, falling back to the raw scope string.
//
// Mount does not register this for you — wire it where your consent route
// lives, e.g.:
//
//	mux.Handle("GET /authorize", mcpauth.HTMLConsentHandler(ya, mcpauth.ConsentConfig{
//		Config:  cfg,
//		AppName: "spacewombat",
//	}))
func HTMLConsentHandler(ya *yauth.YAuth, cfg ConsentConfig) http.HandlerFunc {
	yaRouter := ya.Router()
	loginPath := cfg.LoginPath
	if loginPath == "" {
		loginPath = "/login"
	}
	appName := cfg.AppName
	if appName == "" {
		appName = "this server"
	}
	base := strings.TrimRight(cfg.AuthBasePath, "/")
	desc := map[string]string{}
	for _, s := range cfg.Scopes {
		desc[s.Name] = s.Description
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Forward the authorize request (with its query + session cookie) into
		// yauth. yauth registers /oauth/authorize at its mux root, so proxy to
		// that internal path, not the AuthBasePath-prefixed one.
		fwd := r.Clone(r.Context())
		fwd.URL.Path = "/oauth/authorize"
		status, _, body := proxyFetch(yaRouter, fwd, "/oauth/authorize")

		if status == http.StatusUnauthorized {
			http.Redirect(w, r, loginPath+"?redirect_to="+url.QueryEscape(r.URL.String()), http.StatusFound)
			return
		}
		if status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
			return
		}

		// Existing consent: yauth returns { redirect_url } directly.
		var redirect struct {
			RedirectURL string `json:"redirect_url"`
		}
		if json.Unmarshal(body, &redirect) == nil && redirect.RedirectURL != "" {
			http.Redirect(w, r, redirect.RedirectURL, http.StatusFound)
			return
		}

		var payload struct {
			Client struct {
				ID   string  `json:"id"`
				Name *string `json:"name,omitempty"`
			} `json:"client"`
			Scopes    []string `json:"scopes"`
			CSRFToken string   `json:"csrf_token"`
			RequestID string   `json:"request_id"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "bad response from authorization server", http.StatusInternalServerError)
			return
		}

		clientName := payload.Client.ID
		if payload.Client.Name != nil && *payload.Client.Name != "" {
			clientName = *payload.Client.Name
		}
		rows := make([]scopeRow, len(payload.Scopes))
		for i, s := range payload.Scopes {
			rows[i] = scopeRow{Name: s, Description: desc[s]}
		}

		// Anti-clickjacking: a consent page must never be framed, or an
		// attacker could overlay it and trick a logged-in user into approving.
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consentTmpl.Execute(w, map[string]any{
			"AppName":    appName,
			"ClientName": clientName,
			"Scopes":     rows,
			"CSRFToken":  payload.CSRFToken,
			"RequestID":  payload.RequestID,
			"ConsentURL": base + "/oauth2/consent",
		})
	}
}

type scopeRow struct {
	Name        string
	Description string
}

var consentTmpl = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authorize — {{.AppName}}</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a12;color:#e2e2e8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
.card{background:#13131f;border:1px solid #2a2a40;border-radius:12px;padding:2rem;max-width:440px;width:100%;box-shadow:0 0 40px rgba(100,80,255,.1)}
h1{font-size:1.2rem;font-weight:600;margin-bottom:.9rem}
.client{color:#a78bfa;font-weight:600}
.desc{color:#9999b8;font-size:.88rem;margin-bottom:1.1rem;line-height:1.5}
.scopes{list-style:none;margin-bottom:1.4rem}
.scopes li{background:#1a1a2e;border:1px solid #2a2a40;border-radius:6px;padding:.5rem .7rem;margin-bottom:.4rem;font-size:.84rem;color:#c4c4d8}
.scopes .name{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#a78bfa;font-size:.78rem}
.scopes .sdesc{display:block;color:#8a8aa8;margin-top:.15rem;font-size:.8rem}
.actions{display:flex;gap:.6rem}
button{flex:1;padding:.55rem 1rem;border-radius:8px;border:none;cursor:pointer;font-size:.88rem;font-weight:500;transition:opacity .15s}
button:hover{opacity:.85}
.approve{background:#7c3aed;color:#fff}
.deny{background:#2a2a40;color:#9999b8}
.err{color:#f87171;font-size:.82rem;margin-top:.7rem;display:none}
</style>
</head>
<body>
<div class="card">
  <h1>Authorize Access</h1>
  <p class="desc"><span class="client">{{.ClientName}}</span> is requesting access to your {{.AppName}} account.</p>
  <ul class="scopes">{{range .Scopes}}<li><span class="name">{{.Name}}</span>{{if .Description}}<span class="sdesc">{{.Description}}</span>{{end}}</li>{{end}}</ul>
  <div class="actions">
    <button class="approve" onclick="consent(true)">Authorize</button>
    <button class="deny" onclick="consent(false)">Deny</button>
  </div>
  <p class="err" id="err"></p>
</div>
<script>
var reqId = "{{.RequestID}}";
var csrf = "{{.CSRFToken}}";
var consentUrl = "{{.ConsentURL}}";
// Defense in depth: never navigate to a javascript:/data: redirect, even if one
// somehow slipped past registration-time validation.
function safeRedirect(u) {
  try { var s = new URL(u, window.location.origin).protocol; return s === "https:" || s === "http:"; }
  catch (e) { return false; }
}
async function consent(approved) {
  try {
    var r = await fetch(consentUrl, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      credentials: "include",
      body: JSON.stringify({request_id: reqId, csrf_token: csrf, approved: approved})
    });
    var d = await r.json();
    if (d.redirect_url && safeRedirect(d.redirect_url)) { window.location.href = d.redirect_url; return; }
    var el = document.getElementById("err");
    el.style.display = "block";
    el.textContent = d.error_description || d.error || "Unknown error";
  } catch(e) {
    var el = document.getElementById("err");
    el.style.display = "block";
    el.textContent = e.message;
  }
}
</script>
</body>
</html>`))
