package oauth2server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
)

// Guided federation handshake (human-approved, browser-bounce). A relying party
// redirects its admin here with a signed federation_request (a JWT signed by the
// RP's key — verified against the RP's JWKS, NOT a static allow-list). The OP
// admin reviews + approves; the OP mints a confidential client and a one-time,
// short-TTL grant, and redirects back. The RP redeems the grant server-to-server
// for the client_secret — which never travels through the browser.
//
// Endpoints (all under the plugin prefix, gated on DCREnabled):
//	POST /federate/review   (admin) — parse+verify the request; return display fields
//	POST /federate/approve  (admin) — register the client + mint a grant; return redirect_url
//	POST /federate/redeem   (public) — exchange a one-time grant for the client creds

const federationGrantTTL = 5 * time.Minute

type federationGrant struct {
	clientID     string
	clientSecret string
	exp          time.Time
}

type federationGrantStore struct {
	mu sync.Mutex
	m  map[string]federationGrant
}

// federationGrants lazily initializes the per-process grant store. In-process is
// sufficient: grants are single-use and live ~5 minutes; a single-replica IdP
// (the common case) needs no shared store, and a pod restart mid-handshake just
// means the admin re-clicks.
func (p *oauth2Plugin) federationGrants() *federationGrantStore {
	p.fedGrantsOnce.Do(func() { p.fedGrantsRef = &federationGrantStore{m: map[string]federationGrant{}} })
	return p.fedGrantsRef
}

func (s *federationGrantStore) put(id string, g federationGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = g
}

// take returns and removes a grant (single use), or false if missing/expired. It
// also opportunistically evicts expired entries.
func (s *federationGrantStore) take(id string) (federationGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.exp) {
			delete(s.m, k)
		}
	}
	g, ok := s.m[id]
	if !ok {
		return federationGrant{}, false
	}
	delete(s.m, id)
	if now.After(g.exp) {
		return federationGrant{}, false
	}
	return g, true
}

func federateJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func federateErr(w http.ResponseWriter, status int, msg string) {
	federateJSON(w, status, map[string]string{"error": msg})
}

type federateRequestBody struct {
	FederationRequest string `json:"federation_request"`
}

// handleFederateReview verifies the request's signature (against the RP's JWKS)
// and returns the fields the approval UI shows. Admin-gated.
func (p *oauth2Plugin) handleFederateReview(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body federateRequestBody
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.FederationRequest) == "" {
			federateErr(w, http.StatusBadRequest, "federation_request is required")
			return
		}
		ts, err := p.verifyStatementSignature(r.Context(), body.FederationRequest)
		if err != nil {
			federateErr(w, http.StatusBadRequest, "invalid federation_request: "+statementErrMessage(r.Context(), host.Logger(), err))
			return
		}
		federateJSON(w, http.StatusOK, map[string]any{
			"issuer":        ts.Issuer,
			"client_name":   ts.ClientName,
			"redirect_uris": ts.RedirectURIs,
			"scopes":        splitScopes(ts.Scope),
		})
	}
}

// handleFederateApprove registers the confidential client and mints a one-time
// grant, returning the redirect_url back to the RP. Admin-gated — the logged-in
// admin's click IS the trust decision.
func (p *oauth2Plugin) handleFederateApprove(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body federateRequestBody
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.FederationRequest) == "" {
			federateErr(w, http.StatusBadRequest, "federation_request is required")
			return
		}
		ts, err := p.verifyStatementSignature(r.Context(), body.FederationRequest)
		if err != nil {
			federateErr(w, http.StatusBadRequest, "invalid federation_request: "+statementErrMessage(r.Context(), host.Logger(), err))
			return
		}
		if len(ts.RedirectURIs) == 0 {
			federateErr(w, http.StatusBadRequest, "federation_request has no redirect_uris")
			return
		}
		if ts.InitiateLoginURI != "" {
			if reason := initiateLoginURIReason(ts.InitiateLoginURI); reason != "" {
				federateErr(w, http.StatusBadRequest, reason)
				return
			}
		}
		returnURI := strings.TrimSpace(ts.ReturnURI)
		if returnURI == "" || !strings.HasPrefix(returnURI, "https://") {
			federateErr(w, http.StatusBadRequest, "federation_request return_uri must be an https URL")
			return
		}

		clientID, err := randomHex(16)
		if err != nil {
			federateErr(w, http.StatusInternalServerError, "server error")
			return
		}
		rawSecret, err := randomHex(32)
		if err != nil {
			federateErr(w, http.StatusInternalServerError, "server error")
			return
		}
		hash, err := auth.HashPassword(rawSecret)
		if err != nil {
			federateErr(w, http.StatusInternalServerError, "server error")
			return
		}
		method := "client_secret_basic"
		name := ts.ClientName
		now := time.Now().UTC()
		scopes := splitScopes(ts.Scope)
		if len(scopes) == 0 {
			scopes = []string{"openid", "email", "profile", "groups"}
		}
		nc := domain.NewOAuth2Client{
			ID:                      uuid.NewString(),
			ClientID:                clientID,
			ClientSecretHash:        &hash,
			RedirectURIs:            rawJSON(ts.RedirectURIs),
			ClientName:              &name,
			GrantTypes:              rawJSON([]string{"authorization_code", "refresh_token"}),
			Scopes:                  rawJSON(scopes),
			IsPublic:                false,
			TokenEndpointAuthMethod: &method,
			DynamicallyRegistered:   true,
			CreatedAt:               now,
		}
		if ts.InitiateLoginURI != "" {
			v := ts.InitiateLoginURI
			nc.InitiateLoginURI = &v
		}
		if err := host.Repo().CreateOAuth2Client(r.Context(), nc); err != nil {
			federateErr(w, http.StatusInternalServerError, "create client failed")
			return
		}

		grantID := uuid.NewString()
		p.federationGrants().put(grantID, federationGrant{clientID: clientID, clientSecret: rawSecret, exp: now.Add(federationGrantTTL)})

		sep := "?"
		if strings.Contains(returnURI, "?") {
			sep = "&"
		}
		// Echo the (signed) request back so the RP can read its own connection
		// params; redeem the grant server-to-side for the secret.
		redirectURL := returnURI + sep + "grant=" + url.QueryEscape(grantID) + "&req=" + url.QueryEscape(body.FederationRequest)
		federateJSON(w, http.StatusOK, map[string]any{"redirect_url": redirectURL})
	}
}

// handleFederateRedeem exchanges a one-time grant for the freshly-minted client
// credentials. Public: the grant itself is the bearer secret (single-use, short
// TTL), redeemed server-to-server by the RP — never through a browser.
func (p *oauth2Plugin) handleFederateRedeem(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Grant string `json:"grant"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Grant) == "" {
			federateErr(w, http.StatusBadRequest, "grant is required")
			return
		}
		g, ok := p.federationGrants().take(body.Grant)
		if !ok {
			federateErr(w, http.StatusGone, "grant is invalid, used, or expired")
			return
		}
		federateJSON(w, http.StatusOK, map[string]string{
			"client_id":     g.clientID,
			"client_secret": g.clientSecret,
		})
	}
}
