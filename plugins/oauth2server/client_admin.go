package oauth2server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// clientJSON is the on-the-wire representation of an OAuth2Client (no
// secret hash). The CreateClient response wraps this with a one-time
// client_secret field.
type clientJSON struct {
	ID                      string    `json:"id"`
	ClientID                string    `json:"client_id"`
	Name                    *string   `json:"name,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	Scopes                  []string  `json:"scopes"`
	IsPublic                bool      `json:"is_public"`
	TokenEndpointAuthMethod *string   `json:"token_endpoint_auth_method,omitempty"`
	JWKSURI                 *string   `json:"jwks_uri,omitempty"`
	HasPublicKey            bool      `json:"has_public_key"`
	Banned                  bool      `json:"banned"`
	BannedReason            *string   `json:"banned_reason,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
}

// createClientRequest is the body for POST /oauth2/clients.
type createClientRequest struct {
	Name                    *string  `json:"name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	Scopes                  []string `json:"scopes"`
	IsPublic                bool     `json:"is_public"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method,omitempty"`
	PublicKeyPEM            *string  `json:"public_key_pem,omitempty"`
	JWKSURI                 *string  `json:"jwks_uri,omitempty"`
}

type createClientResponse struct {
	Client       clientJSON `json:"client"`
	ClientSecret *string    `json:"client_secret,omitempty"`
}

// patchClientRequest is the body for PATCH /oauth2/clients/{id}. Pointer
// fields are absent when not changing; an explicit Banned=false unbans.
type patchClientRequest struct {
	Banned       *bool   `json:"banned,omitempty"`
	BannedReason *string `json:"banned_reason,omitempty"`
	PublicKeyPEM *string `json:"public_key_pem,omitempty"`
}

// toClientJSON converts a domain.OAuth2Client to its JSON shape.
func toClientJSON(c domain.OAuth2Client) clientJSON {
	return clientJSON{
		ID:                      c.ID,
		ClientID:                c.ClientID,
		Name:                    c.ClientName,
		RedirectURIs:            decodeScopes(c.RedirectURIs),
		GrantTypes:              decodeScopes(c.GrantTypes),
		Scopes:                  decodeScopes(c.Scopes),
		IsPublic:                c.IsPublic,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		JWKSURI:                 c.JWKSURI,
		HasPublicKey:            c.PublicKeyPEM != nil && *c.PublicKeyPEM != "",
		Banned:                  c.BannedAt != nil,
		BannedReason:            c.BannedReason,
		CreatedAt:               c.CreatedAt,
	}
}

// handleCreateClient registers a new OAuth2 client. For confidential
// clients (is_public=false) a fresh secret is generated, hashed, and
// returned exactly once in the response.
func (p *oauth2Plugin) handleCreateClient(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createClientRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		// Confidential clients used only for client_credentials and
		// public clients used for the device flow may legitimately
		// have zero redirect_uris. Validation is per-grant on the
		// /authorize and /token paths.

		clientID, err := randomHex(16)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		var secretHash *string
		var rawSecret *string
		if !req.IsPublic {
			s, err := randomHex(24)
			if err != nil {
				writeOAuthError(w, "server_error", err.Error())
				return
			}
			h, err := auth.HashPassword(s)
			if err != nil {
				writeOAuthError(w, "server_error", err.Error())
				return
			}
			secretHash = &h
			rawSecret = &s
		}

		now := time.Now().UTC()
		new := domain.NewOAuth2Client{
			ID:                      uuid.NewString(),
			ClientID:                clientID,
			ClientSecretHash:        secretHash,
			RedirectURIs:            rawJSON(req.RedirectURIs),
			ClientName:              req.Name,
			GrantTypes:              rawJSON(req.GrantTypes),
			Scopes:                  rawJSON(req.Scopes),
			IsPublic:                req.IsPublic,
			CreatedAt:               now,
			TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
			PublicKeyPEM:            req.PublicKeyPEM,
			JWKSURI:                 req.JWKSURI,
		}
		if err := host.Repo().CreateOAuth2Client(r.Context(), new); err != nil {
			writeOAuthError(w, "server_error", "create client: "+err.Error())
			return
		}
		stored, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), clientID)
		if err != nil {
			writeOAuthError(w, "server_error", "lookup created client: "+err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, createClientResponse{
			Client:       toClientJSON(*stored),
			ClientSecret: rawSecret,
		})
	}
}

// handleGetClient fetches a single client by client_id (the path
// parameter is the client_id, not the row id, to match the rest of
// OAuth2's surface).
func (p *oauth2Plugin) handleGetClient(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		c, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeOAuthError(w, "invalid_request", "client not found")
				return
			}
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, toClientJSON(*c))
	}
}

// handleListClients returns the list of banned clients only — the
// repository interface does not expose a generic "list all" method.
// This matches the surface area the underlying repo offers and keeps
// the plugin honest. Callers can still GET an individual client_id.
func (p *oauth2Plugin) handleListClients(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		banned, err := host.Repo().ListBannedOAuth2Clients(r.Context())
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		out := make([]clientJSON, 0, len(banned))
		for _, c := range banned {
			out = append(out, toClientJSON(*c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"banned": out})
	}
}

// handlePatchClient supports two operations: ban/unban and
// public-key rotation (for private_key_jwt-authenticated clients).
func (p *oauth2Plugin) handlePatchClient(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req patchClientRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		id := r.PathValue("id")

		if req.Banned != nil {
			now := time.Now().UTC()
			var bannedAt *time.Time
			var reason *string
			if *req.Banned {
				bannedAt = &now
				reason = req.BannedReason
			}
			if _, err := host.Repo().SetOAuth2ClientBanned(r.Context(), id, bannedAt, reason); err != nil {
				writeOAuthError(w, "server_error", err.Error())
				return
			}
		}
		if req.PublicKeyPEM != nil {
			if _, err := host.Repo().RotateOAuth2ClientPublicKey(r.Context(), id, req.PublicKeyPEM); err != nil {
				writeOAuthError(w, "server_error", err.Error())
				return
			}
		}
		c, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), id)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, toClientJSON(*c))
	}
}

// banRequest is the body for POST /oauth2/clients/{id}/ban.
type banRequest struct {
	Reason string `json:"reason"`
}

// rotatePublicKeyRequest is the body for POST /oauth2/clients/{id}/rotate-public-key.
type rotatePublicKeyRequest struct {
	PublicKeyPEM string `json:"public_key_pem"`
}

// handleBanClient bans a client and writes an "oauth2.client.banned"
// audit log with the acting admin's id.
func (p *oauth2Plugin) handleBanClient(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req banRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		id := r.PathValue("id")
		now := time.Now().UTC()
		var reason *string
		if req.Reason != "" {
			reason = &req.Reason
		}
		ok, err := host.Repo().SetOAuth2ClientBanned(r.Context(), id, &now, reason)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		if !ok {
			writeOAuthError(w, "invalid_request", "client not found")
			return
		}
		c, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), id)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		logClientAuditEvent(r, host, "oauth2.client.banned", id, map[string]any{"reason": req.Reason})
		writeJSON(w, http.StatusOK, toClientJSON(*c))
	}
}

// handleUnbanClient clears banned_at and banned_reason on a client and
// writes an "oauth2.client.unbanned" audit log.
func (p *oauth2Plugin) handleUnbanClient(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ok, err := host.Repo().SetOAuth2ClientBanned(r.Context(), id, nil, nil)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		if !ok {
			writeOAuthError(w, "invalid_request", "client not found")
			return
		}
		c, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), id)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		logClientAuditEvent(r, host, "oauth2.client.unbanned", id, nil)
		writeJSON(w, http.StatusOK, toClientJSON(*c))
	}
}

// handleRotatePublicKey replaces the client's registered public_key_pem
// (used for private_key_jwt verification). The submitted PEM is parsed
// to ensure it is a valid RSA or EC public key before persisting.
func (p *oauth2Plugin) handleRotatePublicKey(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req rotatePublicKeyRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		if req.PublicKeyPEM == "" {
			writeOAuthError(w, "invalid_request", "public_key_pem is required")
			return
		}
		if _, err := parsePEMKey(req.PublicKeyPEM); err != nil {
			writeOAuthError(w, "invalid_request", "public_key_pem is not a valid RSA or EC public key: "+err.Error())
			return
		}
		id := r.PathValue("id")
		pem := req.PublicKeyPEM
		ok, err := host.Repo().RotateOAuth2ClientPublicKey(r.Context(), id, &pem)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		if !ok {
			writeOAuthError(w, "invalid_request", "client not found")
			return
		}
		// Drop any cached JWKS for this client. Public-key path is keyed
		// by jwks_uri, so it is unaffected here, but a safe no-op.
		c, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), id)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		logClientAuditEvent(r, host, "oauth2.client.public_key_rotated", id, nil)
		writeJSON(w, http.StatusOK, toClientJSON(*c))
	}
}

// logClientAuditEvent records an OAuth2 client admin event. extra is
// merged into the audit metadata alongside admin_id and client_id.
func logClientAuditEvent(r *http.Request, host plugin.PluginHost, eventType, clientID string, extra map[string]any) {
	meta := map[string]any{"client_id": clientID}
	if au, ok := middleware.AuthUserFromContext(r.Context()); ok && au != nil {
		meta["admin_id"] = au.User.ID
	}
	for k, v := range extra {
		meta[k] = v
	}
	raw, _ := json.Marshal(meta)
	_ = host.Repo().LogAuditEvent(r.Context(), domain.NewAuditLog{
		ID:        uuid.NewString(),
		EventType: eventType,
		Metadata:  raw,
		CreatedAt: time.Now().UTC(),
	})
}

// handleDeleteClient soft-deletes (bans) a client. Hard delete is not
// exposed because issued tokens still reference the client.
func (p *oauth2Plugin) handleDeleteClient(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		now := time.Now().UTC()
		reason := stringPtr("deleted via DELETE /oauth2/clients/" + id)
		ok, err := host.Repo().SetOAuth2ClientBanned(r.Context(), id, &now, reason)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		if !ok {
			writeOAuthError(w, "invalid_request", "client not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
