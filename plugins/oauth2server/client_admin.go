package oauth2server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
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
	EnforceGroupAssignment  bool      `json:"enforce_group_assignment"`
	CreatedAt               time.Time `json:"created_at"`

	PostLogoutRedirectURIs           []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI             *string  `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool     `json:"backchannel_logout_session_required"`
}

// createClientRequest is the body for POST /oauth2/clients. It is a native
// huma typed Body (additionalProperties:false rejects unknown fields → 422),
// so the request schema auto-derives.
type createClientRequest struct {
	// Every field is omitempty so huma imposes no required constraint the
	// bridged strict-decoder did not: the legacy handler accepted bodies with
	// zero redirect_uris / absent grant_types (e.g. a public device-flow or a
	// client_credentials-only confidential client), validating per-grant later
	// on /authorize and /token. Marking any field required would 422 those
	// legitimate bodies.
	Name                    *string  `json:"name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	IsPublic                bool     `json:"is_public,omitempty"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method,omitempty"`
	PublicKeyPEM            *string  `json:"public_key_pem,omitempty"`
	JWKSURI                 *string  `json:"jwks_uri,omitempty"`
	EnforceGroupAssignment  bool     `json:"enforce_group_assignment,omitempty"`

	PostLogoutRedirectURIs           []string `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI             *string  `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool     `json:"backchannel_logout_session_required,omitempty"`

	_ struct{} `json:"-" additionalProperties:"false"`
}

// createClientInput is the native huma request wrapper for POST /oauth2/clients.
type createClientInput struct {
	Body createClientRequest
}

type createClientResponse struct {
	Client       clientJSON `json:"client"`
	ClientSecret *string    `json:"client_secret,omitempty"`
}

// createClientOutput wraps createClientResponse; DefaultStatus drives the 201.
type createClientOutput struct {
	Body createClientResponse
}

// patchClientRequest is the body for PATCH /oauth2/clients/{id}. Pointer
// fields are absent when not changing; an explicit Banned=false unbans. It is a
// native huma typed Body (additionalProperties:false → 422 on unknown fields).
type patchClientRequest struct {
	Banned                 *bool   `json:"banned,omitempty"`
	BannedReason           *string `json:"banned_reason,omitempty"`
	PublicKeyPEM           *string `json:"public_key_pem,omitempty"`
	EnforceGroupAssignment *bool   `json:"enforce_group_assignment,omitempty"`

	// OIDC logout config. Any non-nil field triggers a logout-config update
	// (merged with the client's current values for the fields left nil).
	PostLogoutRedirectURIs           *[]string `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI             *string   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired *bool     `json:"backchannel_logout_session_required,omitempty"`

	_ struct{} `json:"-" additionalProperties:"false"`
}

// patchClientInput is the native huma request for PATCH /oauth2/clients/{id}:
// the {id} path param plus the typed JSON body.
type patchClientInput struct {
	ID   string `path:"id"`
	Body patchClientRequest
}

// clientOutput wraps a single clientJSON (the 200 body shared by patch).
type clientOutput struct {
	Body clientJSON
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
		EnforceGroupAssignment:  c.EnforceGroupAssignment,
		CreatedAt:               c.CreatedAt,

		PostLogoutRedirectURIs:           decodeScopes(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: c.BackchannelLogoutSessionRequired,
	}
}

// handleCreateClient registers a new OAuth2 client. For confidential
// clients (is_public=false) a fresh secret is generated, hashed, and
// returned exactly once in the response.
//
// This is a native huma handler: huma parses + validates the typed Body
// (additionalProperties:false → 422 on unknown/malformed JSON), so the
// request schema auto-derives and the old strict-decoder bridge is gone.
// Business errors keep their original status: a server-side failure that
// the legacy handler wrote as RFC 6749 server_error (HTTP 500) becomes
// huma.Error500InternalServerError (problem+json, same 500). The 201 success
// shape ({client, client_secret}) is byte-identical.
func (p *oauth2Plugin) handleCreateClient(host plugin.PluginHost) func(context.Context, *createClientInput) (*createClientOutput, error) {
	return func(ctx context.Context, in *createClientInput) (*createClientOutput, error) {
		req := in.Body
		// Confidential clients used only for client_credentials and
		// public clients used for the device flow may legitimately
		// have zero redirect_uris. Validation is per-grant on the
		// /authorize and /token paths.

		// Repair copy/paste damage: strip CR/LF that terminals inject when
		// wrapping long redirect URIs.
		for i := range req.RedirectURIs {
			req.RedirectURIs[i] = sanitizeURL(req.RedirectURIs[i])
		}
		for i := range req.PostLogoutRedirectURIs {
			req.PostLogoutRedirectURIs[i] = sanitizeURL(req.PostLogoutRedirectURIs[i])
		}
		if req.BackchannelLogoutURI != nil {
			s := sanitizeURL(*req.BackchannelLogoutURI)
			req.BackchannelLogoutURI = &s
		}

		clientID, err := randomHex(16)
		if err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}
		var secretHash *string
		var rawSecret *string
		if !req.IsPublic {
			s, err := randomHex(24)
			if err != nil {
				return nil, huma.Error500InternalServerError(err.Error())
			}
			h, err := auth.HashPassword(s)
			if err != nil {
				return nil, huma.Error500InternalServerError(err.Error())
			}
			secretHash = &h
			rawSecret = &s
		}

		now := time.Now().UTC()
		newClient := domain.NewOAuth2Client{
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
			EnforceGroupAssignment:  req.EnforceGroupAssignment,

			PostLogoutRedirectURIs:           rawJSON(req.PostLogoutRedirectURIs),
			BackchannelLogoutURI:             req.BackchannelLogoutURI,
			BackchannelLogoutSessionRequired: req.BackchannelLogoutSessionRequired,
		}
		if err := host.Repo().CreateOAuth2Client(ctx, newClient); err != nil {
			return nil, huma.Error500InternalServerError("create client: " + sanitizeErr(err))
		}
		stored, err := host.Repo().GetOAuth2ClientByClientID(ctx, clientID)
		if err != nil {
			return nil, huma.Error500InternalServerError("lookup created client: " + sanitizeErr(err))
		}
		return &createClientOutput{Body: createClientResponse{
			Client:       toClientJSON(*stored),
			ClientSecret: rawSecret,
		}}, nil
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

// handleListClients returns all registered clients (admin enumeration). Each
// entry carries its banned status. The legacy "banned" key is kept for
// backward compatibility with callers that only read banned clients.
func (p *oauth2Plugin) handleListClients(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients, err := host.Repo().ListOAuth2Clients(r.Context())
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		items := make([]clientJSON, 0, len(clients))
		banned := make([]clientJSON, 0)
		for _, c := range clients {
			j := toClientJSON(*c)
			items = append(items, j)
			if j.Banned {
				banned = append(banned, j)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "banned": banned})
	}
}

// handlePatchClient supports two operations: ban/unban and
// public-key rotation (for private_key_jwt-authenticated clients).
//
// Native huma handler: typed Body (additionalProperties:false → 422 on
// unknown/malformed JSON). Business errors keep their legacy status —
// invalid_request → 400 (huma.Error400BadRequest), server_error → 500
// (huma.Error500InternalServerError) — emitted as problem+json. The 200
// clientJSON body is unchanged.
func (p *oauth2Plugin) handlePatchClient(host plugin.PluginHost) func(context.Context, *patchClientInput) (*clientOutput, error) {
	return func(ctx context.Context, in *patchClientInput) (*clientOutput, error) {
		req := in.Body
		id := in.ID

		if req.Banned != nil {
			now := time.Now().UTC()
			var bannedAt *time.Time
			var reason *string
			if *req.Banned {
				bannedAt = &now
				reason = req.BannedReason
			}
			if _, err := host.Repo().SetOAuth2ClientBanned(ctx, id, bannedAt, reason); err != nil {
				return nil, huma.Error500InternalServerError(err.Error())
			}
		}
		if req.PublicKeyPEM != nil {
			if _, err := host.Repo().RotateOAuth2ClientPublicKey(ctx, id, req.PublicKeyPEM); err != nil {
				return nil, huma.Error500InternalServerError(err.Error())
			}
		}
		if req.EnforceGroupAssignment != nil {
			if err := host.Repo().SetClientEnforceGroupAssignment(ctx, id, *req.EnforceGroupAssignment); err != nil {
				return nil, huma.Error500InternalServerError(err.Error())
			}
		}
		if req.PostLogoutRedirectURIs != nil || req.BackchannelLogoutURI != nil || req.BackchannelLogoutSessionRequired != nil {
			// Merge against current values for the logout fields not provided.
			cur, err := host.Repo().GetOAuth2ClientByClientID(ctx, id)
			if err != nil {
				if errors.Is(err, yautherr.ErrNotFound) {
					return nil, huma.Error400BadRequest("client not found")
				}
				return nil, huma.Error500InternalServerError(err.Error())
			}
			plru := cur.PostLogoutRedirectURIs
			if req.PostLogoutRedirectURIs != nil {
				uris := *req.PostLogoutRedirectURIs
				for i := range uris {
					uris[i] = sanitizeURL(uris[i])
				}
				plru = rawJSON(uris)
			}
			bclURI := cur.BackchannelLogoutURI
			if req.BackchannelLogoutURI != nil {
				s := sanitizeURL(*req.BackchannelLogoutURI)
				if s == "" {
					bclURI = nil // explicit empty string clears back-channel logout
				} else {
					bclURI = &s
				}
			}
			sessReq := cur.BackchannelLogoutSessionRequired
			if req.BackchannelLogoutSessionRequired != nil {
				sessReq = *req.BackchannelLogoutSessionRequired
			}
			if _, err := host.Repo().SetOAuth2ClientLogout(ctx, id, plru, bclURI, sessReq); err != nil {
				return nil, huma.Error500InternalServerError(err.Error())
			}
		}
		c, err := host.Repo().GetOAuth2ClientByClientID(ctx, id)
		if err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}
		return &clientOutput{Body: toClientJSON(*c)}, nil
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
			writeOAuthError(w, "invalid_request", "public_key_pem is not a valid RSA or EC public key: "+sanitizeErr(err)) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
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
