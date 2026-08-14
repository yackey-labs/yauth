package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. On a route in
// this plugin's GET/POST chain it is always present; the nil guard keeps the
// helper safe.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

// auditAPIKeyEvent writes one API-key lifecycle row through the audit
// choke point, so it is both persisted and handed to the host's audit
// recorders (audit-export's outbox). Errors are swallowed on purpose: a
// key was minted or revoked, and an unhappy audit store must not turn that
// into a 500 the caller retries.
//
// The actor is au.User.ID, which is the human for a user principal and the
// key's creator for a service account (domain.AuthUser.Principal
// synthesises it from CreatedBy). actor_kind carries the distinction, so a
// key minted BY a machine is never mistaken for one a person asked for.
func auditAPIKeyEvent(ctx context.Context, host plugin.PluginHost, event string, au *domain.AuthUser, r *http.Request, fields map[string]any) {
	if au == nil {
		return
	}
	meta := map[string]any{"actor_kind": actorKind(au)}
	for k, v := range fields {
		meta[k] = v
	}
	raw, _ := json.Marshal(meta)
	uid := au.User.ID
	var ip *string
	if r != nil {
		ip = middleware.RequestIP(r)
	}
	_ = plugin.WriteAudit(ctx, host, domain.NewAuditLog{
		ID:        uuid.NewString(),
		UserID:    &uid,
		EventType: event,
		Metadata:  raw,
		IPAddress: ip,
		CreatedAt: time.Now().UTC(),
	})
}

// actorKind reports whether the caller acted as a human or as a service
// account, for the audit row.
func actorKind(au *domain.AuthUser) string {
	if au.Principal.IsServiceAccount() {
		return "service_account"
	}
	return "user"
}

// apiKeyJSON is the JSON shape returned by the management endpoints. It
// deliberately omits any secret material — only the prefix and metadata.
type apiKeyJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func toAPIKeyJSON(k domain.APIKey) apiKeyJSON {
	return apiKeyJSON{
		ID:         k.ID,
		Name:       k.Name,
		Prefix:     k.KeyPrefix,
		Scopes:     decodeScopes(k.Scopes),
		LastUsedAt: k.LastUsedAt,
		ExpiresAt:  k.ExpiresAt,
		CreatedAt:  k.CreatedAt,
	}
}

// decodeScopes converts the stored scopes column into a string slice. An
// invalid or empty payload yields a non-nil empty slice so the JSON
// response is always "scopes": [] rather than null.
func decodeScopes(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return []string{}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// requireUserPrincipal rejects callers who are not the user acting in their
// own right on the personal key-management routes.
//
// An org-scoped API key resolves to an AuthUser whose User is the human who
// MINTED it, so these handlers — which read and write "the caller's" keys via
// au.User.ID — would otherwise let a machine credential enumerate its
// creator's personal keys, delete them, and (worst) mint a NEW user-scoped
// key for that person: a credential with no org binding at all, which
// resolves as the human on every route. A service account's authority is its
// own key row; issuing itself a human one is a straight escalation.
//
// A DELEGATED OAuth2 access token — one a relying party holds on the user's
// behalf — is refused for the same reason and then some: POST /api-keys hands
// it a permanent secret that OUTLIVES the OAuth grant and is not revoked when
// the user revokes the app. Signing in to a third-party app with yauth must
// not be a way for that app to issue itself a standing credential. See
// bearer.Config.ResourceIdentifiers for which tokens count as delegated.
func requireUserPrincipal(au *domain.AuthUser) error {
	if au == nil {
		return nil
	}
	if au.Principal.IsServiceAccount() {
		return huma.Error403Forbidden("service accounts cannot manage a user's personal API keys")
	}
	if au.Principal.IsDelegated() {
		return huma.Error403Forbidden(middleware.DelegatedCredentialDetail)
	}
	return nil
}

// --- GET /api-keys ------------------------------------------------------

// listResponse wraps the GET /api-keys collection with pagination
// metadata. Wrapping (over a bare array) lets us add fields later
// without breaking clients.
type listResponse struct {
	Items   []apiKeyJSON `json:"items"`
	Total   int64        `json:"total"`
	Page    int          `json:"page"`
	PerPage int          `json:"per_page"`
}

// listOutput wraps listResponse so huma marshals exactly the body the legacy
// handleList produced.
type listOutput struct {
	Body listResponse
}

// registerList wires GET /api-keys as a huma-native operation guarded by
// RequireAuthHuma. It pairs with StashHTTPHuma so paginationFromQuery keeps its
// lenient ?page=/?per_page= parsing (bad values degrade to defaults rather than
// 400) — typed huma query params would 422 instead, changing behaviour.
func (p *apiKeyPlugin) registerList(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "apikey-list",
		Method:      http.MethodGet,
		Path:        prefix + "/api-keys",
		Summary:     "List the current user's API keys",
		Tags:        []string{"api-key"},
		Security:    apiKeySecurity(),
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api), middleware.RequireAuthHuma(api, mw)},
	}, func(ctx context.Context, _ *struct{}) (*listOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		if err := requireUserPrincipal(au); err != nil {
			return nil, err
		}
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		page, perPage := paginationFromQuery(r)

		rows, err := host.Repo().ListAPIKeysByUserID(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list api keys")
		}
		total := int64(len(rows))
		// Repo currently returns the full list; slice in-memory for now.
		// This matches the existing behavior — only the wire shape is
		// changing here.
		start := (page - 1) * perPage
		end := start + perPage
		if start > len(rows) {
			start = len(rows)
		}
		if end > len(rows) {
			end = len(rows)
		}
		page1 := rows[start:end]

		out := make([]apiKeyJSON, 0, len(page1))
		for _, k := range page1 {
			if k == nil {
				continue
			}
			out = append(out, toAPIKeyJSON(*k))
		}
		return &listOutput{Body: listResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		}}, nil
	})
}

// paginationFromQuery parses ?page= and ?per_page= with sane defaults
// (page 1, per_page 50 capped at 200). Invalid values fall back to the
// defaults silently — the list is non-critical and we'd rather degrade
// than 400 on a typo.
func paginationFromQuery(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 50
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := parsePositiveInt(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := parsePositiveInt(v); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			perPage = n
		}
	}
	return page, perPage
}

func parsePositiveInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not an integer")
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0, errors.New("too large")
		}
	}
	return n, nil
}

// --- POST /api-keys -----------------------------------------------------

const (
	// MaxExpiresInDays bounds expires_in_days on every key-creating route
	// (this one and the org-scoped one in plugins/organizations, which
	// reuses the constant).
	//
	// The lifetime is computed as time.Duration(days) * 24 * time.Hour,
	// which is int64 nanoseconds and WRAPS above roughly 106,751 days:
	// expires_in_days=200000 answered 201, handed back a plaintext secret,
	// and stored an expires_at in 1989 — a credential dead on arrival, with
	// nothing in the response to say so.
	//
	// The bound is 100 years rather than a tidier ten because no maximum
	// was ever documented (not in openapi.json, not in the generated
	// clients) and a request that works today must keep working: a 20-year
	// service key is unusual, not invalid. This refuses only values that
	// were already broken, with three orders of magnitude of headroom below
	// the wrap.
	MaxExpiresInDays = 36500

	// ExpiresInDaysRangeMsg is the 400 detail for an out-of-range value,
	// shared so both key-creating routes answer identically.
	ExpiresInDaysRangeMsg = "expires_in_days must be between 1 and 36500"
)

type createRequest struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes,omitempty"`
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
	_             struct{} `json:"-" additionalProperties:"false"`
}

// createInput is the huma-native request: a typed JSON body. huma parses +
// validates it (and rejects unknown fields via additionalProperties:false),
// so the spec auto-derives the request schema — no StashHTTPHuma bridge.
type createInput struct {
	Body createRequest
}

// createResponse splits the persisted key metadata from the one-time
// plaintext secret. Wrapping the metadata under `api_key` and exposing
// the plaintext separately as `secret` keeps logging-vs-display
// concerns clearly separated — clients can log api_key freely while
// keeping `secret` out of structured logs.
type createResponse struct {
	APIKey apiKeyJSON `json:"api_key"`
	Secret string     `json:"secret"`
}

// createOutput wraps createResponse and drives the 201 status via the
// operation's DefaultStatus.
type createOutput struct {
	Body createResponse
}

// registerCreate wires POST /api-keys as a huma-native operation guarded by
// RequireAuthHuma. The request body is a native huma typed Body, so huma
// parses + validates it and the OpenAPI request schema auto-derives;
// additionalProperties:false rejects unknown fields (422).
//
// It is also guarded by RejectMachineCredentialHuma: an API key that can mint
// another API key is a persistence primitive, not a convenience. A key leaked
// from a build log used to answer 201 with a fresh secret, as many times as
// MaxKeysPerUser allowed, so revoking the leaked key left every replacement
// live. Minting a lasting credential is a decision a human makes from a
// session (or a first-party /token pair); the key itself does not get a vote.
func (p *apiKeyPlugin) registerCreate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "apikey-create",
		Method:        http.MethodPost,
		Path:          prefix + "/api-keys",
		Summary:       "Create a new API key",
		Tags:          []string{"api-key"},
		Security:      apiKeySecurity(),
		DefaultStatus: http.StatusCreated,
		Middlewares: huma.Middlewares{
			// Stashed so the audit row below can carry the client IP that
			// minted the key. Middlewares are absent from the OpenAPI
			// document, and the typed Body still auto-derives its schema.
			middleware.StashHTTPHuma(api),
			middleware.RequireAuthHuma(api, mw),
			middleware.RejectMachineCredentialHuma(api),
		},
	}, func(ctx context.Context, in *createInput) (*createOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		if err := requireUserPrincipal(au); err != nil {
			return nil, err
		}
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		req := in.Body
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		var expiresAt *time.Time
		if req.ExpiresInDays != nil {
			if *req.ExpiresInDays <= 0 {
				return nil, huma.Error400BadRequest("expires_in_days must be positive")
			}
			if *req.ExpiresInDays > MaxExpiresInDays {
				return nil, huma.Error400BadRequest(ExpiresInDaysRangeMsg)
			}
			t := time.Now().UTC().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
			expiresAt = &t
		}

		repo := host.Repo()
		existing, err := repo.ListAPIKeysByUserID(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to count api keys")
		}
		if len(existing) >= p.cfg.MaxKeysPerUser {
			return nil, huma.Error409Conflict("max api keys per user reached")
		}

		gen, err := GenerateKey(p.cfg.Prefix)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate key")
		}

		scopesJSON := encodeScopes(req.Scopes)

		now := time.Now().UTC()
		uid := au.User.ID
		input := domain.NewAPIKey{
			ID:              uuid.NewString(),
			UserID:          &uid,
			KeyPrefix:       gen.Prefix,
			KeyHash:         gen.Hash,
			Name:            req.Name,
			Scopes:          scopesJSON,
			ExpiresAt:       expiresAt,
			CreatedAt:       now,
			CreatedByUserID: au.User.ID,
		}
		if err := repo.CreateAPIKey(ctx, input); err != nil {
			return nil, huma.Error500InternalServerError("unable to store api key")
		}

		// Minting a key is a persistence primitive — a bearer credential
		// that authenticates as its owner on every route and, by default,
		// never expires — and it used to leave exactly the footprint of a
		// GET: none. An attacker who held a session for five minutes could
		// issue themselves a standing credential and the audit log showed
		// only the login. Every other credential lifecycle in the tree
		// (password change, admin ban, SCIM deprovision) writes a row.
		//
		// credential_id, not key_id: the host's scrubber redacts any
		// metadata key containing "key", and while WriteAudit does not
		// scrub, keeping the field name clear of that fragment means the row
		// reads the same wherever it is copied. Only the id and the public
		// prefix go in — never the plaintext secret and never its hash.
		auditAPIKeyEvent(ctx, host, "apikey.created", au, r, map[string]any{
			"credential_id": input.ID,
			"prefix":        input.KeyPrefix,
		})

		return &createOutput{Body: createResponse{
			APIKey: apiKeyJSON{
				ID:        input.ID,
				Name:      input.Name,
				Prefix:    input.KeyPrefix,
				Scopes:    normalizeScopes(req.Scopes),
				CreatedAt: input.CreatedAt,
				ExpiresAt: input.ExpiresAt,
			},
			Secret: gen.Plaintext,
		}}, nil
	})
}

// encodeScopes serialises a (possibly nil) scope slice into its stored
// JSON form. The empty slice round-trips as "[]".
func encodeScopes(scopes []string) json.RawMessage {
	if scopes == nil {
		scopes = []string{}
	}
	b, err := json.Marshal(scopes)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

// normalizeScopes returns a non-nil slice so downstream JSON encoding
// emits "[]" instead of null.
func normalizeScopes(scopes []string) []string {
	if scopes == nil {
		return []string{}
	}
	return scopes
}

// --- DELETE /api-keys/{id} ----------------------------------------------

// deleteInput is the typed request for DELETE /api-keys/{id}: a single
// required path parameter. huma's router guarantees a non-empty {id}, so the
// legacy empty-id 400 branch is unreachable and dropped.
type deleteInput struct {
	ID string `path:"id" doc:"API key ID"`
}

// emptyOutput carries no body and lets the operation drive a 204 via
// DefaultStatus.
type emptyOutput struct{}

// registerDelete wires DELETE /api-keys/{id} as a huma-native operation guarded
// by RequireAuthHuma. It takes a native path param (no StashHTTPHuma needed —
// no body, no custom query parsing) and returns 204 via DefaultStatus.
//
// RejectMachineCredentialHuma guards it for the mirror-image reason it guards
// create: whoever holds a leaked key must not be able to take the OWNER's
// credentials away — including the key the owner would use to notice. GET
// /api-keys is deliberately left open; reading its own list is what a key is
// for, and it reveals no secret.
func (p *apiKeyPlugin) registerDelete(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "apikey-delete",
		Method:        http.MethodDelete,
		Path:          prefix + "/api-keys/{id}",
		Summary:       "Revoke an API key by ID",
		Tags:          []string{"api-key"},
		Security:      apiKeySecurity(),
		DefaultStatus: http.StatusNoContent,
		Middlewares: huma.Middlewares{
			// Stashed for the audit row's client IP, as on create.
			middleware.StashHTTPHuma(api),
			middleware.RequireAuthHuma(api, mw),
			middleware.RejectMachineCredentialHuma(api),
		},
	}, func(ctx context.Context, in *deleteInput) (*emptyOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		if err := requireUserPrincipal(au); err != nil {
			return nil, err
		}
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		repo := host.Repo()

		// Ownership check: only allow deleting keys that belong to the
		// caller. Without this, any authenticated user could delete
		// another user's key by guessing the id.
		if _, err := repo.GetAPIKeyByIDAndUser(ctx, in.ID, au.User.ID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("api key not found")
			}
			return nil, huma.Error500InternalServerError("unable to look up api key")
		}

		if err := repo.DeleteAPIKey(ctx, in.ID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("api key not found")
			}
			return nil, huma.Error500InternalServerError("unable to delete api key")
		}
		// The mirror of the mint row: without it there is no record of WHEN
		// a credential stopped being valid, which is the first question
		// asked about a key that turns up in a leak.
		auditAPIKeyEvent(ctx, host, "apikey.revoked", au, r, map[string]any{
			"credential_id": in.ID,
		})
		return &emptyOutput{}, nil
	})
}
