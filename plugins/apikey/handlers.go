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

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
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

// decodeJSON parses r.Body into v with a 1 MiB cap.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
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

type createRequest struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes,omitempty"`
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
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
// RequireAuthHuma. It pairs with StashHTTPHuma and reuses the strict decodeJSON
// (DisallowUnknownFields, 1 MiB cap) on the stashed request so the request body
// parsing — including the 400 on unknown/malformed fields — stays
// byte-identical to the legacy handler. The input struct carries NO huma Body
// field, so huma never consumes the body itself.
func (p *apiKeyPlugin) registerCreate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "apikey-create",
		Method:        http.MethodPost,
		Path:          prefix + "/api-keys",
		Summary:       "Create a new API key",
		Tags:          []string{"api-key"},
		Security:      apiKeySecurity(),
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{middleware.StashHTTPHuma(api), middleware.RequireAuthHuma(api, mw)},
	}, func(ctx context.Context, _ *struct{}) (*createOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		var req createRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		var expiresAt *time.Time
		if req.ExpiresInDays != nil {
			if *req.ExpiresInDays <= 0 {
				return nil, huma.Error400BadRequest("expires_in_days must be positive")
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
func (p *apiKeyPlugin) registerDelete(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "apikey-delete",
		Method:        http.MethodDelete,
		Path:          prefix + "/api-keys/{id}",
		Summary:       "Revoke an API key by ID",
		Tags:          []string{"api-key"},
		Security:      apiKeySecurity(),
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{middleware.RequireAuthHuma(api, mw)},
	}, func(ctx context.Context, in *deleteInput) (*emptyOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
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
		return &emptyOutput{}, nil
	})
}
