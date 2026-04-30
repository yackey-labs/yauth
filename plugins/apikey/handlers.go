package apikey

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

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

// errorBody mirrors the canonical error envelope used elsewhere in
// yauth-go.
type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorPayload{Code: code, Message: message}})
}

// decodeJSON parses r.Body into v with a 1 MiB cap.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- GET /api-keys ------------------------------------------------------

type listResponse struct {
	Keys []apiKeyJSON `json:"keys"`
}

func (p *apiKeyPlugin) handleList(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}

		rows, err := host.Repo().ListAPIKeysByUserID(r.Context(), au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list api keys")
			return
		}
		out := make([]apiKeyJSON, 0, len(rows))
		for _, k := range rows {
			if k == nil {
				continue
			}
			out = append(out, toAPIKeyJSON(*k))
		}
		writeJSON(w, http.StatusOK, listResponse{Keys: out})
	}
}

// --- POST /api-keys -----------------------------------------------------

type createRequest struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// createResponse returns the persisted key metadata plus the one-time
// plaintext value. The plaintext is shown ONCE and is unrecoverable
// thereafter — callers must capture it from this response.
type createResponse struct {
	APIKey apiKeyJSON `json:"api_key"`
	Key    string     `json:"key"`
}

func (p *apiKeyPlugin) handleCreate(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}

		var req createRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "INVALID_NAME", "name is required")
			return
		}
		if req.ExpiresAt != nil && !req.ExpiresAt.UTC().After(time.Now().UTC()) {
			writeError(w, http.StatusBadRequest, "INVALID_EXPIRY", "expires_at must be in the future")
			return
		}

		repo := host.Repo()
		existing, err := repo.ListAPIKeysByUserID(r.Context(), au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to count api keys")
			return
		}
		if len(existing) >= p.cfg.MaxKeysPerUser {
			writeError(w, http.StatusConflict, "TOO_MANY_KEYS", "max api keys per user reached")
			return
		}

		gen, err := GenerateKey(p.cfg.Prefix)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate key")
			return
		}

		scopesJSON := encodeScopes(req.Scopes)

		now := time.Now().UTC()
		input := domain.NewAPIKey{
			ID:        uuid.NewString(),
			UserID:    au.User.ID,
			KeyPrefix: gen.Prefix,
			KeyHash:   gen.Hash,
			Name:      req.Name,
			Scopes:    scopesJSON,
			ExpiresAt: req.ExpiresAt,
			CreatedAt: now,
		}
		if err := repo.CreateAPIKey(r.Context(), input); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to store api key")
			return
		}

		writeJSON(w, http.StatusCreated, createResponse{
			APIKey: apiKeyJSON{
				ID:         input.ID,
				Name:       input.Name,
				Prefix:     input.KeyPrefix,
				Scopes:     normalizeScopes(req.Scopes),
				LastUsedAt: nil,
				ExpiresAt:  input.ExpiresAt,
				CreatedAt:  input.CreatedAt,
			},
			Key: gen.Plaintext,
		})
	}
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

func (p *apiKeyPlugin) handleDelete(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		id := r.PathValue("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "id is required")
			return
		}

		repo := host.Repo()

		// Ownership check: only allow deleting keys that belong to the
		// caller. Without this, any authenticated user could delete
		// another user's key by guessing the id.
		if _, err := repo.GetAPIKeyByIDAndUser(r.Context(), id, au.User.ID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "api key not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up api key")
			return
		}

		if err := repo.DeleteAPIKey(r.Context(), id); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "api key not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete api key")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
