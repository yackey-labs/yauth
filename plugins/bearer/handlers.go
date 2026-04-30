package bearer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- response shapes ---------------------------------------------------

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

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

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- POST /token -------------------------------------------------------

type tokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (p *bearerPlugin) handleToken(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "email and password are required")
			return
		}

		ctx := r.Context()
		repo := host.Repo()

		user, err := repo.GetUserByEmail(ctx, req.Email)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				_ = auth.DummyVerify(req.Password)
				writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up user")
			return
		}
		if user.Banned {
			writeError(w, http.StatusForbidden, "USER_BANNED", "account suspended")
			return
		}

		pw, err := repo.GetPasswordByUserID(ctx, user.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				_ = auth.DummyVerify(req.Password)
				writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up password")
			return
		}
		ok, err := auth.VerifyPassword(req.Password, pw.PasswordHash)
		if err != nil || !ok {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
			return
		}

		resp, err := p.mintTokens(ctx, host, user.ID, uuid.NewString())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to mint tokens")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- POST /token/refresh ----------------------------------------------

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (p *bearerPlugin) handleRefresh(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if req.RefreshToken == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "refresh_token is required")
			return
		}

		ctx := r.Context()
		repo := host.Repo()

		hash := auth.HashToken(req.RefreshToken)
		stored, err := repo.GetRefreshTokenByHash(ctx, hash)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusUnauthorized, "INVALID_GRANT", "refresh token not recognised")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up refresh token")
			return
		}

		// Reuse detection: a previously revoked refresh token has been
		// presented again. Revoke the entire family — this is the
		// standard rotation-attack mitigation.
		if stored.Revoked {
			_, _ = repo.RevokeRefreshTokenFamily(ctx, stored.FamilyID)
			writeError(w, http.StatusUnauthorized, "REFRESH_REUSE", "refresh token reuse detected; family revoked")
			return
		}
		if !stored.ExpiresAt.After(time.Now().UTC()) {
			writeError(w, http.StatusUnauthorized, "TOKEN_EXPIRED", "refresh token expired")
			return
		}

		user, err := repo.GetUserByID(ctx, stored.UserID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusUnauthorized, "INVALID_GRANT", "user no longer exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up user")
			return
		}
		if user.Banned {
			writeError(w, http.StatusForbidden, "USER_BANNED", "account suspended")
			return
		}

		// Rotation: revoke the presented token, mint a fresh pair under
		// the same family.
		if err := repo.RevokeRefreshToken(ctx, stored.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to rotate refresh token")
			return
		}
		resp, err := p.mintTokens(ctx, host, user.ID, stored.FamilyID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to mint tokens")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- POST /token/revoke ----------------------------------------------

type revokeRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (p *bearerPlugin) handleRevoke(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		var req revokeRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if req.RefreshToken == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "refresh_token is required")
			return
		}

		ctx := r.Context()
		repo := host.Repo()

		stored, err := repo.GetRefreshTokenByHash(ctx, auth.HashToken(req.RefreshToken))
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// RFC 7009: revocation is idempotent — unknown tokens
				// return 200.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up refresh token")
			return
		}
		if stored.UserID != au.User.ID {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "refresh token does not belong to caller")
			return
		}
		if _, err := repo.RevokeRefreshTokenFamily(ctx, stored.FamilyID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to revoke refresh token")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- shared minting ---------------------------------------------------

// mintTokens issues an access JWT and a fresh refresh token under
// familyID, persists the refresh-token row, and returns the response
// body.
func (p *bearerPlugin) mintTokens(ctx context.Context, host plugin.PluginHost, userID, familyID string) (tokenResponse, error) {
	now := time.Now().UTC()

	access, _, err := signAccessToken(p.cfg.JWTSecret, userID, uuid.NewString(), p.cfg, now)
	if err != nil {
		return tokenResponse{}, err
	}

	refreshRaw, refreshHash, err := auth.GenerateSessionToken()
	if err != nil {
		return tokenResponse{}, err
	}
	if err := host.Repo().CreateRefreshToken(ctx, domain.NewRefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: refreshHash,
		FamilyID:  familyID,
		ExpiresAt: now.Add(p.cfg.RefreshTTL),
		CreatedAt: now,
	}); err != nil {
		return tokenResponse{}, err
	}

	return tokenResponse{
		AccessToken:  access,
		RefreshToken: refreshRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(p.cfg.AccessTTL.Seconds()),
	}, nil
}
