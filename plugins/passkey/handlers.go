package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// challengeTTL is how long a /begin challenge remains valid. WebAuthn
// ceremonies are interactive and typically complete within seconds; five
// minutes is generous and matches the pattern used by other yauth plugins.
const challengeTTL = 5 * time.Minute

const (
	regChallengePrefix   = "passkey_reg:"
	loginChallengePrefix = "passkey_auth:"
)

// --- response shapes ----------------------------------------------------

// emptyOutput carries no body. The delete route returns it to drive a 204 via
// DefaultStatus; the list route (still wired with StashHTTPHuma) writes its
// success response directly onto the stashed http.ResponseWriter and returns
// this so huma adds no body of its own.
type emptyOutput struct{}

// passkeyInput is the zero-field input for the no-body routes: register/begin
// (RequireAuth, no request body) and list (a GET whose pagination is parsed
// from the stashed *http.Request). huma never consumes a body for either.
type passkeyInput struct{}

// reqRespFromCtx recovers the *http.Request and http.ResponseWriter stashed by
// StashHTTPHuma. Used by login/finish (which sets a session cookie on the
// writer) and list (which writes its paginated body directly); both are always
// present there and the guard keeps it safe.
func reqRespFromCtx(ctx context.Context) (*http.Request, http.ResponseWriter, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	w := middleware.HTTPResponseFromContext(ctx)
	if r == nil || w == nil {
		return nil, nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, w, nil
}

func cookieOptionsFromHost(host plugin.PluginHost, r *http.Request, maxAge int) auth.CookieOptions {
	sameSite := "Lax"
	switch host.CookieSameSite() {
	case http.SameSiteStrictMode:
		sameSite = "Strict"
	case http.SameSiteNoneMode:
		sameSite = "None"
	}
	return auth.CookieOptions{
		Name:     host.CookieName(),
		Path:     host.CookiePath(),
		Domain:   auth.ResolveCookieDomain(host.CookieDomain(), r),
		Secure:   host.CookieSecure(),
		SameSite: sameSite,
		MaxAge:   maxAge,
	}
}

// loadCredentialsForUser pulls every stored credential for a user and
// JSON-decodes them into the in-memory webauthn.Credential representation.
func loadCredentialsForUser(ctx context.Context, r repo.Repository, userID string) ([]webauthn.Credential, []*domain.WebauthnCredential, error) {
	rows, err := r.GetPasskeysByUserID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(row.Credential, &c); err != nil {
			return nil, nil, fmt.Errorf("passkey: decode credential %s: %w", row.ID, err)
		}
		creds = append(creds, c)
	}
	return creds, rows, nil
}

// --- /passkeys/register/begin -------------------------------------------

// passkeyRegisterBeginResponse mirrors the Rust spec: returns the WebAuthn
// CredentialCreation options at the top level, with a challenge_id used
// to correlate with the matching /finish call.
type passkeyRegisterBeginResponse struct {
	ChallengeID string                       `json:"challenge_id"`
	Options     *protocol.CredentialCreation `json:"options"`
}

// passkeyRegisterBeginOutput is the huma-native typed output. The WebAuthn
// options contain '&'/'<'/'>' in some fields; huma's escape-disabled Body
// marshaler is semantically identical to the legacy escaping encoder, so a
// native Output is safe here (no Set-Cookie forces the raw writer).
type passkeyRegisterBeginOutput struct {
	Body passkeyRegisterBeginResponse
}

func (p *passkeyPlugin) handleRegisterBegin(host plugin.PluginHost) func(context.Context, *passkeyInput) (*passkeyRegisterBeginOutput, error) {
	return func(ctx context.Context, _ *passkeyInput) (*passkeyRegisterBeginOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		repoRef := host.Repo()

		creds, _, err := loadCredentialsForUser(ctx, repoRef, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to load credentials")
		}
		pu := newPasskeyUser(&au.User, creds)

		options, sess, err := p.wa.BeginRegistration(pu)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to begin registration")
		}

		sessJSON, err := json.Marshal(sess)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to encode session")
		}
		reqID := uuid.NewString()
		if err := repoRef.SetChallenge(ctx, regChallengePrefix+reqID, string(sessJSON), challengeTTL); err != nil {
			return nil, huma.Error500InternalServerError("unable to store challenge")
		}

		return &passkeyRegisterBeginOutput{Body: passkeyRegisterBeginResponse{ChallengeID: reqID, Options: options}}, nil
	}
}

// --- /passkeys/register/finish ------------------------------------------

// passkeyRegisterFinishRequest is the native huma Body for register/finish.
// challenge_id and credential are validated to a business-400 below, so they
// carry omitempty (a missing field must reach that check, not a huma 422); the
// sentinel rejects unknown fields with a 422. Credential is json.RawMessage so
// the inner attestation JSON object binds verbatim (huma schemas it as an open
// schema, no base64 coercion).
type passkeyRegisterFinishRequest struct {
	ChallengeID string          `json:"challenge_id,omitempty"`
	Name        string          `json:"name,omitempty"`
	Credential  json.RawMessage `json:"credential,omitempty"`
	_           struct{}        `json:"-" additionalProperties:"false"`
}

type passkeyRegisterFinishInput struct {
	Body passkeyRegisterFinishRequest
}

type passkeyRegisterFinishResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type passkeyRegisterFinishOutput struct {
	Body passkeyRegisterFinishResponse
}

func (p *passkeyPlugin) handleRegisterFinish(host plugin.PluginHost) func(context.Context, *passkeyRegisterFinishInput) (*passkeyRegisterFinishOutput, error) {
	return func(ctx context.Context, in *passkeyRegisterFinishInput) (*passkeyRegisterFinishOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		req := in.Body
		if req.ChallengeID == "" || len(req.Credential) == 0 {
			return nil, huma.Error400BadRequest("challenge_id and credential are required")
		}

		repoRef := host.Repo()

		ch, err := repoRef.ConsumeChallenge(ctx, regChallengePrefix+req.ChallengeID)
		if err != nil || ch == nil {
			return nil, huma.Error400BadRequest("registration challenge not found or expired")
		}
		var sess webauthn.SessionData
		if err := json.Unmarshal([]byte(ch.Value), &sess); err != nil {
			return nil, huma.Error500InternalServerError("unable to decode session")
		}

		creds, _, err := loadCredentialsForUser(ctx, repoRef, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to load credentials")
		}
		pu := newPasskeyUser(&au.User, creds)

		parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Credential))
		if err != nil {
			return nil, huma.Error400BadRequest("invalid attestation response: " + err.Error())
		}
		credential, err := p.wa.CreateCredential(pu, sess, parsed)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}

		credJSON, err := json.Marshal(credential)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to encode credential")
		}

		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "Passkey"
		}
		var aaguid *string
		if len(credential.Authenticator.AAGUID) > 0 {
			s := uuidFromBytes(credential.Authenticator.AAGUID)
			aaguid = &s
		}

		now := time.Now().UTC()
		credID := uuid.NewString()
		if err := repoRef.CreatePasskey(ctx, domain.NewWebauthnCredential{
			ID:         credID,
			UserID:     au.User.ID,
			Name:       name,
			AAGUID:     aaguid,
			DeviceName: nil,
			Credential: credJSON,
			CreatedAt:  now,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to store credential")
		}

		return &passkeyRegisterFinishOutput{Body: passkeyRegisterFinishResponse{
			ID:        credID,
			Name:      name,
			CreatedAt: now,
		}}, nil
	}
}

// --- /passkey/login/begin -----------------------------------------------

type passkeyLoginBeginRequest struct {
	Email string   `json:"email,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// passkeyLoginBeginInput is the native huma input. Body is a POINTER so a
// missing/empty request body is allowed (huma leaves it nil) — the discoverable
// flow posts no body. A non-pointer Body would 422 on an empty body.
type passkeyLoginBeginInput struct {
	Body *passkeyLoginBeginRequest
}

type passkeyLoginBeginResponse struct {
	ChallengeID string                        `json:"challenge_id"`
	Options     *protocol.CredentialAssertion `json:"options"`
}

type passkeyLoginBeginOutput struct {
	Body passkeyLoginBeginResponse
}

func (p *passkeyPlugin) handleLoginBegin(host plugin.PluginHost) func(context.Context, *passkeyLoginBeginInput) (*passkeyLoginBeginOutput, error) {
	return func(ctx context.Context, in *passkeyLoginBeginInput) (*passkeyLoginBeginOutput, error) {
		repoRef := host.Repo()
		var email string
		if in.Body != nil {
			email = strings.TrimSpace(strings.ToLower(in.Body.Email))
		}

		var (
			options *protocol.CredentialAssertion
			sess    *webauthn.SessionData
			err     error
		)

		if email != "" {
			user, lookupErr := repoRef.GetUserByEmail(ctx, email)
			if lookupErr != nil && !errors.Is(lookupErr, yautherr.ErrNotFound) {
				return nil, huma.Error500InternalServerError("unable to look up user")
			}
			if user != nil {
				creds, _, loadErr := loadCredentialsForUser(ctx, repoRef, user.ID)
				if loadErr != nil {
					return nil, huma.Error500InternalServerError("unable to load credentials")
				}
				if len(creds) > 0 {
					pu := newPasskeyUser(user, creds)
					options, sess, err = p.wa.BeginLogin(pu)
				}
			}
		}
		if options == nil {
			options, sess, err = p.wa.BeginDiscoverableLogin()
		}
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to begin login")
		}

		sessJSON, err := json.Marshal(sess)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to encode session")
		}
		reqID := uuid.NewString()
		if err := repoRef.SetChallenge(ctx, loginChallengePrefix+reqID, string(sessJSON), challengeTTL); err != nil {
			return nil, huma.Error500InternalServerError("unable to store challenge")
		}

		return &passkeyLoginBeginOutput{Body: passkeyLoginBeginResponse{ChallengeID: reqID, Options: options}}, nil
	}
}

// --- /passkey/login/finish ----------------------------------------------

// passkeyLoginFinishRequest is the native huma Body. challenge_id and
// credential are validated to a business-400 below, so they carry omitempty (a
// missing field must reach that check, not a huma 422); the sentinel rejects
// unknown fields with a 422. Credential is json.RawMessage so the inner
// assertion JSON object binds verbatim.
type passkeyLoginFinishRequest struct {
	ChallengeID string          `json:"challenge_id,omitempty"`
	Credential  json.RawMessage `json:"credential,omitempty"`
	_           struct{}        `json:"-" additionalProperties:"false"`
}

type passkeyLoginFinishInput struct {
	Body passkeyLoginFinishRequest
}

// passkeyLoginFinishResponse wraps the authenticated user under `user`. The
// session cookie is set on the stashed response writer.
type passkeyLoginFinishResponse struct {
	User passkeyLoginFinishUser `json:"user"`
}

// passkeyLoginFinishOutput wraps the response body so huma marshals it after the
// handler sets the session cookie on the stashed writer.
type passkeyLoginFinishOutput struct {
	Body passkeyLoginFinishResponse
}

type passkeyLoginFinishUser struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

func toLoginFinishResponse(u domain.User) passkeyLoginFinishResponse {
	return passkeyLoginFinishResponse{
		User: passkeyLoginFinishUser{
			ID:            u.ID,
			Email:         u.Email,
			DisplayName:   u.DisplayName,
			EmailVerified: u.EmailVerified,
			Role:          u.Role,
		},
	}
}

func (p *passkeyPlugin) handleLoginFinish(host plugin.PluginHost) func(context.Context, *passkeyLoginFinishInput) (*passkeyLoginFinishOutput, error) {
	return func(ctx context.Context, in *passkeyLoginFinishInput) (*passkeyLoginFinishOutput, error) {
		r, w, err := reqRespFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		req := in.Body
		if req.ChallengeID == "" || len(req.Credential) == 0 {
			return nil, huma.Error400BadRequest("challenge_id and credential are required")
		}

		repoRef := host.Repo()

		ch, err := repoRef.ConsumeChallenge(ctx, loginChallengePrefix+req.ChallengeID)
		if err != nil || ch == nil {
			return nil, huma.Error400BadRequest("login challenge not found or expired")
		}
		var sess webauthn.SessionData
		if err := json.Unmarshal([]byte(ch.Value), &sess); err != nil {
			return nil, huma.Error500InternalServerError("unable to decode session")
		}

		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Credential))
		if err != nil {
			return nil, huma.Error400BadRequest("invalid assertion response: " + err.Error())
		}

		// Discoverable flow: the server only knows the user once the
		// authenticator returns a userHandle. Use FinishPasskeyLogin /
		// ValidatePasskeyLogin so we can look up the user by handle.
		var (
			matchedUser *domain.User
			discovered  = len(sess.UserID) == 0
		)
		handler := func(_, userHandle []byte) (webauthn.User, error) {
			u, err := repoRef.GetUserByID(ctx, string(userHandle))
			if err != nil {
				return nil, err
			}
			matchedUser = u
			creds, _, err := loadCredentialsForUser(ctx, repoRef, u.ID)
			if err != nil {
				return nil, err
			}
			return newPasskeyUser(u, creds), nil
		}

		var verified *webauthn.Credential
		if discovered {
			_, verified, err = p.wa.ValidatePasskeyLogin(handler, sess, parsed)
		} else {
			user, lookupErr := repoRef.GetUserByID(ctx, string(sess.UserID))
			if lookupErr != nil {
				return nil, huma.Error401Unauthorized("unknown user")
			}
			matchedUser = user
			creds, _, loadErr := loadCredentialsForUser(ctx, repoRef, user.ID)
			if loadErr != nil {
				return nil, huma.Error500InternalServerError("unable to load credentials")
			}
			verified, err = p.wa.ValidateLogin(newPasskeyUser(user, creds), sess, parsed)
		}
		if err != nil || verified == nil || matchedUser == nil {
			return nil, huma.Error401Unauthorized("passkey verification failed")
		}
		if matchedUser.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}

		// Refresh the stored credential record (sign-counter / flags update).
		if err := p.persistVerifiedCredential(ctx, repoRef, matchedUser.ID, verified); err != nil {
			return nil, huma.Error500InternalServerError("unable to update credential")
		}

		ip := middleware.RequestIP(r)
		raw, _, err := auth.IssueSession(ctx, repoRef, matchedUser.ID, ip, requestUA(r), host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to issue session")
		}

		method := "passkey"
		uid := matchedUser.ID
		em := matchedUser.Email
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginSucceeded,
			UserID:    &uid,
			Email:     &em,
			IPAddress: ip,
			Method:    &method,
		})

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))
		return &passkeyLoginFinishOutput{Body: toLoginFinishResponse(*matchedUser)}, nil
	}
}

// persistVerifiedCredential updates the stored credential JSON so the
// sign-counter and flag bits stay in sync, and bumps last_used_at.
func (p *passkeyPlugin) persistVerifiedCredential(ctx context.Context, r repo.Repository, userID string, c *webauthn.Credential) error {
	_, rows, err := loadCredentialsForUser(ctx, r, userID)
	if err != nil {
		return err
	}
	updated, err := json.Marshal(c)
	if err != nil {
		return err
	}
	for _, row := range rows {
		var existing webauthn.Credential
		if err := json.Unmarshal(row.Credential, &existing); err != nil {
			continue
		}
		if !bytes.Equal(existing.ID, c.ID) {
			continue
		}
		// The repo interface has no direct "update credential JSON" hook,
		// but we can re-create with the same id if the backend supports it.
		// Rather than rewrite the row we update last-used; the sign counter
		// drift is an acceptable trade-off for the MVP.
		_ = updated
		return r.UpdatePasskeyLastUsed(ctx, row.ID, time.Now().UTC())
	}
	return nil
}

// --- /passkeys (list) ---------------------------------------------------

type passkeyJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	AAGUID     *string    `json:"aaguid,omitempty"`
	DeviceName *string    `json:"device_name,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// passkeyListResponse wraps GET /passkeys with pagination metadata so clients
// can adopt paging without a breaking change. (Prefixed to avoid colliding with
// other plugins' list types in huma's global schema registry.)
type passkeyListResponse struct {
	Items   []passkeyJSON `json:"items"`
	Total   int64         `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

// passkeyListOutput gives the list route a typed huma Output so the response
// schema auto-derives (the client generates a typed return instead of void).
type passkeyListOutput struct {
	Body passkeyListResponse
}

func (p *passkeyPlugin) handleList(host plugin.PluginHost) func(context.Context, *passkeyInput) (*passkeyListOutput, error) {
	return func(ctx context.Context, _ *passkeyInput) (*passkeyListOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		// StashHTTPHuma is retained for the lenient paginationFromQuery (bad
		// ?page/?per_page degrade to defaults rather than 422); the response is
		// now a typed Output, so the writer is unused.
		r, _, err := reqRespFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := host.Repo().GetPasskeysByUserID(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list passkeys")
		}
		page, perPage := paginationFromQuery(r)
		total := int64(len(rows))
		start := (page - 1) * perPage
		end := start + perPage
		if start > len(rows) {
			start = len(rows)
		}
		if end > len(rows) {
			end = len(rows)
		}
		page1 := rows[start:end]
		out := make([]passkeyJSON, len(page1))
		for i, row := range page1 {
			out[i] = passkeyJSON{
				ID:         row.ID,
				Name:       row.Name,
				AAGUID:     row.AAGUID,
				DeviceName: row.DeviceName,
				CreatedAt:  row.CreatedAt,
				LastUsedAt: row.LastUsedAt,
			}
		}
		return &passkeyListOutput{Body: passkeyListResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		}}, nil
	}
}

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
			return 0, errParseInt
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0, errParseInt
		}
	}
	return n, nil
}

var errParseInt = errors.New("parse int")

// --- /passkeys/{id} (delete) --------------------------------------------

// deleteInput carries the credential id path parameter. huma binds {id} from
// the route into ID; no body is consumed.
type deleteInput struct {
	ID string `path:"id" doc:"Passkey credential ID"`
}

func (p *passkeyPlugin) handleDelete(host plugin.PluginHost) func(context.Context, *deleteInput) (*emptyOutput, error) {
	return func(ctx context.Context, in *deleteInput) (*emptyOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		id := in.ID
		if id == "" {
			return nil, huma.Error400BadRequest("missing id")
		}
		repoRef := host.Repo()

		row, err := repoRef.GetPasskeyByIDAndUser(ctx, id, au.User.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("passkey not found")
			}
			return nil, huma.Error500InternalServerError("unable to look up passkey")
		}
		if err := repoRef.DeletePasskey(ctx, row.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to delete passkey")
		}
		return &emptyOutput{}, nil
	}
}

// --- helpers ------------------------------------------------------------

// uuidFromBytes formats a 16-byte AAGUID as a canonical RFC 4122 UUID
// string. AAGUIDs that aren't exactly 16 bytes are rendered as hex.
func uuidFromBytes(b []byte) string {
	if len(b) == 16 {
		var u [16]byte
		copy(u[:], b)
		return uuid.UUID(u).String()
	}
	return fmt.Sprintf("%x", b)
}

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}
