package oauth2server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugin"
)

// backchannelLogoutEvent is the OIDC Back-Channel Logout 1.0 event identifier
// that MUST appear (as a key with an empty-object value) in the logout_token's
// `events` claim.
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// bclDeliveryHook, when non-nil, is invoked after each back-channel logout
// delivery attempt. Test-only; nil in production.
var bclDeliveryHook func(clientID string, statusCode int, err error)

// bclEventHandler turns offboarding events into OIDC Back-Channel Logout
// notifications. When a user is suspended or banned, every RP the user
// authorized that registered a backchannel_logout_uri is sent a signed
// logout_token so it can terminate its own session for that user — closing the
// "RP validates the access token locally" gap in instant termination.
//
// We deliberately do NOT fan out on a routine EventLogout: our logout_token is
// sub-only (no sid), which instructs the RP to kill ALL of the user's sessions.
// That is the correct intent for offboarding (suspend/ban/SCIM-deprovision) but
// wrong for a single-device logout, which would then force-log-out the user's
// other devices. RP-Initiated Logout (end_session) and Back-Channel Logout are
// separate specs; we keep them decoupled until per-session sid tracking exists.
type bclEventHandler struct {
	p    *oauth2Plugin
	host plugin.PluginHost
}

func (h *bclEventHandler) Handle(ctx context.Context, e events.AuthEvent) (events.Decision, error) {
	switch e.Type {
	case events.EventUserBanned, events.EventUserSuspended:
		if e.UserID != nil && *e.UserID != "" {
			h.p.fanOutBackchannelLogout(h.host, *e.UserID)
		}
	}
	return events.Continue(), nil
}

// bclHTTPClient delivers logout_tokens. It does NOT follow redirects: a
// compromised/misconfigured RP must not be able to 302 the logout_token POST
// toward an internal address (SSRF defense-in-depth).
var bclHTTPClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// fanOutBackchannelLogout sends a logout_token to every RP the user authorized
// (per stored consents) that registered a back-channel logout endpoint.
// Delivery is asynchronous and best-effort: each RP is notified in its own
// goroutine with a bounded timeout, so a slow/unreachable RP never blocks the
// triggering request, and one failure does not affect the others.
func (p *oauth2Plugin) fanOutBackchannelLogout(host plugin.PluginHost, userID string) {
	// Detach from the request context: deliveries outlive the request that
	// triggered them.
	ctx := context.Background()

	consents, err := host.Repo().ListConsentsByUserID(ctx, userID)
	if err != nil {
		return
	}
	seen := make(map[string]bool, len(consents))
	for _, c := range consents {
		if seen[c.ClientID] {
			continue
		}
		seen[c.ClientID] = true

		client, err := host.Repo().GetOAuth2ClientByClientID(ctx, c.ClientID)
		if err != nil || client == nil {
			continue
		}
		if client.BackchannelLogoutURI == nil || *client.BackchannelLogoutURI == "" {
			continue
		}
		token, err := p.signLogoutToken(host, client.ClientID, userID)
		if err != nil {
			continue
		}
		uri := *client.BackchannelLogoutURI
		clientID := client.ClientID
		go p.deliverLogoutToken(uri, clientID, token)
	}
}

// signLogoutToken builds and signs an OIDC Back-Channel Logout 1.0 logout_token
// for (audience=client_id, sub=userID). Per §2.4 it carries the backchannel
// event and a jti, and — critically — MUST NOT carry a nonce. We send a
// sub-only token (no sid), which instructs the RP to terminate all of the
// user's sessions; yauth-go does not yet track per-RP session ids.
func (p *oauth2Plugin) signLogoutToken(host plugin.PluginHost, audience, userID string) (string, error) {
	now := time.Now().UTC()
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": p.cfg.Issuer,
		"aud": audience,
		"sub": userID,
		"iat": now.Unix(),
		"jti": jti,
		// This was the only token yauth minted with no exp, and it is handed
		// to every RP the user ever authorized that registered a
		// backchannel_logout_uri — including one that registered itself
		// through anonymous DCR. Without an exp it is a permanent signed
		// assertion naming one of our users, held by parties we have no
		// relationship with. A logout token is consumed within seconds of
		// delivery, so two minutes is generous; it is set in the shared claims
		// map so both the asymmetric signer and the HS256 fallback below carry
		// it. Signer.Verify now requires exp, and this is the token that check
		// would otherwise have rejected.
		"exp": now.Add(2 * time.Minute).Unix(),
		"events": map[string]any{
			backchannelLogoutEvent: map[string]any{},
		},
	}
	if signer := host.JWTSigner(); signer != nil {
		return signer.Sign(claims)
	}
	secret := host.JWTSecret()
	if len(secret) == 0 {
		return "", errors.New("logout_token requires a JWT signer or HS256 secret")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString(secret)
}

// deliverLogoutToken POSTs the logout_token to the RP's back-channel logout
// endpoint as application/x-www-form-urlencoded (OIDC BCL §2.5). Best-effort.
func (p *oauth2Plugin) deliverLogoutToken(endpoint, clientID, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.BackchannelLogoutTimeout)
	defer cancel()

	form := url.Values{}
	form.Set("logout_token", token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		if bclDeliveryHook != nil {
			bclDeliveryHook(clientID, 0, err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := bclHTTPClient.Do(req)
	if err != nil {
		if bclDeliveryHook != nil {
			bclDeliveryHook(clientID, 0, err)
		}
		return
	}
	defer resp.Body.Close()
	if bclDeliveryHook != nil {
		bclDeliveryHook(clientID, resp.StatusCode, nil)
	}
}
