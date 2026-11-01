package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/repo"
)

// lostRaceRepo simulates a concurrent poll winning the device_code redemption:
// the first consume attempt is applied by "someone else", so ours loses the
// compare-and-swap and sees ErrNotFound.
type lostRaceRepo struct{ repo.Repository }

func (l lostRaceRepo) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	if status == "consumed" {
		if err := l.Repository.UpdateDeviceCodeStatus(ctx, id, status, userID); err != nil {
			return err
		}
	}
	return l.Repository.UpdateDeviceCodeStatus(ctx, id, status, userID)
}

// TestDeviceCodeGrant_LostRedemptionRace_InvalidGrant: the loser of a
// concurrent redemption gets RFC 8628 invalid_grant, not server_error, and no
// internal error text.
func TestDeviceCodeGrant_LostRedemptionRace_InvalidGrant(t *testing.T) {
	h := newHarnessWrapped(t, func(r repo.Repository) repo.Repository { return lostRaceRepo{r} })
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	body := `{"name":"tv","redirect_uris":[],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scopes":["read"],"is_public":true,"token_endpoint_auth_method":"none"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)

	df := url.Values{}
	df.Set("client_id", clientID)
	df.Set("scope", "read")
	status, da := h.postForm(t, "/api/auth/oauth/device/code", df, "", "")
	if status != http.StatusOK {
		t.Fatalf("device_authorization: %d %v", status, da)
	}
	approval, _ := json.Marshal(map[string]any{"user_code": da["user_code"]})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth/device", strings.NewReader(string(approval)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("device approve: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("device approve status=%d", res.StatusCode)
	}

	pf := url.Values{}
	pf.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	pf.Set("device_code", da["device_code"].(string))
	pf.Set("client_id", clientID)
	status, out := h.postForm(t, "/api/auth/oauth/token", pf, "", "")
	assertNoTokens(t, status, out)
	if d, _ := out["error_description"].(string); strings.Contains(d, "yauth:") {
		t.Errorf("internal error text leaked: %q", d)
	}
}
