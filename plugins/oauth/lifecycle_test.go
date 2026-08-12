package oauth_test

// The OAuth callback gated the resolved user on user.Banned alone, so
// suspension — the documented offboarding kill switch — did not hold on this
// path: an offboarded employee could sign back in through Google. The gate
// now lives in plugin.RunFederatedLogin, shared with the two SSO plugins;
// these drive it through the real callback.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/oauth"
)

// assertNoSession asserts the refusal end to end: no session cookie came
// back, and no session row exists for the user. DeleteUserSessions returns
// the number of rows it removed, so a non-zero count is a session that was
// issued despite the refusal.
func assertNoSession(t *testing.T, s *stack, res *http.Response, userID string) {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			t.Fatalf("refused login still set a session cookie")
		}
	}
	n, err := s.repo.DeleteUserSessions(context.Background(), userID)
	if err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}
	if n != 0 {
		t.Fatalf("refused login left %d session row(s) behind", n)
	}
}

// TestOAuthCallback_RefusesLifecycleStates drives the real callback for an
// account already linked to the provider that may no longer authenticate.
func TestOAuthCallback_RefusesLifecycleStates(t *testing.T) {
	suspendedAt := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)

	cases := []struct {
		name  string
		apply func(*domain.NewUser)
	}{
		{"suspended", func(u *domain.NewUser) { u.SuspendedAt = &suspendedAt }},
		{"staged", func(u *domain.NewUser) { u.ActivatesAt = &future }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const providerUserID = "remote-offboarded"
			s := newStack(t, oauth.UserInfo{
				ProviderUserID: providerUserID,
				Email:          "hank@example.com",
				EmailVerified:  true,
			})
			ctx := context.Background()
			now := time.Now().UTC()

			nu := domain.NewUser{
				ID:            uuid.NewString(),
				Email:         "hank@example.com",
				EmailVerified: true,
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			tc.apply(&nu)
			u, err := s.repo.CreateUser(ctx, nu)
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := s.repo.CreateOAuthAccount(ctx, domain.NewOAuthAccount{
				ID:             uuid.NewString(),
				UserID:         u.ID,
				Provider:       "fake",
				ProviderUserID: providerUserID,
				CreatedAt:      now,
				UpdatedAt:      now,
			}); err != nil {
				t.Fatalf("CreateOAuthAccount: %v", err)
			}

			cbURL, _ := followAuthorizeAndExtractCallback(t, s, "")
			res, err := s.client.Get(cbURL)
			if err != nil {
				t.Fatalf("callback: %v", err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("%s account: expected 403, got %d (%s)", tc.name, res.StatusCode, drainBody(res))
			}
			assertNoSession(t, s, res, u.ID)
		})
	}
}
