package oauth_test

// link_principal_test.go — POST /oauth/{provider}/link is the route that
// starts attaching a social identity to a person's account, and it is gated by
// middleware.RequireAuthHuma ALONE.
//
// Every other authed oauth route goes through authedGuards (handlers.go),
// which composes RequireAuthHuma with RequireUserPrincipalHuma, and the comment
// there says why: "Linking/unlinking a social identity acts on the caller's own
// account; a service account resolves to the human who minted its key and must
// not rewrite that person's sign-in methods." /link opted out of that chain
// when it moved to a native typed Body — it needs neither the stashed request
// nor the writer — and dropped the principal check along with the bridge.
//
// An org-scoped API key resolves, via plugins/apikey/resolver.go, to an
// AuthUser whose User is the whole row of the human who minted it and whose
// Principal is a SERVICE ACCOUNT. RequireAuthHuma is satisfied by that, so the
// machine credential reaches the handler, is treated as the human, and gets a
// live OAuth state row minted against the human's user ID — the first half of
// attaching an attacker-controlled social identity to that account. The second
// leg (completeLink) does 401 without a session, so this is not a takeover
// today; it is the entry point declining to say no, and the refusal belongs
// where the other three routes put it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/oauth"
)

// mintKey writes an API key row directly (the organizations/apikey handlers
// are not mounted on this stack) and returns the plaintext credential. orgID
// empty mints a USER-scoped key; non-empty mints an ORG-scoped one, which is
// what the resolver turns into a service-account principal.
func mintKey(t *testing.T, s *stack, id, orgID, creatorID string) string {
	t.Helper()
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	in := domain.NewAPIKey{
		ID: id, KeyPrefix: gen.Prefix, KeyHash: gen.Hash, Name: id,
		Scopes: json.RawMessage(`[]`), CreatedAt: time.Now().UTC(),
		CreatedByUserID: creatorID,
	}
	if orgID != "" {
		o := orgID
		in.OrganizationID = &o
	} else {
		u := creatorID
		in.UserID = &u
	}
	if err := s.repo.CreateAPIKey(context.Background(), in); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return gen.Plaintext
}

// linkWithKey POSTs /oauth/fake/link authenticated by X-Api-Key only (no
// cookie jar), and returns the status plus the auth_url when there is one.
func linkWithKey(t *testing.T, s *stack, key string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/oauth/fake/link",
		strings.NewReader(`{"redirect_url":"/after-link"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", key)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	defer res.Body.Close()
	var body struct {
		AuthURL string `json:"auth_url"`
	}
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body.AuthURL
}

// seedOrgKeyFixture registers alice, gives her an org, and returns her user ID
// and the org ID.
func seedOrgKeyFixture(t *testing.T, s *stack) (aliceID, orgID string) {
	t.Helper()
	alice := registerLocalUser(t, s, "alice@corp.example")
	ctx := context.Background()
	now := time.Now().UTC()
	org, err := s.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: "org-ci", Name: "CI Org", Slug: "ci-org", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if _, err := s.repo.CreateMembership(ctx, domain.NewMembership{
		OwnerRoleAuthorized: true, // fixture seeds the owner directly
		ID:                  "m-org-ci", OrganizationID: org.ID, UserID: alice.ID,
		Role: "owner", Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateMembership: %v", err)
	}
	return alice.ID, org.ID
}

// TestOAuthLink_RefusesServiceAccount: the org's CI key must not be able to
// start attaching a social identity to the human who minted it. The assertion
// is the persisted state row, not just the status — a 403 that still wrote a
// live state bound to alice would be no refusal at all.
func TestOAuthLink_RefusesServiceAccount(t *testing.T) {
	s := newStack(t, oauth.UserInfo{
		ProviderUserID: "link-remote", Email: "alice@corp.example", EmailVerified: true,
	})
	aliceID, orgID := seedOrgKeyFixture(t, s)
	orgKey := mintKey(t, s, "k-org-ci", orgID, aliceID)

	status, authURL := linkWithKey(t, s, orgKey)

	// State first: a 403 that still minted a live link-mode row would be no
	// refusal at all, and it is the durable artefact.
	assertNoLinkState(t, s, authURL, aliceID)
	if authURL != "" {
		t.Errorf("service-account /link handed back an authorization URL: %s", authURL)
	}
	if status != http.StatusForbidden {
		t.Fatalf("service-account /link: expected 403, got %d", status)
	}
}

// assertNoLinkState fails if the call left a consumable link-mode state row
// behind — the durable artefact a refusal must not create.
func assertNoLinkState(t *testing.T, s *stack, authURL, userID string) {
	t.Helper()
	if authURL == "" {
		return
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth_url: %v", err)
	}
	tok := u.Query().Get("state")
	if tok == "" {
		return
	}
	st, err := s.repo.ConsumeOAuthState(context.Background(), tok)
	if err == nil && st != nil && st.RedirectURL != nil && strings.Contains(*st.RedirectURL, userID) {
		t.Fatalf("refused /link still persisted a link-mode state row for %s: %q", userID, *st.RedirectURL)
	}
}

// Positive controls. The cheap wrong fix is "refuse every X-Api-Key on /link",
// which would break the user-scoped key that exists precisely to act for its
// owner, and the cheaper one is "refuse everything", which breaks the browser
// flow the route was written for.
func TestOAuthLink_HumanAndUserScopedKeyStillLink(t *testing.T) {
	t.Run("session_cookie", func(t *testing.T) {
		s := newStack(t, oauth.UserInfo{
			ProviderUserID: "link-remote-2", Email: "human@corp.example", EmailVerified: true,
		})
		registerAndLogin(t, s, "human@corp.example")
		res := postLink(t, s, []byte(`{"redirect_url":"/after-link"}`))
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("human /link: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
		}
	})

	t.Run("user_scoped_key", func(t *testing.T) {
		s := newStack(t, oauth.UserInfo{
			ProviderUserID: "link-remote-3", Email: "alice@corp.example", EmailVerified: true,
		})
		aliceID, _ := seedOrgKeyFixture(t, s)
		userKey := mintKey(t, s, "k-alice-cli", "", aliceID)

		status, authURL := linkWithKey(t, s, userKey)
		if status != http.StatusOK {
			t.Fatalf("user-scoped key /link: expected 200, got %d", status)
		}
		if authURL == "" {
			t.Fatalf("user-scoped key /link returned no auth_url")
		}
	})
}
