package oauth_test

// On a first login with no existing link, the callback adopts an existing
// account whose email matches — which makes the provider's word on that
// address the whole authentication. An IdP that permits self-signup with an
// unverified address then hands an attacker the victim's account, so the
// adoption branch now requires info.EmailVerified. Creating a NEW user from
// an unverified address takes over nothing and is unchanged.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/plugins/oauth"
	"github.com/yackey-labs/yauth/yautherr"
)

// TestOAuthCallback_RefusesUnverifiedEmailAdoption is the takeover scenario:
// the attacker registers the victim's address at an IdP that does not verify
// addresses. Refusing means 403, no cookie, no session row, and no link
// written that a later login could ride in on.
func TestOAuthCallback_RefusesUnverifiedEmailAdoption(t *testing.T) {
	const victimEmail = "victim@corp.example"
	const providerUserID = "attacker-1"

	s := newStack(t, oauth.UserInfo{
		ProviderUserID: providerUserID,
		Email:          victimEmail,
		EmailVerified:  false,
	})
	ctx := context.Background()

	// The victim already has a password account here.
	body := strings.NewReader(`{"email":"` + victimEmail + `","password":"correct horse battery staple"}`)
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	rres, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	rres.Body.Close()
	if rres.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", rres.StatusCode)
	}
	logoutReq, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/logout", nil)
	lres, err := s.client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	lres.Body.Close()

	victim, err := s.repo.GetUserByEmail(ctx, victimEmail)
	if err != nil || victim == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if _, err := s.repo.DeleteUserSessions(ctx, victim.ID); err != nil {
		t.Fatalf("clear sessions: %v", err)
	}

	cbURL, _ := followAuthorizeAndExtractCallback(t, s, "")
	res, err := s.client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", res.StatusCode, drainBody(res))
	}
	assertNoSession(t, s, res, victim.ID)

	// No link was written, so a later login cannot inherit one.
	if acct, err := s.repo.GetOAuthAccountByProviderAndProviderUserID(ctx, "fake", providerUserID); err == nil && acct != nil {
		t.Fatalf("refused adoption still linked the provider account: %+v", acct)
	} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("GetOAuthAccountByProviderAndProviderUserID: %v", err)
	}

	// And the client is still anonymous.
	sres, err := s.client.Get(s.srv.URL + "/api/auth/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	sres.Body.Close()
	if sres.StatusCode == http.StatusOK {
		t.Fatalf("session: expected the client to remain anonymous, got 200")
	}
}

// TestOAuthCallback_UnverifiedEmailStillCreatesNewUser pins the branch that
// was deliberately left alone: an unverified address takes over nothing when
// no account exists, so registration still works — and the address lands
// unverified.
func TestOAuthCallback_UnverifiedEmailStillCreatesNewUser(t *testing.T) {
	s := newStack(t, oauth.UserInfo{
		ProviderUserID: "remote-new",
		Email:          "ivy@example.com",
		EmailVerified:  false,
	})

	cbURL, _ := followAuthorizeAndExtractCallback(t, s, "")
	res, err := s.client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}

	sres, err := s.client.Get(s.srv.URL + "/api/auth/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sres.Body.Close()
	if sres.StatusCode != http.StatusOK {
		t.Fatalf("session: expected 200, got %d", sres.StatusCode)
	}
	var sess struct {
		User struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"user"`
	}
	_ = json.NewDecoder(sres.Body).Decode(&sess)
	if sess.User.Email != "ivy@example.com" {
		t.Fatalf("session email: %q", sess.User.Email)
	}
	if sess.User.EmailVerified {
		t.Errorf("an unverified provider address must not land as email_verified=true")
	}
}
