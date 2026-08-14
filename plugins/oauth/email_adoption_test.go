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

	"github.com/yackey-labs/yauth/domain"
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
	if rres.StatusCode != http.StatusOK {
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

// --- the same gate, one byte off -----------------------------------------
//
// The adoption gate above only runs when GetUserByEmail actually FINDS the
// local account, and completeLogin looks it up with the provider's string
// verbatim: `repoRef.GetUserByEmail(ctx, info.Email)`, then stores
// `Email: info.Email` verbatim on the CreateUser branch. Nothing folds case on
// the way in — providers/oidc.go only TrimSpaces the claim and
// providers/google.go does not touch it — while every password path lowercases
// (plugins/emailpassword/handlers.go). memrepo's emailIdx and the Postgres
// UNIQUE column are both byte-exact.
//
// So an IdP that returns "Alice@corp.example" for the mailbox stored locally as
// "alice@corp.example" misses the lookup entirely: the flow never reaches the
// adoption gate, falls into the CreateUser branch, and the deployment ends up
// with a SECOND global user row for the same mailbox — carrying whatever
// email_verified the claim asserted, and owning the OAuth link. The sibling RPs
// already fold at the consumption point (plugins/ssosaml/handlers_login.go's
// assertedEmail, and ssooidc); plugins/oauth does not.
//
// The two tests below pin both halves of that: the verified case must land on
// the EXISTING account, and the unverified case must land on the adoption
// refusal rather than quietly minting a duplicate.

// countUsers is the assertion that matters here — "one mailbox, one row" — and
// it is repository state, not a status code.
func countUsers(t *testing.T, s *stack) int64 {
	t.Helper()
	_, total, err := s.repo.ListUsers(context.Background(), "", 100, 0)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	return total
}

// registerLocalUser creates the password account the provider claim will
// collide with, and leaves the client anonymous.
func registerLocalUser(t *testing.T, s *stack, email string) *domain.User {
	t.Helper()
	body := strings.NewReader(`{"email":"` + email + `","password":"correct horse battery staple"}`)
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register: %d", res.StatusCode)
	}
	logoutReq, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/auth/logout", nil)
	lres, err := s.client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	lres.Body.Close()

	u, err := s.repo.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail(%q): %v", email, err)
	}
	if _, err := s.repo.DeleteUserSessions(context.Background(), u.ID); err != nil {
		t.Fatalf("clear sessions: %v", err)
	}
	return u
}

// TestOAuthCallback_FoldsProviderEmailBeforeAdoption: the provider asserts a
// verified address that differs only in case from the local account. That is
// the SAME mailbox — the flow must adopt the existing user, not mint a second
// row for it.
func TestOAuthCallback_FoldsProviderEmailBeforeAdoption(t *testing.T) {
	const localEmail = "alice@corp.example"
	const claimedEmail = "Alice@corp.example"

	s := newStack(t, oauth.UserInfo{
		ProviderUserID: "idp-alice",
		Email:          claimedEmail,
		EmailVerified:  true,
	})
	alice := registerLocalUser(t, s, localEmail)
	if before := countUsers(t, s); before != 1 {
		t.Fatalf("fixture: expected 1 user before the callback, got %d", before)
	}

	cbURL, _ := followAuthorizeAndExtractCallback(t, s, "")
	res, err := s.client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: expected 200, got %d (%s)", res.StatusCode, drainBody(res))
	}

	if after := countUsers(t, s); after != 1 {
		t.Fatalf("a case variant of the same mailbox created %d user rows; "+
			"one address must own exactly one account", after)
	}

	// And the session belongs to the pre-existing account, not a fresh one.
	var cb struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.NewDecoder(res.Body).Decode(&cb)
	if cb.User.ID != alice.ID {
		t.Fatalf("callback signed the caller into user %q (%q); the local account is %q (%q)",
			cb.User.ID, cb.User.Email, alice.ID, alice.Email)
	}

	// The OAuth link hangs off the existing user, so the next login lands there
	// too rather than on a shadow account.
	acct, err := s.repo.GetOAuthAccountByProviderAndProviderUserID(context.Background(), "fake", "idp-alice")
	if err != nil || acct == nil {
		t.Fatalf("GetOAuthAccountByProviderAndProviderUserID: %v", err)
	}
	if acct.UserID != alice.ID {
		t.Fatalf("provider link was attached to %q, not the existing account %q", acct.UserID, alice.ID)
	}
}

// TestOAuthCallback_MixedCaseEmailStillHitsTheAdoptionGate is the security
// half: with the claim UNVERIFIED, folding the case is what makes the
// collision visible at all. Today the byte-exact miss routes the request into
// CreateUser, so the refusal added by
// TestOAuthCallback_RefusesUnverifiedEmailAdoption is skipped whenever the IdP
// varies the case — and the deployment silently grows a second row for a
// mailbox someone else already holds.
func TestOAuthCallback_MixedCaseEmailStillHitsTheAdoptionGate(t *testing.T) {
	const localEmail = "bob@corp.example"
	const claimedEmail = "BOB@corp.example"

	s := newStack(t, oauth.UserInfo{
		ProviderUserID: "idp-attacker",
		Email:          claimedEmail,
		EmailVerified:  false,
	})
	bob := registerLocalUser(t, s, localEmail)

	cbURL, _ := followAuthorizeAndExtractCallback(t, s, "")
	res, err := s.client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected the adoption refusal (403), got %d (%s)", res.StatusCode, drainBody(res))
	}
	assertNoSession(t, s, res, bob.ID)

	if after := countUsers(t, s); after != 1 {
		t.Fatalf("refused adoption still left %d user rows for one mailbox", after)
	}
	if acct, err := s.repo.GetOAuthAccountByProviderAndProviderUserID(
		context.Background(), "fake", "idp-attacker"); err == nil && acct != nil {
		t.Fatalf("refused adoption still linked the provider account: %+v", acct)
	} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		t.Fatalf("GetOAuthAccountByProviderAndProviderUserID: %v", err)
	}
}

// Positive control for the folding: an address that collides with NOTHING must
// still register, and a byte-identical match must still adopt — the fix must
// not turn every federated first login into a 403.
func TestOAuthCallback_FoldingKeepsTheOrdinaryPathsWorking(t *testing.T) {
	t.Run("exact_match_still_adopts", func(t *testing.T) {
		s := newStack(t, oauth.UserInfo{
			ProviderUserID: "idp-carol",
			Email:          "carol@corp.example",
			EmailVerified:  true,
		})
		carol := registerLocalUser(t, s, "carol@corp.example")

		cbURL, _ := followAuthorizeAndExtractCallback(t, s, "")
		res, err := s.client.Get(cbURL)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", res.StatusCode, drainBody(res))
		}
		if n := countUsers(t, s); n != 1 {
			t.Fatalf("exact-match adoption created %d rows", n)
		}
		var cb struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		}
		_ = json.NewDecoder(res.Body).Decode(&cb)
		if cb.User.ID != carol.ID {
			t.Fatalf("exact-match adoption signed in %q, want %q", cb.User.ID, carol.ID)
		}
	})

	t.Run("unknown_mixed_case_address_still_registers", func(t *testing.T) {
		s := newStack(t, oauth.UserInfo{
			ProviderUserID: "idp-dave",
			Email:          "Dave@corp.example",
			EmailVerified:  true,
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
		if n := countUsers(t, s); n != 1 {
			t.Fatalf("first federated login created %d user rows", n)
		}
		sres, err := s.client.Get(s.srv.URL + "/api/auth/session")
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		defer sres.Body.Close()
		if sres.StatusCode != http.StatusOK {
			t.Fatalf("session: expected 200, got %d", sres.StatusCode)
		}
	})
}
