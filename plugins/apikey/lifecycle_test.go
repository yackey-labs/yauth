package apikey

// Account-lifecycle cover for the X-Api-Key resolver. The resolver checked
// user.Banned only, so POST /admin/users/{id}/suspend — which deletes every
// session and revokes every refresh token — left the offboarded user's
// personal API key authenticating indefinitely. domain.User.CanAuthenticate
// is the predicate the cookie middleware and the bearer resolver already
// apply; this file pins it here too, and pins the deliberate exception for
// org-scoped (service-account) keys.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// TestResolver_LifecycleStates_RecognizedUnauthorized asserts the refusal
// itself: no AuthUser is resolved, so no request can proceed on the key. A
// merely different error message would be no defence.
func TestResolver_LifecycleStates_RecognizedUnauthorized(t *testing.T) {
	suspendedAt := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)

	cases := []struct {
		name  string
		apply func(u *domain.User)
	}{
		{"suspended", func(u *domain.User) { u.SuspendedAt = &suspendedAt }},
		{"staged", func(u *domain.User) { u.ActivatesAt = &future }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, h, user, gen, _ := seededFixture(t)
			tc.apply(&user)
			r.putUser(user)

			res := newResolver(h, "yak")
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(headerName, gen.Plaintext)
			au, recognized, err := res.Resolve(req)
			if au != nil {
				t.Fatalf("%s user resolved an AuthUser: %+v", tc.name, au)
			}
			if !recognized {
				t.Fatalf("want recognized=true so the resolver chain short-circuits, got false")
			}
			if !errors.Is(err, yautherr.ErrUnauthorized) {
				t.Errorf("want ErrUnauthorized, got %v", err)
			}
		})
	}
}

// TestResolver_OrgScopedKey_SuspendedCreator_StillAuthenticates pins the
// deliberate asymmetry in the branch above the user-scoped path: an
// org-scoped key belongs to the ORGANIZATION, not to the human who minted
// it, so offboarding that human must not silently break the org's CI
// runner. Retiring a service account is done by deleting or expiring the
// key.
func TestResolver_OrgScopedKey_SuspendedCreator_StillAuthenticates(t *testing.T) {
	r := newFakeRepo()
	h := newFakeHost(r)
	suspendedAt := time.Now().UTC().Add(-time.Hour)
	creator := domain.User{
		ID:          uuid.NewString(),
		Email:       "admin@example.com",
		Role:        "user",
		SuspendedAt: &suspendedAt,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	r.putUser(creator)
	gen := mustGenerateKey(t)
	orgID := uuid.NewString()
	r.putKey(domain.APIKey{
		ID:              uuid.NewString(),
		OrganizationID:  &orgID,
		KeyPrefix:       gen.Prefix,
		KeyHash:         gen.Hash,
		Name:            "ci-runner",
		Scopes:          []byte("[]"),
		CreatedAt:       time.Now().UTC(),
		CreatedByUserID: creator.ID,
	})

	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, gen.Plaintext)
	au, recognized, err := res.Resolve(req)
	if err != nil || !recognized || au == nil {
		t.Fatalf("org key must survive a suspended creator; got au=%v recognized=%v err=%v", au, recognized, err)
	}
	if !au.Principal.IsServiceAccount() {
		t.Errorf("want ServiceAccount principal; got %+v", au.Principal)
	}
}
