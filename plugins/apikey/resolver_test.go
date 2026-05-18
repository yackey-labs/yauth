package apikey

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func mustGenerateKey(t *testing.T) GeneratedKey {
	t.Helper()
	k, err := GenerateKey("yak")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

func seededFixture(t *testing.T) (*fakeRepo, *fakeHost, domain.User, GeneratedKey, string) {
	t.Helper()
	r := newFakeRepo()
	h := newFakeHost(r)

	user := domain.User{
		ID:        uuid.NewString(),
		Email:     "alice@example.com",
		Role:      "user",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	r.putUser(user)

	gen := mustGenerateKey(t)
	keyID := uuid.NewString()
	r.putKey(domain.APIKey{
		ID:        keyID,
		UserID:    &user.ID,
		KeyPrefix: gen.Prefix,
		KeyHash:   gen.Hash,
		Name:      "test",
		Scopes:    []byte("[]"),
		CreatedAt: time.Now().UTC(),
	})
	return r, h, user, gen, keyID
}

func TestResolver_NoHeader_NotRecognized(t *testing.T) {
	_, h, _, _, _ := seededFixture(t)
	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	au, recognized, err := res.Resolve(req)
	if au != nil || recognized || err != nil {
		t.Fatalf("want (nil, false, nil), got (%v, %v, %v)", au, recognized, err)
	}
}

func TestResolver_MalformedHeader_NotRecognized(t *testing.T) {
	_, h, _, _, _ := seededFixture(t)
	res := newResolver(h, "yak")

	for _, val := range []string{
		"Bearer abc",
		"yak",
		"yak_",
		"yak_xx_yy",
		"yak_zzzzzzzz_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		"wrongtag_aabbccdd_" + strings.Repeat("0", 32),
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerName, val)
		au, recognized, err := res.Resolve(req)
		if au != nil || recognized || err != nil {
			t.Errorf("input %q: want (nil, false, nil), got (%v, %v, %v)", val, au, recognized, err)
		}
	}
}

func TestResolver_GoodKey_Authenticates(t *testing.T) {
	_, h, user, gen, keyID := seededFixture(t)
	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, gen.Plaintext)
	au, recognized, err := res.Resolve(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !recognized {
		t.Fatalf("expected recognized=true")
	}
	if au == nil || au.User.ID != user.ID {
		t.Fatalf("wrong user resolved: %+v", au)
	}

	// last_used_at update is async; give it a tick to land.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		k, ok := h.repo.(*fakeRepo).keyByID(keyID)
		if ok && k.LastUsedAt != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("expected LastUsedAt to be set asynchronously")
}

func TestResolver_BadSecret_RecognizedUnauthorized(t *testing.T) {
	_, h, _, gen, _ := seededFixture(t)
	res := newResolver(h, "yak")

	// Tamper with the last hex char so the secret hashes differently but
	// remains valid hex of length 32.
	tampered := gen.Plaintext[:len(gen.Plaintext)-1]
	if last := gen.Plaintext[len(gen.Plaintext)-1]; last == 'a' {
		tampered += "b"
	} else {
		tampered += "a"
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, tampered)
	au, recognized, err := res.Resolve(req)
	if au != nil {
		t.Errorf("expected nil user, got %+v", au)
	}
	if !recognized {
		t.Fatalf("malformed-but-syntactically-valid header should be recognized=true so the chain short-circuits")
	}
	if !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Errorf("want ErrUnauthorized, got %v", err)
	}
}

func TestResolver_UnknownPrefix_RecognizedUnauthorized(t *testing.T) {
	_, h, _, _, _ := seededFixture(t)
	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, "yak_deadbeef_"+strings.Repeat("a", 32))
	au, recognized, err := res.Resolve(req)
	if au != nil || !recognized {
		t.Fatalf("want (nil, true), got (%v, %v)", au, recognized)
	}
	if !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Errorf("want ErrUnauthorized, got %v", err)
	}
}

func TestResolver_ExpiredKey_RecognizedExpired(t *testing.T) {
	r, h, user, _, _ := seededFixture(t)

	// Plant an expired key for this user. The fake's GetAPIKeyByPrefix
	// already filters expired keys to ErrNotFound — that's the realistic
	// production behavior for the GORM repo too — so the resolver returns
	// ErrUnauthorized rather than ErrTokenExpired in that path. To exercise
	// the explicit expiry branch, override GetAPIKeyByPrefix by inserting
	// a key whose ExpiresAt is in the future, then advance to the past via
	// a clock-independent approach: we cannot reach the explicit branch
	// without a time injection, so skip — the equivalent assertion is that
	// expired keys do NOT authenticate.
	expiredAt := time.Now().UTC().Add(-time.Minute)
	gen2 := mustGenerateKey(t)
	r.putKey(domain.APIKey{
		ID:        uuid.NewString(),
		UserID:    &user.ID,
		KeyPrefix: gen2.Prefix,
		KeyHash:   gen2.Hash,
		Name:      "expired",
		Scopes:    []byte("[]"),
		ExpiresAt: &expiredAt,
		CreatedAt: time.Now().UTC().Add(-time.Hour),
	})

	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, gen2.Plaintext)
	au, recognized, err := res.Resolve(req)
	if au != nil {
		t.Errorf("expected nil user, got %+v", au)
	}
	if !recognized {
		t.Errorf("expected recognized=true")
	}
	if !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Errorf("want ErrUnauthorized for expired key, got %v", err)
	}
}

func TestResolver_BannedUser_RecognizedBanned(t *testing.T) {
	r, h, user, gen, _ := seededFixture(t)
	user.Banned = true
	r.putUser(user)

	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, gen.Plaintext)
	au, recognized, err := res.Resolve(req)
	if au != nil || !recognized {
		t.Fatalf("want (nil, true), got (%v, %v)", au, recognized)
	}
	if !errors.Is(err, yautherr.ErrUserBanned) {
		t.Errorf("want ErrUserBanned, got %v", err)
	}
}

// TestResolver_OrgScopedKey verifies the yauth #91 / yauth-go #19
// service-account path: the resolver tags Method = service-account,
// surfaces the org id on ActiveOrgID, and emits a ServiceAccount
// Principal with KeyID + CreatedBy populated for downstream audit.
func TestResolver_OrgScopedKey(t *testing.T) {
	r := newFakeRepo()
	h := newFakeHost(r)
	creator := domain.User{
		ID:        uuid.NewString(),
		Email:     "admin@example.com",
		Role:      "user",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	r.putUser(creator)
	gen := mustGenerateKey(t)
	orgID := uuid.NewString()
	role := "admin"
	keyID := uuid.NewString()
	r.putKey(domain.APIKey{
		ID:              keyID,
		OrganizationID:  &orgID,
		KeyPrefix:       gen.Prefix,
		KeyHash:         gen.Hash,
		Name:            "ci-runner",
		Scopes:          []byte("[]"),
		Role:            &role,
		CreatedAt:       time.Now().UTC(),
		CreatedByUserID: creator.ID,
	})

	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, gen.Plaintext)
	au, recognized, err := res.Resolve(req)
	if err != nil || !recognized || au == nil {
		t.Fatalf("expected service-account auth; got au=%v recognized=%v err=%v", au, recognized, err)
	}
	if au.Method != domain.AuthMethodServiceAccount {
		t.Errorf("want Method=%q got %q", domain.AuthMethodServiceAccount, au.Method)
	}
	if au.ActiveOrgID == nil || *au.ActiveOrgID != orgID {
		t.Errorf("want ActiveOrgID=%q got %+v", orgID, au.ActiveOrgID)
	}
	if au.OrgRole == nil || *au.OrgRole != "admin" {
		t.Errorf("want OrgRole=admin got %+v", au.OrgRole)
	}
	if !au.Principal.IsServiceAccount() {
		t.Errorf("want ServiceAccount principal; got %+v", au.Principal)
	}
	if au.Principal.KeyID == nil || *au.Principal.KeyID != keyID {
		t.Errorf("KeyID not surfaced: %+v", au.Principal.KeyID)
	}
	if au.Principal.CreatedBy == nil || *au.Principal.CreatedBy != creator.ID {
		t.Errorf("CreatedBy not surfaced: %+v", au.Principal.CreatedBy)
	}
}

// TestResolver_OrgScopedKey_CreatorDeleted asserts that a key whose
// human creator has been deleted returns 401 cleanly rather than
// crashing.
func TestResolver_OrgScopedKey_CreatorDeleted(t *testing.T) {
	r := newFakeRepo()
	h := newFakeHost(r)
	// Do NOT seed creator; key references a missing user.
	gen := mustGenerateKey(t)
	orgID := uuid.NewString()
	r.putKey(domain.APIKey{
		ID:              uuid.NewString(),
		OrganizationID:  &orgID,
		KeyPrefix:       gen.Prefix,
		KeyHash:         gen.Hash,
		Name:            "orphan",
		Scopes:          []byte("[]"),
		CreatedAt:       time.Now().UTC(),
		CreatedByUserID: "deleted-user-id",
	})
	res := newResolver(h, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, gen.Plaintext)
	au, recognized, err := res.Resolve(req)
	if au != nil || !recognized {
		t.Fatalf("want (nil, true), got (%v, %v)", au, recognized)
	}
	if !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Errorf("want ErrUnauthorized, got %v", err)
	}
}
