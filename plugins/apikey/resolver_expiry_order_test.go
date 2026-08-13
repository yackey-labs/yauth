package apikey

// The resolver answers "this key expired" BEFORE it has established that the
// caller holds the key's secret:
//
//	rec, err := repo.GetAPIKeyByPrefix(ctx, prefix)   // prefix is NOT secret
//	if rec.ExpiresAt != nil && !rec.ExpiresAt.After(now) {
//	        return nil, true, yautherr.ErrTokenExpired
//	}
//	if subtle.ConstantTimeCompare(hashSecret(secret), rec.KeyHash) != 1 {
//	        return nil, true, yautherr.ErrUnauthorized
//	}
//
// The 8-hex prefix is deliberately non-secret: GET /api-keys returns it, and
// it shows up in logs and dashboards. So anyone holding a prefix alone learns,
// from the error the resolver returns, whether that prefix names a real key
// that has expired or no key at all — a fact the credential check itself is
// supposed to gate. yauth re-exports both sentinels (errors.go: ErrTokenExpired),
// and an embedder that calls middleware.ResolveAuth (or plugs its own resolver
// chain) branches on them; yauth's own router happens to render both as a bare
// 401, which is why this belongs at the resolver contract rather than at HTTP.
// The verification order is the fix: nothing about a stored row should be
// reported before the secret matches.
//
// HARNESS NOTE — why this file needs its own repo wrapper. The package's
// fakeRepo (and repo/memrepo) filter expired rows to ErrNotFound inside
// GetAPIKeyByPrefix, so the resolver's own expiry branch is unreachable
// through them; TestResolver_ExpiredKey_RecognizedExpired in resolver_test.go
// says as much in a comment and asserts the fake's behaviour instead. The
// production query does no such filtering —
//
//	-- name: GetAPIKeyByPrefix :one
//	SELECT * FROM yauth_api_keys WHERE key_prefix = $1 LIMIT 1;
//
// — so on Postgres the branch runs on every request that presents an expired
// key. unexpiredFilterRepo restores that production behaviour and nothing else.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// unexpiredFilterRepo is fakeRepo with GetAPIKeyByPrefix behaving like
// pgxrepo: the row comes back whatever its expires_at says, and deciding what
// to do about it is the resolver's job.
type unexpiredFilterRepo struct {
	*fakeRepo
}

func (r *unexpiredFilterRepo) GetAPIKeyByPrefix(_ context.Context, prefix string) (*domain.APIKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range r.keys {
		if k.KeyPrefix == prefix {
			k := k
			return &k, nil
		}
	}
	return nil, yautherr.ErrNotFound
}

// seedExpiredKey plants a user-scoped key that expired an hour ago and returns
// the generated material.
func seedExpiredKey(t *testing.T, r *fakeRepo) GeneratedKey {
	t.Helper()
	now := time.Now().UTC()
	user := domain.User{
		ID:        uuid.NewString(),
		Email:     uuid.NewString() + "@example.com",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	}
	r.putUser(user)

	gen := mustGenerateKey(t)
	expired := now.Add(-time.Hour)
	r.putKey(domain.APIKey{
		ID:              uuid.NewString(),
		UserID:          &user.ID,
		KeyPrefix:       gen.Prefix,
		KeyHash:         gen.Hash,
		Name:            "ci-runner",
		Scopes:          []byte("[]"),
		ExpiresAt:       &expired,
		CreatedAt:       now.Add(-24 * time.Hour),
		CreatedByUserID: user.ID,
	})
	return gen
}

func resolveHeader(t *testing.T, r *fakeRepo, header string) error {
	t.Helper()
	h := newFakeHost(&unexpiredFilterRepo{fakeRepo: r})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, header)
	_, recognized, err := newResolver(h, "yak").Resolve(req)
	if !recognized {
		t.Fatalf("a well-formed X-Api-Key must be recognized=true so the chain short-circuits")
	}
	return err
}

// A caller who knows only the (public) prefix must not be able to tell a real
// expired key from a prefix that names nothing.
func TestResolve_ExpiredKeyWithWrongSecretIsIndistinguishable(t *testing.T) {
	r := newFakeRepo()
	gen := seedExpiredKey(t, r)

	realPrefixGarbageSecret := resolveHeader(t, r, "yak_"+gen.Prefix+"_"+strings.Repeat("a", 32))
	unknownPrefix := resolveHeader(t, r, "yak_deadbeef_"+strings.Repeat("a", 32))

	if !errors.Is(unknownPrefix, yautherr.ErrUnauthorized) {
		t.Fatalf("baseline changed: unknown prefix should be ErrUnauthorized, got %v", unknownPrefix)
	}
	if !errors.Is(realPrefixGarbageSecret, yautherr.ErrUnauthorized) {
		t.Errorf("a caller holding only the public prefix learned the key exists: got %v, want %v",
			realPrefixGarbageSecret, yautherr.ErrUnauthorized)
	}
}

// POSITIVE CONTROL: expiry is still enforced. An expired key presented with
// its CORRECT secret must still be refused — the fix is the order of the two
// checks, not the removal of one.
func TestResolve_ExpiredKeyWithCorrectSecretStillRefused(t *testing.T) {
	r := newFakeRepo()
	gen := seedExpiredKey(t, r)

	err := resolveHeader(t, r, gen.Plaintext)
	if err == nil {
		t.Fatalf("an expired key authenticated with its correct secret")
	}
	if !errors.Is(err, yautherr.ErrTokenExpired) && !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Fatalf("expired key rejected with an unexpected error: %v", err)
	}
}

// POSITIVE CONTROL: a live key still authenticates through the same
// production-shaped repo, so the wrapper above is not quietly breaking the
// happy path.
func TestResolve_LiveKeyStillAuthenticatesWithProductionRepoSemantics(t *testing.T) {
	r := newFakeRepo()
	now := time.Now().UTC()
	user := domain.User{
		ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	}
	r.putUser(user)
	gen := mustGenerateKey(t)
	future := now.Add(time.Hour)
	r.putKey(domain.APIKey{
		ID: uuid.NewString(), UserID: &user.ID, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "live", Scopes: []byte("[]"), ExpiresAt: &future,
		CreatedAt: now, CreatedByUserID: user.ID,
	})

	h := newFakeHost(&unexpiredFilterRepo{fakeRepo: r})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, gen.Plaintext)
	au, recognized, err := newResolver(h, "yak").Resolve(req)
	if err != nil || !recognized || au == nil {
		t.Fatalf("live key failed to authenticate: au=%v recognized=%v err=%v", au, recognized, err)
	}
	if au.User.ID != user.ID {
		t.Fatalf("resolved the wrong user: %s", au.User.ID)
	}
}
