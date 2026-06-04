package apikey

import (
	"github.com/yackey-labs/yauth-go/humaapi"

	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
)

// stubResolver authenticates every request as the supplied user. Used to
// drive the management-endpoint tests without standing up the cookie path.
type stubResolver struct {
	user *domain.AuthUser
}

func (s *stubResolver) Name() string { return "stub" }
func (s *stubResolver) Resolve(_ *http.Request) (*domain.AuthUser, bool, error) {
	return s.user, true, nil
}

var _ middleware.AuthResolver = (*stubResolver)(nil)

// newServer wires the apikey plugin's routes onto a fresh ServeMux with a
// stub resolver authenticating as user.
func newServer(t *testing.T, cfg Config, user domain.User, repo *fakeRepo) (*httptest.Server, *fakeHost) {
	t.Helper()
	host := newFakeHost(repo)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})

	mux := http.NewServeMux()
	p := New(cfg).(*apiKeyPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")

	return httptest.NewServer(mux), host
}

func seededUser(t *testing.T, r *fakeRepo) domain.User {
	t.Helper()
	u := domain.User{
		ID:        uuid.NewString(),
		Email:     "owner@example.com",
		Role:      "user",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	r.putUser(u)
	return u
}

func TestHandleCreate_ReturnsPlaintextOnce(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	srv, _ := newServer(t, Config{}, user, repo)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"name": "ci-bot", "scopes": []string{"read:users"}})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status: want 201, got %d", res.StatusCode)
	}

	var out createResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Secret == "" {
		t.Fatalf("plaintext secret missing from response")
	}
	if out.APIKey.Prefix == "" || out.APIKey.ID == "" {
		t.Fatalf("response metadata incomplete: %+v", out)
	}
	if len(out.APIKey.Scopes) != 1 || out.APIKey.Scopes[0] != "read:users" {
		t.Errorf("scopes round-trip failed: %v", out.APIKey.Scopes)
	}

	// The plaintext must parse back to the stored prefix.
	prefix, secret, ok := ParseHeader(out.Secret, "yak")
	if !ok {
		t.Fatalf("returned key did not parse: %q", out.Secret)
	}
	if prefix != out.APIKey.Prefix {
		t.Errorf("prefix mismatch between metadata and plaintext")
	}
	if secret == "" {
		t.Errorf("empty secret")
	}
}

func TestHandleCreate_RejectsEmptyName(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	srv, _ := newServer(t, Config{}, user, repo)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"name": "  "})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.StatusCode)
	}
}

func TestHandleCreate_RejectsPastExpiry(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	srv, _ := newServer(t, Config{}, user, repo)
	defer srv.Close()

	past := time.Now().UTC().Add(-time.Hour)
	// `expires_at` is not a field on createRequest — huma's native body
	// validation (additionalProperties:false) rejects the unknown field with
	// 422 Unprocessable Entity (the RFC-standard validation status), replacing
	// the old hand-rolled strict-decode 400.
	body, _ := json.Marshal(map[string]any{"name": "expired", "expires_at": past})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", res.StatusCode)
	}
}

func TestHandleCreate_EnforcesMaxKeysPerUser(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	cfg := Config{MaxKeysPerUser: 2}
	srv, _ := newServer(t, cfg, user, repo)
	defer srv.Close()

	for i := 0; i < cfg.MaxKeysPerUser; i++ {
		body, _ := json.Marshal(map[string]any{"name": "key"})
		res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("create %d: want 201, got %d", i, res.StatusCode)
		}
	}
	body, _ := json.Marshal(map[string]any{"name": "overflow"})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post overflow: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("overflow: want 409, got %d", res.StatusCode)
	}
}

func TestHandleList_ReturnsOwnedKeys(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	srv, _ := newServer(t, Config{}, user, repo)
	defer srv.Close()

	// Create two keys for this user, plus one for a different user that
	// must NOT appear in the list response.
	for _, name := range []string{"a", "b"} {
		body, _ := json.Marshal(map[string]any{"name": name})
		res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("post %q: %v", name, err)
		}
		res.Body.Close()
	}
	other := domain.User{ID: uuid.NewString(), Email: "x@y.com", Role: "user", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	repo.putUser(other)
	gen, err := GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	repo.putKey(domain.APIKey{
		ID: uuid.NewString(), UserID: &other.ID, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "stranger", Scopes: []byte("[]"), CreatedAt: time.Now().UTC(),
	})

	res, err := http.Get(srv.URL + "/api-keys")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: want 200, got %d", res.StatusCode)
	}
	var lst listResponse
	if err := json.NewDecoder(res.Body).Decode(&lst); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lst.Items) != 2 {
		t.Fatalf("want 2 keys, got %d (%+v)", len(lst.Items), lst)
	}
	if lst.Total != 2 {
		t.Errorf("total: want 2, got %d", lst.Total)
	}
	for _, k := range lst.Items {
		if k.Name == "stranger" {
			t.Errorf("list leaked another user's key: %+v", k)
		}
	}
}

func TestHandleDelete_OwnerCanDelete(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	srv, _ := newServer(t, Config{}, user, repo)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"name": "k"})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var created createResponse
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api-keys/"+created.APIKey.ID, nil)
	delRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delRes.Body.Close()
	if delRes.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", delRes.StatusCode)
	}

	// Confirm gone.
	if _, ok := repo.keyByID(created.APIKey.ID); ok {
		t.Errorf("key still present after delete")
	}
}

func TestHandleDelete_RejectsForeignKey(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	srv, _ := newServer(t, Config{}, user, repo)
	defer srv.Close()

	// Plant a key owned by someone else.
	other := domain.User{ID: uuid.NewString(), Email: "x@y.com", Role: "user", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	repo.putUser(other)
	gen, err := GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	foreignID := uuid.NewString()
	repo.putKey(domain.APIKey{
		ID: foreignID, UserID: &other.ID, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "stranger", Scopes: []byte("[]"), CreatedAt: time.Now().UTC(),
	})

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api-keys/"+foreignID, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign delete: want 404, got %d", res.StatusCode)
	}
	if _, ok := repo.keyByID(foreignID); !ok {
		t.Errorf("foreign key was deleted!")
	}
}

func TestHandleEndToEnd_CreateUseDelete(t *testing.T) {
	repo := newFakeRepo()
	user := seededUser(t, repo)
	srv, _ := newServer(t, Config{}, user, repo)
	defer srv.Close()

	// 1. Create a key.
	body, _ := json.Marshal(map[string]any{"name": "bot"})
	res, err := http.Post(srv.URL+"/api-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: want 201, got %d", res.StatusCode)
	}
	var created createResponse
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()

	// 2. Use the resolver directly to authenticate. We cannot reuse the
	//    stub resolver from the test server because it ignores headers —
	//    so spin up a separate resolver bound to the same repo.
	host2 := newFakeHost(repo)
	res2 := newResolver(host2, "yak")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerName, created.Secret)
	au, recognized, err := res2.Resolve(req)
	if err != nil || !recognized || au == nil {
		t.Fatalf("resolve good key: au=%v recognized=%v err=%v", au, recognized, err)
	}
	if au.User.ID != user.ID {
		t.Fatalf("wrong user resolved: got %s, want %s", au.User.ID, user.ID)
	}

	// 3. Delete the key via the management endpoint.
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api-keys/"+created.APIKey.ID, nil)
	delRes, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delRes.Body.Close()
	if delRes.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", delRes.StatusCode)
	}

	// 4. The deleted key must no longer authenticate.
	au2, _, err2 := res2.Resolve(req)
	if au2 != nil {
		t.Errorf("deleted key still authenticated: %+v", au2)
	}
	if err2 == nil {
		t.Errorf("expected error on deleted key, got nil")
	}
}
