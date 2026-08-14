// secret_repoint_test.go — the PATCH route will carry a client_secret the
// caller has never seen onto an endpoint the caller chooses.
//
// The connection's IdP client_secret is stored AES-256-GCM encrypted and is
// deliberately never readable: GET returns client_secret_set: true and
// nothing more (connectionJSON in handlers_admin.go). PATCH is a partial
// update, and to avoid forcing the operator to re-type the secret on every
// unrelated edit it decrypts the current config and merges field by field:
//
//	merged := cur
//	if strings.TrimSpace(req.OIDC.DiscoveryURL) != "" { merged.DiscoveryURL = ... }
//	if strings.TrimSpace(req.OIDC.ClientID)     != "" { merged.ClientID = ... }
//	if strings.TrimSpace(req.OIDC.ClientSecret) != "" { merged.ClientSecret = ... }
//
// Those three branches are independent, so supplying the first and omitting
// the third re-encrypts the RETAINED secret onto the new destination. The
// secret is now bound to a discovery document the caller controls, and the
// next login spends it: handlers_login.go's exchangeCode does
// req.SetBasicAuth(clientID, clientSecret) against disco.TokenURL, which
// comes from that document. An admin who was never trusted with the secret
// reads it out of the server by pointing the server at themselves — the exact
// path the unreadable-by-design storage was meant to close.
//
// Both copies of the merge are covered. global_connections.go carries a
// second, identical one for org-less connections; a fix applied to only one
// of them leaves the hole open on the other route.
//
// The assertion is on the STORED config, decrypted straight out of the repo,
// not on the response: what matters is which endpoint the credential is
// bound to on disk. And the last case in each pair is the regression this
// guard must not cause — an unrelated PATCH (a rename) still has to preserve
// the secret, or every operator has to re-enter it to rename a connection.
package ssooidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const (
	originalDiscovery = "https://idp.example/.well-known/openid-configuration"
	attackerDiscovery = "https://attacker.example/.well-known/openid-configuration"
	originalSecret    = "s3cr3t-the-caller-never-saw"
)

// repointServer mounts the plugin behind a principal who is BOTH an
// install-wide admin (for the global routes) and the org's owner (for the
// org-scoped ones), so one fixture drives both copies of the merge.
func repointServer(t *testing.T) (*ssoOIDCPlugin, *httptest.Server, repo.Repository, domain.Organization) {
	t.Helper()
	p := newPluginWithClient(t, nil)
	r := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()
	admin, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "admin@example.com", Role: auth.RoleAdmin,
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	org, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		OwnerRoleAuthorized: true, // fixture: seeds state directly, bypassing the handler layer
		ID:                  uuid.NewString(), OrganizationID: org.ID, UserID: admin.ID,
		Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return p, srv, r, org
}

// storedConfig decrypts the connection row the way every login does.
func storedConfig(t *testing.T, p *ssoOIDCPlugin, r repo.Repository, cid string) OidcConnectionConfig {
	t.Helper()
	row, err := r.GetSsoConnectionByID(context.Background(), cid)
	if err != nil {
		t.Fatalf("load connection: %v", err)
	}
	cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, row.Config)
	if err != nil {
		t.Fatalf("decrypt stored config: %v", err)
	}
	return cfg
}

// seedRepointable creates a connection carrying a secret the test then tries
// to move. base is "" for the org route's URL prefix or the global one.
func seedRepointable(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	resp := doJSON(t, http.MethodPost, srv.URL+path, map[string]any{
		"name": "Corp IdP",
		"oidc": map[string]any{
			"discovery_url": originalDiscovery,
			"client_id":     "rp-1",
			"client_secret": originalSecret,
		},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s", resp.StatusCode, readAll(t, resp))
	}
	var created connectionJSON
	decode(t, resp, &created)
	return created.ID
}

// --- org-scoped route (handlers_admin.go) -----------------------------

func TestPatchConnection_RefusesToCarrySecretOntoNewDiscoveryURL(t *testing.T) {
	p, srv, r, org := repointServer(t)
	connPath := "/organizations/" + org.ID + "/sso/connections"
	cid := seedRepointable(t, srv, connPath)

	resp := doJSON(t, http.MethodPatch, srv.URL+connPath+"/"+cid, map[string]any{
		"oidc": map[string]any{"discovery_url": attackerDiscovery},
	})
	status := resp.StatusCode
	body := readAll(t, resp)

	cfg := storedConfig(t, p, r, cid)
	if cfg.DiscoveryURL == attackerDiscovery && cfg.ClientSecret == originalSecret {
		t.Errorf("the retained client_secret was re-bound to a caller-chosen endpoint: "+
			"stored discovery_url=%q with the original secret intact (PATCH returned %d %s)",
			cfg.DiscoveryURL, status, body)
	}
	if cfg.DiscoveryURL != originalDiscovery {
		t.Errorf("stored discovery_url = %q, want it unchanged at %q", cfg.DiscoveryURL, originalDiscovery)
	}
	if status != http.StatusBadRequest {
		t.Errorf("repointing without a fresh secret: status=%d body=%s; want 400", status, body)
	}
}

func TestPatchConnection_RefusesToCarrySecretOntoNewClientID(t *testing.T) {
	p, srv, r, org := repointServer(t)
	connPath := "/organizations/" + org.ID + "/sso/connections"
	cid := seedRepointable(t, srv, connPath)

	resp := doJSON(t, http.MethodPatch, srv.URL+connPath+"/"+cid, map[string]any{
		"oidc": map[string]any{"client_id": "someone-elses-client"},
	})
	status := resp.StatusCode
	body := readAll(t, resp)

	cfg := storedConfig(t, p, r, cid)
	if cfg.ClientID != "rp-1" {
		t.Errorf("stored client_id = %q; the secret was re-paired with a client_id the caller chose "+
			"(PATCH returned %d %s)", cfg.ClientID, status, body)
	}
	if status != http.StatusBadRequest {
		t.Errorf("re-pairing without a fresh secret: status=%d body=%s; want 400", status, body)
	}
}

// TestPatchConnection_RepointWithFreshSecretSucceeds — positive control #1:
// rotating a discovery URL is a legitimate operation. It just has to arrive
// with the secret that belongs to the new endpoint.
func TestPatchConnection_RepointWithFreshSecretSucceeds(t *testing.T) {
	p, srv, r, org := repointServer(t)
	connPath := "/organizations/" + org.ID + "/sso/connections"
	cid := seedRepointable(t, srv, connPath)

	resp := doJSON(t, http.MethodPatch, srv.URL+connPath+"/"+cid, map[string]any{
		"oidc": map[string]any{
			"discovery_url": attackerDiscovery,
			"client_secret": "a-brand-new-secret",
		},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repoint WITH a fresh secret must succeed: status=%d body=%s", resp.StatusCode, readAll(t, resp))
	}
	resp.Body.Close() //nolint:errcheck
	cfg := storedConfig(t, p, r, cid)
	if cfg.DiscoveryURL != attackerDiscovery || cfg.ClientSecret != "a-brand-new-secret" {
		t.Fatalf("repoint with a fresh secret did not store both: %+v", cfg)
	}
}

// TestPatchConnection_UnrelatedEditPreservesSecret — positive control #2, and
// the regression a careless guard causes: renaming a connection must not
// force the operator to re-enter a secret they may not have.
func TestPatchConnection_UnrelatedEditPreservesSecret(t *testing.T) {
	p, srv, r, org := repointServer(t)
	connPath := "/organizations/" + org.ID + "/sso/connections"
	cid := seedRepointable(t, srv, connPath)

	resp := doJSON(t, http.MethodPatch, srv.URL+connPath+"/"+cid, map[string]any{
		"name":   "Corp IdP (prod)",
		"status": "active",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename: status=%d body=%s", resp.StatusCode, readAll(t, resp))
	}
	resp.Body.Close() //nolint:errcheck
	cfg := storedConfig(t, p, r, cid)
	if cfg.ClientSecret != originalSecret || cfg.DiscoveryURL != originalDiscovery {
		t.Fatalf("an unrelated PATCH disturbed the stored credentials: %+v", cfg)
	}

	// Same again with an oidc block that changes neither destination — a
	// scope edit must also keep the secret.
	resp = doJSON(t, http.MethodPatch, srv.URL+connPath+"/"+cid, map[string]any{
		"oidc": map[string]any{"scopes": []string{"openid", "email", "profile", "groups"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scope edit: status=%d body=%s", resp.StatusCode, readAll(t, resp))
	}
	resp.Body.Close() //nolint:errcheck
	cfg = storedConfig(t, p, r, cid)
	if cfg.ClientSecret != originalSecret {
		t.Fatalf("a scope-only PATCH lost the stored secret: %+v", cfg)
	}
	if len(cfg.Scopes) != 4 {
		t.Fatalf("a scope-only PATCH did not apply: %+v", cfg)
	}
}

// --- global (org-less) route (global_connections.go) ------------------

func TestPatchGlobalConnection_RefusesToCarrySecretOntoNewDiscoveryURL(t *testing.T) {
	p, srv, r, _ := repointServer(t)
	cid := seedRepointable(t, srv, "/sso/connections")

	resp := doJSON(t, http.MethodPatch, srv.URL+"/sso/connections/"+cid, map[string]any{
		"oidc": map[string]any{"discovery_url": attackerDiscovery},
	})
	status := resp.StatusCode
	body := readAll(t, resp)

	cfg := storedConfig(t, p, r, cid)
	if cfg.DiscoveryURL == attackerDiscovery && cfg.ClientSecret == originalSecret {
		t.Errorf("GLOBAL route: the retained client_secret was re-bound to a caller-chosen endpoint "+
			"(stored discovery_url=%q; PATCH returned %d %s)", cfg.DiscoveryURL, status, body)
	}
	if status != http.StatusBadRequest {
		t.Errorf("GLOBAL route: repointing without a fresh secret: status=%d body=%s; want 400", status, body)
	}
}

// Positive control for the global twin.
func TestPatchGlobalConnection_UnrelatedEditPreservesSecret(t *testing.T) {
	p, srv, r, _ := repointServer(t)
	cid := seedRepointable(t, srv, "/sso/connections")

	resp := doJSON(t, http.MethodPatch, srv.URL+"/sso/connections/"+cid, map[string]any{
		"name": "Global IdP (prod)",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GLOBAL rename: status=%d body=%s", resp.StatusCode, readAll(t, resp))
	}
	resp.Body.Close() //nolint:errcheck
	cfg := storedConfig(t, p, r, cid)
	if cfg.ClientSecret != originalSecret || cfg.DiscoveryURL != originalDiscovery {
		t.Fatalf("GLOBAL: an unrelated PATCH disturbed the stored credentials: %+v", cfg)
	}
}
