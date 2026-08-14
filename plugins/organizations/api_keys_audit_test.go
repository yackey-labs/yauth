package organizations

// api_keys_audit_test.go — org-scoped service-account keys are minted,
// rotated and revoked without leaving an audit row.
//
// An org API key is the strongest credential this plugin can issue: it
// carries a ROLE (up to admin) and a permission set, and it authenticates
// as a service-account principal on every org-scoped route. Yet
// `grep -rn 'host.Emit|LogAuditEvent|events\.' plugins/organizations/`
// returns nothing — minting one is as silent as listing them. That grep is
// empty for the WHOLE plugin, not just this file: member adds, role changes
// and policy edits write no audit row either, so there is no org trail for
// a mint to be missing from. This test pins the credential half, which is
// the part that hands an attacker persistence: an org admin whose session
// is stolen can mint a permanent admin-role key and leave nothing behind.
//
// The same handler also computes
// `time.Now().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)`,
// which overflows int64 above ~106,751 days: expires_in_days=200000 answers
// 201 with a plaintext secret whose expires_at is in the past.
//
// Both checks are paired with positive controls that the key really is
// created, rotated and revoked.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

// orgAuditRows reads every audit row the plugin's repo holds.
func orgAuditRows(t *testing.T, r interface {
	ListAuditLog(context.Context, domain.ListAuditFilters) ([]*domain.AuditLog, error)
}) []*domain.AuditLog {
	t.Helper()
	rows, err := r.ListAuditLog(context.Background(), domain.ListAuditFilters{Limit: 1000})
	if err != nil {
		t.Fatalf("list audit log: %v", err)
	}
	return rows
}

func orgAuditTypes(rows []*domain.AuditLog) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.EventType)
	}
	return out
}

// TestOrgAPIKeyLifecycle_IsAudited drives mint -> rotate -> revoke and
// asserts each step leaves a row. Each step uses Errorf so the failure
// report names every silent op, not just the first.
func TestOrgAPIKeyLifecycle_IsAudited(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)

	// --- mint -------------------------------------------------------------
	before := len(orgAuditRows(t, r))
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{
		"name": "scim-runner", "role": "admin",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create key: %d", res.StatusCode)
	}
	var created createOrgAPIKeyResponse
	decode(t, res, &created)
	// POSITIVE CONTROL: an admin-role service account really was minted.
	if created.Secret == "" || created.APIKey.ID == "" {
		t.Fatalf("create must keep returning a usable key: %+v", created)
	}
	if rows := orgAuditRows(t, r); len(rows) == before {
		t.Errorf("POST /organizations/%s/api-keys minted an ADMIN-role service account and wrote "+
			"no audit row (%d rows before and after: %v)", org.ID, before, orgAuditTypes(rows))
	}

	// --- rotate -----------------------------------------------------------
	before = len(orgAuditRows(t, r))
	res = doJSON(t, http.MethodPost,
		srv.URL+"/organizations/"+org.ID+"/api-keys/"+created.APIKey.ID+"/rotate", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rotate key: %d", res.StatusCode)
	}
	var rotated rotateOrgAPIKeyResponse
	decode(t, res, &rotated)
	// POSITIVE CONTROL: rotation issued a genuinely new credential.
	if rotated.Secret == "" || rotated.APIKey.ID == created.APIKey.ID {
		t.Fatalf("rotate must mint a new key row: %+v", rotated)
	}
	if rows := orgAuditRows(t, r); len(rows) == before {
		t.Errorf("POST .../api-keys/%s/rotate replaced a live credential and wrote no audit row "+
			"(%d rows before and after: %v)", created.APIKey.ID, before, orgAuditTypes(rows))
	}

	// --- revoke -----------------------------------------------------------
	before = len(orgAuditRows(t, r))
	res = doJSON(t, http.MethodDelete,
		srv.URL+"/organizations/"+org.ID+"/api-keys/"+rotated.APIKey.ID, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete key: %d", res.StatusCode)
	}
	res.Body.Close()
	// POSITIVE CONTROL: the key is really gone.
	if _, err := r.GetAPIKeyByIDAndOrg(context.Background(), rotated.APIKey.ID, org.ID); err == nil {
		t.Fatalf("key %s survived DELETE", rotated.APIKey.ID)
	}
	if rows := orgAuditRows(t, r); len(rows) == before {
		t.Errorf("DELETE .../api-keys/%s revoked a credential and wrote no audit row "+
			"(%d rows before and after: %v)", rotated.APIKey.ID, before, orgAuditTypes(rows))
	}
}

// TestOrgAPIKeyCreate_HugeExpiryDoesNotWrapNegative asserts on the stored
// row: the failure mode is a 201 with a plaintext secret that is already
// expired.
func TestOrgAPIKeyCreate_HugeExpiryDoesNotWrapNegative(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)

	// POSITIVE CONTROL: a sane expiry lands in the future.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{
		"name": "ten-years", "expires_in_days": 3650,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expires_in_days=3650: %d, want 201", res.StatusCode)
	}
	var okKey createOrgAPIKeyResponse
	decode(t, res, &okKey)
	stored, err := r.GetAPIKeyByIDAndOrg(context.Background(), okKey.APIKey.ID, org.ID)
	if err != nil {
		t.Fatalf("repo lookup: %v", err)
	}
	if stored.ExpiresAt == nil || !stored.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("expires_in_days=3650 must store a future expiry, got %v", stored.ExpiresAt)
	}

	// THE DEFECT.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{
		"name": "overflow", "expires_in_days": 200000,
	})
	code := res.StatusCode
	var over createOrgAPIKeyResponse
	if code == http.StatusCreated {
		decode(t, res, &over)
		k, err := r.GetAPIKeyByIDAndOrg(context.Background(), over.APIKey.ID, org.ID)
		if err != nil {
			t.Fatalf("repo lookup: %v", err)
		}
		if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now().UTC()) {
			t.Fatalf("expires_in_days=200000 answered 201 with a plaintext secret whose stored "+
				"expires_at is %s — in the PAST. The int64 duration multiplication overflows "+
				"above ~106751 days. Want a 400.", k.ExpiresAt.UTC())
		}
	} else {
		res.Body.Close()
	}
	if code != http.StatusBadRequest {
		t.Fatalf("expires_in_days=200000: %d, want 400", code)
	}
}
