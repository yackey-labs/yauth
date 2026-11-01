package scim

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestPutGroup_ClearsExternalIDAndSkipsNoOpWrites: PUT is a full replace, so
// dropping externalId clears it — but an IdP re-PUTting an unchanged group on
// every sync must not write at all (updated_at / meta.lastModified stay put).
func TestPutGroup_ClearsExternalIDAndSkipsNoOpWrites(t *testing.T) {
	app := newTestApp(t)
	ctx := context.Background()

	resp := app.do(t, "POST", groupsPath(app.orgA.orgID), app.orgA.apiKey, map[string]any{
		"schemas":     []string{CoreGroupSchema},
		"displayName": "eng",
		"externalId":  "okta-eng",
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	gid, _ := decodeJSON(t, resp)["id"].(string)

	put := func() {
		t.Helper()
		resp := app.do(t, "PUT", scimGroupPath(app.orgA.orgID, gid), app.orgA.apiKey, map[string]any{
			"schemas":     []string{CoreGroupSchema},
			"displayName": "eng",
		})
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("put: %d %s", resp.StatusCode, body)
		}
	}

	put()
	g, err := app.repo.GetGroupByID(ctx, gid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if g.ExternalID != nil {
		t.Fatalf("PUT without externalId must clear it, still %q", *g.ExternalID)
	}
	cleared := g.UpdatedAt

	time.Sleep(1100 * time.Millisecond) // past any second-granularity clock
	put()
	g, err = app.repo.GetGroupByID(ctx, gid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !g.UpdatedAt.Equal(cleared) {
		t.Fatalf("unchanged PUT bumped updated_at: %v -> %v", cleared, g.UpdatedAt)
	}
}
