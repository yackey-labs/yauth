package middleware

// binding_audit_fanout_test.go — the middleware's own corner of the
// audit-export outbox hole.
//
// A session-binding mismatch is the closest thing yauth has to a hijack
// alarm: enforceBinding notices that the cookie arrived from a different
// client than the one it was issued to and, on
// ua_mismatch_action=invalidate, deletes the session. auditMismatch records
// that in yauth_audit_log.
//
// It recorded it and nothing else. The row was written straight to the repo,
// and the only path from the audit table to audit-export's outbox is the
// host's recorder list — which package middleware could not reach, because
// package plugin imports middleware and so the dependency cannot run the
// other way. The result: the row existed in the database and no SIEM ever
// saw it, exactly like the handler-authored rows now funnelled through
// plugin.WriteAudit. SetAuditFanout is the hand-off; yauth.Build installs
// YAuth.FanoutAudit into it.
//
// The positive control is the row itself: if the mismatch stopped being
// detected, or stopped being written, this test fails on the first
// assertion rather than passing vacuously on an empty fan-out.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBindingMismatch_AuditRowReachesTheFanout(t *testing.T) {
	cap, raw, _ := setupBindingHarness(t, "", "issued-to/1.0")
	mw := New(cap, Config{
		CookieName:       "yauth_session",
		BindUA:           true,
		UAMismatchAction: MismatchActionInvalidate,
	})

	var fanned []string
	mw.SetAuditFanout(func(_ context.Context, auditLogID string, orgID *string) {
		if orgID != nil {
			t.Errorf("a session is not org-scoped; fan-out got organization_id=%q", *orgID)
		}
		fanned = append(fanned, auditLogID)
	})

	h := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:55555"
	req.Header.Set("User-Agent", "stolen-by/9.9")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// POSITIVE CONTROL: the mismatch is still detected and still recorded.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay from a different User-Agent = %d, want 401", rec.Code)
	}
	if len(cap.audits) != 1 {
		t.Fatalf("want exactly 1 binding-mismatch audit row, got %d (%+v)", len(cap.audits), cap.audits)
	}

	// THE DEFECT: the row was written and handed to nobody.
	if len(fanned) != 1 || fanned[0] != cap.audits[0].ID {
		t.Fatalf("binding-mismatch row %s was written to the audit table but not handed to the "+
			"audit fan-out (fan-out saw %v). That fan-out is audit-export's only enqueue point, so "+
			"an invalidated-on-hijack session is invisible to every exported stream.",
			cap.audits[0].ID, fanned)
	}
}
