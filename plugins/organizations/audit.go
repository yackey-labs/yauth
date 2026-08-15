// audit.go — one audit call for every mutating route in this package.
//
// Twenty-five operations in plugins/organizations change state. Until this
// file, three of them wrote an audit row: the API-key ones. Deleting an
// organization, transferring its ownership, removing a member, changing a
// member's role, creating or deleting a group, adding or removing a group
// member, verifying a domain, rewriting the auth policy and every invitation
// operation all completed in silence. An investigator reading yauth_audit_log
// after an org takeover would have concluded that nothing happened.
//
// That is a worse failure than a missing feature, because the log's value is
// its completeness: a partial audit trail reads as authoritative and is not.
// The three that did audit made it look deliberate.
//
// The choke point itself already existed — plugin.WriteAudit, added so that
// every row is both persisted AND handed to the host's recorders (which is
// what routes it to the org's export destinations). What was missing was
// anybody calling it. audit_coverage_test.go now enforces that structurally:
// it parses this package and fails if a mutating huma.Register is added whose
// handler does not audit, so handler twenty-six cannot repeat this quietly.
package organizations

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// orgAudit writes one mutation row through the audit choke
// point (plugin.WriteAudit), so it is both persisted and handed to the
// host's audit recorders. Before this, `grep LogAuditEvent` over this whole
// plugin returned nothing: an org admin whose session was stolen could mint
// a permanent admin-role service account — the strongest credential this
// plugin issues — as silently as listing them.
//
// organization_id is in the metadata both because an auditor needs it and
// because plugin.WriteAudit reads the org scope back out of it, which is
// what routes the row to that org's own export destinations.
//
// Errors are swallowed: the key operation already succeeded, and an unhappy
// audit store must not turn it into a 500 the caller retries.
func orgAudit(ctx context.Context, host plugin.PluginHost, event, orgID string, au *domain.AuthUser, fields map[string]any) {
	if au == nil {
		return
	}
	// Actor is au.User.ID — the human, or for a service-account caller the
	// human who minted the calling key (Principal synthesises it from
	// CreatedBy). actor_kind keeps the two distinguishable.
	kind := "user"
	if au.Principal.IsServiceAccount() {
		kind = "service_account"
	}
	meta := map[string]any{
		"organization_id": orgID,
		"actor_kind":      kind,
	}
	for k, v := range fields {
		meta[k] = v
	}
	raw, _ := json.Marshal(meta)
	uid := au.User.ID
	var ip *string
	if r := middleware.HTTPRequestFromContext(ctx); r != nil {
		ip = middleware.RequestIP(r)
	}
	_ = plugin.WriteAudit(ctx, host, domain.NewAuditLog{
		ID:        uuid.NewString(),
		UserID:    &uid,
		EventType: event,
		Metadata:  raw,
		IPAddress: ip,
		CreatedAt: time.Now().UTC(),
	})
}
