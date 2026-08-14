package oauth2server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
)

// startStaleClientSweep launches the opt-in background sweep (guarded so it
// starts at most once). Gated by Config.DCRStaleClientTTL > 0 at the call site.
func (p *oauth2Plugin) startStaleClientSweep(host plugin.PluginHost) {
	p.sweepOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(p.cfg.DCRStaleSweepInterval)
			defer ticker.Stop()
			for range ticker.C {
				p.sweepStaleClients(host)
			}
		}()
	})
}

// sweepStaleClients purges DCR clients unused for longer than DCRStaleClientTTL
// and records the result. Never silent: it logs and writes an
// `oauth2.client.swept` audit event whenever anything is reclaimed. Safe to call
// directly (used by tests).
func (p *oauth2Plugin) sweepStaleClients(host plugin.PluginHost) {
	ctx := context.Background()
	cutoff := time.Now().UTC().Add(-p.cfg.DCRStaleClientTTL)
	swept, err := host.Repo().PurgeStaleDynamicClients(ctx, cutoff)
	if err != nil {
		host.Logger().ErrorContext(ctx, "oauth2: stale DCR client sweep failed", "err", err)
		return
	}
	if len(swept) == 0 {
		return
	}
	host.Logger().InfoContext(ctx, "oauth2: swept stale DCR clients", "count", len(swept), "ttl", p.cfg.DCRStaleClientTTL)
	meta, _ := json.Marshal(map[string]any{
		"count":      len(swept),
		"client_ids": swept,
		"cutoff":     cutoff,
	})
	// WriteAudit, not LogAuditEvent, so the sweep is exported like every
	// other audit row. Note this is the one caller with no request behind
	// it — a background goroutine — which is why AuditRecorder's contract
	// spells out that recorders must not assume a request context.
	_ = plugin.WriteAudit(ctx, host, domain.NewAuditLog{
		ID:        uuid.NewString(),
		EventType: "oauth2.client.swept",
		Metadata:  meta,
		CreatedAt: time.Now().UTC(),
	})
}
