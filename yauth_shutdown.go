package yauth

import (
	"context"

	"github.com/yackey-labs/yauth/plugin"
)

// Shutdown drains every registered plugin that implements
// plugin.ShutdownAware, in registration order. The first non-nil error
// is returned, but every plugin is given a chance to shut down even if
// an earlier plugin failed.
//
// Callers should pass a context with a deadline so a stuck plugin
// cannot wedge process exit. Shutdown does not flush telemetry — pair
// it with TelemetryShutdown when telemetry is enabled.
func (y *YAuth) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, p := range y.plugins {
		sa, ok := p.(plugin.ShutdownAware)
		if !ok {
			continue
		}
		if err := sa.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
