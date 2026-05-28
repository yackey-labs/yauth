// Command yauth is the operational CLI for yauth-go. It is the
// production-blessed entry point for migrations: run `yauth migrate`
// as a one-shot job (Kubernetes Job, ECS task, etc.) before rolling
// out app replicas. App startup never migrates.
package main

import (
	"fmt"
	"os"

	// Register the gorm-backed drivers (sqlite, postgres, mysql) so the CLI
	// can migrate/check any configured driver. pgx is built into the root pkg.
	_ "github.com/yackey-labs/yauth-go/repo/gormrepo/gormbackend"
)

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
