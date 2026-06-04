// Command yauth is the operational CLI for yauth. It is the
// production-blessed entry point for migrations: run `yauth migrate`
// as a one-shot job (Kubernetes Job, ECS task, etc.) before rolling
// out app replicas. App startup never migrates.
package main

import (
	"fmt"
	"os"
)

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
