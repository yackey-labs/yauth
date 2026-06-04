package main

import (
	"fmt"

	"github.com/spf13/cobra"
	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/yauthcfg"
)

func newMigrateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:          "migrate",
		Short:        "Run AutoMigrate against the configured database (production-blessed entry point)",
		Long:         "Open the configured database and run yauth-go AutoMigrate. Run this as a one-shot Job before rolling out app replicas; concurrent migrations across replicas race.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := yauthcfg.Load(configPath)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if err := yauth.Migrate(ctx, cfg); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "migrated %s database (%s)\n", cfg.Database.Driver, cfg.Database.DSN)
			tables := cfg.ExpectedTables()
			fmt.Fprintf(out, "expected tables (%d):\n", len(tables))
			for _, t := range tables {
				fmt.Fprintf(out, "  - %s\n", t)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "yauth.yaml", "path to config file")
	return cmd
}
