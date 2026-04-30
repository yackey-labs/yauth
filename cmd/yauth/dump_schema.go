package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
	"github.com/yackey-labs/yauth-go/yauthcfg"
)

func newDumpSchemaCmd() *cobra.Command {
	var (
		configPath string
		outPath    string
	)
	cmd := &cobra.Command{
		Use:          "dump-schema",
		Short:        "Migrate an in-memory SQLite and dump the resulting CREATE statements",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load config purely for diagnostics — we always migrate
			// against an in-memory SQLite to make the dump portable.
			if _, err := yauthcfg.Load(configPath); err != nil {
				return err
			}
			db, err := gormrepo.OpenSQLite("file::memory:?cache=shared")
			if err != nil {
				return fmt.Errorf("open in-memory sqlite: %w", err)
			}
			ctx := cmd.Context()
			if err := gormrepo.Migrate(ctx, db); err != nil {
				return fmt.Errorf("migrate in-memory: %w", err)
			}
			sqlDB, err := db.DB()
			if err != nil {
				return err
			}
			ddl, err := dumpDDL(ctx, sqlDB)
			if err != nil {
				return err
			}
			body := strings.Join(ddl, ";\n\n") + ";\n"
			if outPath == "" || outPath == "-" {
				fmt.Fprintln(cmd.OutOrStdout(), body)
			} else {
				if err := os.WriteFile(outPath, []byte(body), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", outPath, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d statements)\n", outPath, len(ddl))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "yauth.yaml", "path to config file")
	cmd.Flags().StringVarP(&outPath, "out", "o", "schema.sql", "output path (- for stdout)")
	return cmd
}

func dumpDDL(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if s.Valid && strings.TrimSpace(s.String) != "" {
			out = append(out, s.String)
		}
	}
	return out, rows.Err()
}
