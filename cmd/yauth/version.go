package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "version",
		Short:        "Print the yauth-go module version",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			info, ok := debug.ReadBuildInfo()
			if !ok {
				fmt.Fprintln(out, "yauth-go (version unknown)")
				return nil
			}
			version := info.Main.Version
			if version == "" || version == "(devel)" {
				version = "(devel)"
			}
			fmt.Fprintf(out, "yauth-go %s\n", version)
			fmt.Fprintf(out, "go: %s\n", info.GoVersion)
			return nil
		},
	}
}
