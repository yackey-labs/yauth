package main

import (
	"io"

	"github.com/spf13/cobra"
)

// newRootCmd assembles every subcommand and returns the root command.
// All output is routed through cmd.OutOrStdout()/ErrOrStderr() so
// tests can capture it via cobra.SetOut/SetErr.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "yauth",
		Short:         "yauth-go operational CLI",
		Long:          "Operational CLI for yauth-go. Production users run `yauth migrate` as a one-shot Job; the library never auto-migrates at app startup.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newInitCmd(),
		newStatusCmd(),
		newMigrateCmd(),
		newCheckCmd(),
		newGenSecretsCmd(),
		newDumpSchemaCmd(),
		newGenKeysCmd(),
		newVersionCmd(),
	)
	return root
}

// Helper to keep test wiring simple.
func setOutput(c *cobra.Command, out, errOut io.Writer) {
	c.SetOut(out)
	c.SetErr(errOut)
}
