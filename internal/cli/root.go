// Package cli defines the gossl command-line interface.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewRoot returns the root gossl command.
func NewRoot(version, commit string) *cobra.Command {
	root := &cobra.Command{
		Use:     "gossl",
		Short:   "Simplified TLS certificate management and troubleshooting",
		Version: fmt.Sprintf("%s (%s)", version, commit),
	}

	root.AddCommand(newCACmd())
	root.AddCommand(newCertCmd())
	root.AddCommand(newCSRCmd())
	root.AddCommand(newKeyCmd())
	root.AddCommand(newSClientCmd())
	root.AddCommand(newServeCmd())
	root.AddCommand(newDocsCmd())
	root.AddCommand(newGraphCmd())

	return root
}
