// Package main is the entry point for the gossl tool.
package main

import (
	"os"

	"github.com/bejelith/gossl/internal/cli"
	"github.com/bejelith/gossl/internal/version"
)

func main() {
	if err := cli.NewRoot(version.Version, version.Commit).Execute(); err != nil {
		os.Exit(1)
	}
}
