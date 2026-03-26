//go:build tools

// Package tools imports tool dependencies to ensure they are included in go.sum.
package tools

import (
	_ "github.com/testcontainers/testcontainers-go"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "modernc.org/sqlite"
)
