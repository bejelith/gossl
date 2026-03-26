// Package store provides SQLite-backed storage implementations.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var schemaSQL string

// SchemaVersion is the current database schema version.
const SchemaVersion = 1

// DB wraps a sql.DB connection with schema management.
type DB struct {
	db *sql.DB
}

// OpenDB opens a SQLite database and ensures the schema is initialized.
// Use ":memory:" for in-memory databases (testing).
func OpenDB(ctx context.Context, path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	if _, err := sqlDB.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}

	var version int
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("reading schema version: %w", err)
	}

	if version == 0 {
		if _, err := sqlDB.ExecContext(ctx, schemaSQL); err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("initializing schema: %w", err)
		}
		if _, err := sqlDB.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion)); err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("setting schema version: %w", err)
		}
	} else if version != SchemaVersion {
		sqlDB.Close()
		return nil, fmt.Errorf("unsupported schema version %d (expected %d)", version, SchemaVersion)
	}

	return &DB{db: sqlDB}, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// SQLDB returns the underlying *sql.DB for query execution.
func (d *DB) SQLDB() *sql.DB {
	return d.db
}
