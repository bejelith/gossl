package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenDB_CreatesSchema(t *testing.T) {
	db, err := OpenDB(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("OpenDB(:memory:) error = %v", err)
	}
	defer db.Close()

	var version int
	err = db.db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&version)
	if err != nil {
		t.Fatalf("PRAGMA user_version error = %v", err)
	}
	if version != SchemaVersion {
		t.Errorf("user_version = %d, want %d", version, SchemaVersion)
	}
}

func TestOpenDB_TablesExist(t *testing.T) {
	db, err := OpenDB(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("OpenDB(:memory:) error = %v", err)
	}
	defer db.Close()

	tables := []string{"ca", "cert", "keystore"}
	for _, table := range tables {
		var name string
		err := db.db.QueryRowContext(context.Background(),
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestOpenDB_ForeignKeysEnabled(t *testing.T) {
	db, err := OpenDB(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("OpenDB(:memory:) error = %v", err)
	}
	defer db.Close()

	var fk int
	err = db.db.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&fk)
	if err != nil {
		t.Fatalf("PRAGMA foreign_keys error = %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
}

func TestOpenDB_RejectsWrongVersion(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	_, err = db.db.ExecContext(context.Background(), "PRAGMA user_version = 99")
	if err != nil {
		t.Fatalf("set user_version error = %v", err)
	}
	db.Close()

	_, err = OpenDB(context.Background(), dbPath)
	if err == nil {
		t.Fatal("OpenDB(wrong version) expected error, got nil")
	}
}

func TestOpenDB_ReopensExistingDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	db.Close()

	db2, err := OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB(reopen) error = %v", err)
	}
	db2.Close()
}

func TestOpenDB_InvalidPath(t *testing.T) {
	_, err := OpenDB(context.Background(), "/nonexistent/dir/db.sqlite")
	if err == nil {
		t.Fatal("OpenDB(bad path) expected error, got nil")
	}
}
