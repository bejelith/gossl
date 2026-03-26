package store

import (
	"context"
	"database/sql"
	"testing"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("OpenDB(:memory:) error = %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newTestQueries(t *testing.T) *Queries {
	t.Helper()
	db := openTestDB(t)
	return New(db.SQLDB())
}

func TestKeyStore_StoreAndLoad(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	key := []byte("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
	if err := q.StoreKey(ctx, StoreKeyParams{ID: "serial-001", KeyPem: key}); err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	got, err := q.LoadKey(ctx, "serial-001")
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}
	if string(got) != string(key) {
		t.Errorf("LoadKey() = %q, want %q", got, key)
	}
}

func TestKeyStore_LoadNotFound(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	_, err := q.LoadKey(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("LoadKey(nonexistent) error = %v, want sql.ErrNoRows", err)
	}
}

func TestKeyStore_Delete(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	key := []byte("test-key")
	if err := q.StoreKey(ctx, StoreKeyParams{ID: "serial-002", KeyPem: key}); err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}
	n, err := q.DeleteKey(ctx, "serial-002")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	if n != 1 {
		t.Errorf("DeleteKey() rows = %d, want 1", n)
	}
	_, err = q.LoadKey(ctx, "serial-002")
	if err != sql.ErrNoRows {
		t.Fatalf("LoadKey() after Delete error = %v, want sql.ErrNoRows", err)
	}
}

func TestKeyStore_DeleteNotFound(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	n, err := q.DeleteKey(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("DeleteKey(nonexistent) error = %v", err)
	}
	if n != 0 {
		t.Errorf("DeleteKey(nonexistent) rows = %d, want 0", n)
	}
}

func TestKeyStore_StoreDuplicate(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	key := []byte("test-key")
	if err := q.StoreKey(ctx, StoreKeyParams{ID: "serial-003", KeyPem: key}); err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}
	err := q.StoreKey(ctx, StoreKeyParams{ID: "serial-003", KeyPem: key})
	if err == nil {
		t.Fatal("StoreKey(duplicate) expected error, got nil")
	}
}
