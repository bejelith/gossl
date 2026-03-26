package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func createTestRootCA(t *testing.T, q *Queries) int64 {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	ca, err := q.CreateCA(context.Background(), CreateCAParams{
		CommonName: "Test Root CA",
		Serial:     "ROOT01",
		KeyAlgo:    "rsa",
		CertPem:    "test-ca-pem",
		NotBefore:  now,
		NotAfter:   now.Add(10 * 365 * 24 * time.Hour),
		CreatedAt:  now,
	})
	if err != nil {
		t.Fatalf("createTestRootCA() error = %v", err)
	}
	return ca.ID
}

func createTestIntermediateCA(t *testing.T, q *Queries, parentID int64) int64 {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	ca, err := q.CreateCA(context.Background(), CreateCAParams{
		ParentID:   sql.NullInt64{Int64: parentID, Valid: true},
		CommonName: "Test Intermediate",
		Serial:     "INTTEST",
		KeyAlgo:    "rsa",
		CertPem:    "test-int-pem",
		NotBefore:  now,
		NotAfter:   now.Add(5 * 365 * 24 * time.Hour),
		CreatedAt:  now,
	})
	if err != nil {
		t.Fatalf("createTestIntermediateCA() error = %v", err)
	}
	return ca.ID
}

// CA tests

func TestCreateAndGetRootCA(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	created, err := q.CreateCA(ctx, CreateCAParams{
		CommonName: "Test Root CA",
		Serial:     "AA11BB22",
		KeyAlgo:    "rsa",
		CertPem:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		NotBefore:  now,
		NotAfter:   now.Add(10 * 365 * 24 * time.Hour),
		CreatedAt:  now,
	})
	if err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if created.ID == 0 {
		t.Error("CreateCA() ID should not be 0")
	}
	if created.ParentID.Valid {
		t.Error("Root CA ParentID should not be valid")
	}

	got, err := q.GetRootCA(ctx)
	if err != nil {
		t.Fatalf("GetRootCA() error = %v", err)
	}
	if got.CommonName != "Test Root CA" {
		t.Errorf("GetRootCA() CommonName = %q, want %q", got.CommonName, "Test Root CA")
	}
	if got.Serial != "AA11BB22" {
		t.Errorf("GetRootCA() Serial = %q, want %q", got.Serial, "AA11BB22")
	}
}

func TestGetRootCAEmpty(t *testing.T) {
	q := newTestQueries(t)

	_, err := q.GetRootCA(context.Background())
	if err != sql.ErrNoRows {
		t.Fatalf("GetRootCA(empty db) error = %v, want sql.ErrNoRows", err)
	}
}

func TestCreateIntermediateCA(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()
	rootID := createTestRootCA(t, q)

	now := time.Now().Truncate(time.Second)
	intermediate, err := q.CreateCA(ctx, CreateCAParams{
		ParentID:   sql.NullInt64{Int64: rootID, Valid: true},
		CommonName: "Staging",
		Serial:     "INT01",
		KeyAlgo:    "rsa",
		CertPem:    "test-pem",
		NotBefore:  now,
		NotAfter:   now.Add(time.Hour),
		CreatedAt:  now,
	})
	if err != nil {
		t.Fatalf("CreateCA(intermediate) error = %v", err)
	}
	if !intermediate.ParentID.Valid || intermediate.ParentID.Int64 != rootID {
		t.Errorf("intermediate ParentID = %v, want %d", intermediate.ParentID, rootID)
	}

	got, err := q.GetCAByCN(ctx, "Staging")
	if err != nil {
		t.Fatalf("GetCAByCN() error = %v", err)
	}
	if got.Serial != "INT01" {
		t.Errorf("GetCAByCN() Serial = %q, want %q", got.Serial, "INT01")
	}
}

func TestCreateCABadParent(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	_, err := q.CreateCA(ctx, CreateCAParams{
		ParentID:   sql.NullInt64{Int64: 999, Valid: true},
		CommonName: "Bad Intermediate",
		Serial:     "BAD01",
		KeyAlgo:    "rsa",
		CertPem:    "test-pem",
		NotBefore:  now,
		NotAfter:   now.Add(time.Hour),
		CreatedAt:  now,
	})
	if err == nil {
		t.Fatal("CreateCA(bad parent_id) expected foreign key error, got nil")
	}
}

func TestListCAs(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()
	rootID := createTestRootCA(t, q)

	now := time.Now().Truncate(time.Second)
	for i, name := range []string{"Intermediate A", "Intermediate B"} {
		_, err := q.CreateCA(ctx, CreateCAParams{
			ParentID:   sql.NullInt64{Int64: rootID, Valid: true},
			CommonName: name,
			Serial:     fmt.Sprintf("INT%d", i),
			KeyAlgo:    "ecdsa",
			CertPem:    "test-pem",
			NotBefore:  now,
			NotAfter:   now.Add(time.Hour),
			CreatedAt:  now,
		})
		if err != nil {
			t.Fatalf("CreateCA(%s) error = %v", name, err)
		}
	}

	cas, err := q.ListCAs(ctx)
	if err != nil {
		t.Fatalf("ListCAs() error = %v", err)
	}
	if len(cas) != 3 {
		t.Errorf("ListCAs() count = %d, want 3", len(cas))
	}
}

// Cert tests

func TestIssueCertAndRevoke(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()
	rootID := createTestRootCA(t, q)
	intID := createTestIntermediateCA(t, q, rootID)

	now := time.Now().Truncate(time.Second)
	cert, err := q.CreateCert(ctx, CreateCertParams{
		CaID: intID, CommonName: "api.example.com", Serial: "CERT01", KeyAlgo: "rsa",
		CertPem: "test-pem", NotBefore: now, NotAfter: now.Add(365 * 24 * time.Hour), CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateCert() error = %v", err)
	}
	if cert.RevokedAt.Valid {
		t.Error("CreateCert() RevokedAt should not be valid")
	}

	revokeTime := now.Add(time.Hour)
	n, err := q.RevokeCert(ctx, RevokeCertParams{
		RevokedAt: sql.NullTime{Time: revokeTime, Valid: true},
		Serial:    "CERT01",
	})
	if err != nil {
		t.Fatalf("RevokeCert() error = %v", err)
	}
	if n != 1 {
		t.Errorf("RevokeCert() rows = %d, want 1", n)
	}

	got, err := q.GetCertBySerial(ctx, "CERT01")
	if err != nil {
		t.Fatalf("GetCertBySerial() error = %v", err)
	}
	if !got.RevokedAt.Valid {
		t.Fatal("GetCertBySerial() RevokedAt should be valid after revoke")
	}
}

func TestRevokeCertNotFound(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	n, err := q.RevokeCert(ctx, RevokeCertParams{
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
		Serial:    "NONEXISTENT",
	})
	if err != nil {
		t.Fatalf("RevokeCert() error = %v", err)
	}
	if n != 0 {
		t.Errorf("RevokeCert(nonexistent) rows = %d, want 0", n)
	}
}

func TestListCertsByCA(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()
	rootID := createTestRootCA(t, q)
	intID := createTestIntermediateCA(t, q, rootID)

	now := time.Now().Truncate(time.Second)
	for i := range 3 {
		_, err := q.CreateCert(ctx, CreateCertParams{
			CaID: intID, CommonName: fmt.Sprintf("cert-%d.example.com", i),
			Serial: fmt.Sprintf("CERT%02d", i), KeyAlgo: "rsa",
			CertPem: "test-pem", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now,
		})
		if err != nil {
			t.Fatalf("CreateCert(%d) error = %v", i, err)
		}
	}

	certs, err := q.ListCertsByCA(ctx, intID)
	if err != nil {
		t.Fatalf("ListCertsByCA() error = %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("ListCertsByCA() count = %d, want 3", len(certs))
	}
}

func TestCreateCertBadCA(t *testing.T) {
	q := newTestQueries(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	_, err := q.CreateCert(ctx, CreateCertParams{
		CaID: 999, CommonName: "bad.example.com", Serial: "BAD01", KeyAlgo: "rsa",
		CertPem: "test-pem", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now,
	})
	if err == nil {
		t.Fatal("CreateCert(bad ca_id) expected foreign key error, got nil")
	}
}
