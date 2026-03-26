package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/bejelith/gossl/internal/store"
)

func TestCACreate_RootRSA(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	err := runCACreate(context.Background(), "Test RSA CA", dbPath, "", 365, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("runCACreate() error = %v", err)
	}

	ca, key := loadRootCAFromDB(t, dbPath)
	if ca.CommonName != "Test RSA CA" {
		t.Errorf("CommonName = %q, want %q", ca.CommonName, "Test RSA CA")
	}
	if ca.KeyAlgo != "rsa" {
		t.Errorf("KeyAlgo = %q, want %q", ca.KeyAlgo, "rsa")
	}
	if ca.ParentID.Valid {
		t.Error("Root CA ParentID should not be valid")
	}

	cert := parseCertPEMFromString(t, ca.CertPem)
	if !cert.IsCA {
		t.Error("cert.IsCA = false, want true")
	}
	if cert.Subject.CommonName != "Test RSA CA" {
		t.Errorf("cert.Subject.CommonName = %q, want %q", cert.Subject.CommonName, "Test RSA CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signed verification failed: %v", err)
	}

	block, _ := pem.Decode(key)
	if block == nil {
		t.Fatal("key PEM decode failed")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("key PEM type = %q, want %q", block.Type, "RSA PRIVATE KEY")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey error = %v", err)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("RSA key size = %d, want 2048", rsaKey.N.BitLen())
	}
}

func TestCACreate_RootECDSA(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	err := runCACreate(context.Background(), "Test ECDSA CA", dbPath, "", 365, "ecdsa", 0, "P-384")
	if err != nil {
		t.Fatalf("runCACreate() error = %v", err)
	}

	ca, key := loadRootCAFromDB(t, dbPath)
	if ca.KeyAlgo != "ecdsa" {
		t.Errorf("KeyAlgo = %q, want %q", ca.KeyAlgo, "ecdsa")
	}

	cert := parseCertPEMFromString(t, ca.CertPem)
	if !cert.IsCA {
		t.Error("cert.IsCA = false, want true")
	}

	block, _ := pem.Decode(key)
	if block == nil {
		t.Fatal("key PEM decode failed")
	}
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParseECPrivateKey error = %v", err)
	}
	if ecKey.Curve.Params().Name != "P-384" {
		t.Errorf("ECDSA curve = %q, want P-384", ecKey.Curve.Params().Name)
	}
}

func TestCACreate_IntermediateDefaultsToRoot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Create root
	err := runCACreate(context.Background(), "Root CA", dbPath, "", 365, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("root runCACreate() error = %v", err)
	}

	// Create intermediate without --ca — should default to root
	err = runCACreate(context.Background(), "Intermediate CA", dbPath, "", 365, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("intermediate runCACreate() error = %v", err)
	}

	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	intCA, err := q.GetCAByCN(context.Background(), "Intermediate CA")
	if err != nil {
		t.Fatalf("GetCAByCN() error = %v", err)
	}
	if !intCA.ParentID.Valid {
		t.Fatal("Intermediate CA should have a parent")
	}

	// Verify it's signed by root
	cert := parseCertPEMFromString(t, intCA.CertPem)
	if cert.Issuer.CommonName != "Root CA" {
		t.Errorf("intermediate issuer = %q, want %q", cert.Issuer.CommonName, "Root CA")
	}
}

func TestCACreate_IntermediateWithExplicitCA(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	err := runCACreate(context.Background(), "Root CA", dbPath, "", 365, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("root error = %v", err)
	}

	err = runCACreate(context.Background(), "Level 1", dbPath, "Root CA", 365, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("level1 error = %v", err)
	}

	// Create off Level 1
	err = runCACreate(context.Background(), "Level 2", dbPath, "Level 1", 365, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("level2 error = %v", err)
	}

	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	l2, err := q.GetCAByCN(context.Background(), "Level 2")
	if err != nil {
		t.Fatalf("GetCAByCN() error = %v", err)
	}

	cert := parseCertPEMFromString(t, l2.CertPem)
	if cert.Issuer.CommonName != "Level 1" {
		t.Errorf("Level 2 issuer = %q, want %q", cert.Issuer.CommonName, "Level 1")
	}
}

func TestCACreate_InvalidAlgo(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := runCACreate(context.Background(), "Bad CA", dbPath, "", 365, "ed25519", 0, "")
	if err == nil {
		t.Fatal("runCACreate(ed25519) expected error, got nil")
	}
}

func TestCACreate_RSAKeyTooSmall(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := runCACreate(context.Background(), "Weak CA", dbPath, "", 365, "rsa", 1024, "")
	if err == nil {
		t.Fatal("runCACreate(rsa 1024) expected error, got nil")
	}
}

func TestCACreate_InvalidCurve(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := runCACreate(context.Background(), "Bad CA", dbPath, "", 365, "ecdsa", 0, "P-999")
	if err == nil {
		t.Fatal("runCACreate(P-999) expected error, got nil")
	}
}

func TestCACreate_CertProperties(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	err := runCACreate(context.Background(), "Prop CA", dbPath, "", 730, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("runCACreate() error = %v", err)
	}

	ca, _ := loadRootCAFromDB(t, dbPath)
	cert := parseCertPEMFromString(t, ca.CertPem)

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("cert missing KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("cert missing KeyUsageCRLSign")
	}

	duration := cert.NotAfter.Sub(cert.NotBefore)
	days := int(duration.Hours() / 24)
	if days < 729 || days > 731 {
		t.Errorf("validity = %d days, want ~730", days)
	}
}

func TestCACreate_CobraCommand(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	root := NewRoot("test", "test")
	root.SetArgs([]string{"ca", "create", "--cn", "Cobra CA", "--db", dbPath, "--key-size", "2048"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	ca, _ := loadRootCAFromDB(t, dbPath)
	if ca.CommonName != "Cobra CA" {
		t.Errorf("CommonName = %q, want %q", ca.CommonName, "Cobra CA")
	}
}

func TestCACreate_CobraMissingCN(t *testing.T) {
	root := NewRoot("test", "test")
	root.SetArgs([]string{"ca", "create", "--db", filepath.Join(t.TempDir(), "test.db")})
	if err := root.Execute(); err == nil {
		t.Fatal("Execute() without --cn expected error, got nil")
	}
}

func TestGenerateKey_RSA(t *testing.T) {
	priv, keyPEM, err := generateKey("rsa", 2048, "")
	if err != nil {
		t.Fatalf("generateKey(rsa) error = %v", err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		t.Errorf("generateKey(rsa) returned %T, want *rsa.PrivateKey", priv)
	}
	if len(keyPEM) == 0 {
		t.Error("generateKey(rsa) returned empty PEM")
	}
}

func TestGenerateKey_ECDSA(t *testing.T) {
	priv, keyPEM, err := generateKey("ecdsa", 0, "P-256")
	if err != nil {
		t.Fatalf("generateKey(ecdsa) error = %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Errorf("generateKey(ecdsa) returned %T, want *ecdsa.PrivateKey", priv)
	}
	if len(keyPEM) == 0 {
		t.Error("generateKey(ecdsa) returned empty PEM")
	}
}

// Helpers

func loadRootCAFromDB(t *testing.T, dbPath string) (store.Ca, []byte) {
	t.Helper()
	ctx := context.Background()

	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	ca, err := q.GetRootCA(ctx)
	if err != nil {
		t.Fatalf("GetRootCA() error = %v", err)
	}

	key, err := q.LoadKey(ctx, ca.Serial)
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}

	return ca, key
}

func parseCertPEMFromString(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("cert PEM decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate error = %v", err)
	}
	return cert
}
