package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
)

func TestPublicKeyFingerprint_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	fp := publicKeyFingerprint(&key.PublicKey)

	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("publicKeyFingerprint() = %q, want SHA256: prefix", fp)
	}

	// Verify it's deterministic.
	fp2 := publicKeyFingerprint(&key.PublicKey)
	if fp != fp2 {
		t.Errorf("publicKeyFingerprint() not deterministic: %q != %q", fp, fp2)
	}

	// Verify format: SHA256: followed by colon-separated lowercase hex bytes.
	rest := strings.TrimPrefix(fp, "SHA256:")
	parts := strings.Split(rest, ":")
	if len(parts) != sha256.Size {
		t.Errorf("publicKeyFingerprint() has %d hex bytes, want %d", len(parts), sha256.Size)
	}
	for _, p := range parts {
		if len(p) != 2 {
			t.Errorf("publicKeyFingerprint() hex byte %q has len %d, want 2", p, len(p))
		}
		if p != strings.ToLower(p) {
			t.Errorf("publicKeyFingerprint() hex byte %q is not lowercase", p)
		}
	}
}

func TestPublicKeyFingerprint_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	fp := publicKeyFingerprint(&key.PublicKey)

	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("publicKeyFingerprint() = %q, want SHA256: prefix", fp)
	}

	fp2 := publicKeyFingerprint(&key.PublicKey)
	if fp != fp2 {
		t.Errorf("publicKeyFingerprint() not deterministic: %q != %q", fp, fp2)
	}
}

func TestPublicKeyFingerprint_MatchesKeyAndCert(t *testing.T) {
	// Generate a key, create a self-signed cert, verify fingerprints match.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: mustGenerateSerial(t),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	keyFP := publicKeyFingerprint(&key.PublicKey)
	certFP := publicKeyFingerprint(cert.PublicKey)

	if keyFP != certFP {
		t.Errorf("fingerprints differ: key=%q cert=%q", keyFP, certFP)
	}
}

func TestPublicKeyFingerprint_DifferentKeysAreDifferent(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	fp1 := publicKeyFingerprint(&key1.PublicKey)
	fp2 := publicKeyFingerprint(&key2.PublicKey)

	if fp1 == fp2 {
		t.Errorf("different keys produced same fingerprint: %q", fp1)
	}
}

func TestPublicKeyRaw_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	raw := publicKeyRaw(&key.PublicKey)

	if raw == "" {
		t.Fatal("publicKeyRaw() returned empty string")
	}

	// Verify format: colon-separated uppercase hex bytes.
	parts := strings.Split(raw, ":")
	for _, p := range parts {
		if len(p) != 2 {
			t.Errorf("publicKeyRaw() hex byte %q has len %d, want 2", p, len(p))
		}
		if p != strings.ToUpper(p) {
			t.Errorf("publicKeyRaw() hex byte %q is not uppercase", p)
		}
	}

	// RSA 2048 modulus is 256 bytes.
	if len(parts) != 256 {
		t.Errorf("publicKeyRaw() has %d bytes, want 256 for RSA 2048", len(parts))
	}
}

func TestPublicKeyRaw_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	raw := publicKeyRaw(&key.PublicKey)

	if raw == "" {
		t.Fatal("publicKeyRaw() returned empty string")
	}

	// P-256 uncompressed point is 65 bytes (0x04 || X || Y).
	parts := strings.Split(raw, ":")
	if len(parts) != 65 {
		t.Errorf("publicKeyRaw() has %d bytes, want 65 for P-256 uncompressed point", len(parts))
	}
}

func TestPublicKeyRaw_MatchesBetweenKeyAndCert(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: mustGenerateSerial(t),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	keyRaw := publicKeyRaw(&key.PublicKey)
	certRaw := publicKeyRaw(cert.PublicKey)

	if keyRaw != certRaw {
		t.Errorf("raw values differ: key=%q cert=%q", keyRaw, certRaw)
	}
}

func mustGenerateSerial(t *testing.T) *big.Int {
	t.Helper()
	sn, err := generateSerial()
	if err != nil {
		t.Fatalf("generateSerial: %v", err)
	}
	return sn
}
