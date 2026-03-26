package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

func generateKey(algo string, size int, curve string) (any, []byte, error) {
	switch algo {
	case "rsa":
		if size < 2048 {
			return nil, nil, fmt.Errorf("RSA key size %d is below minimum 2048 bits", size)
		}
		key, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return nil, nil, fmt.Errorf("generating RSA key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		return key, keyPEM, nil
	case "ecdsa":
		c, err := parseCurve(curve)
		if err != nil {
			return nil, nil, err
		}
		key, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ECDSA key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("marshalling ECDSA key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		return key, keyPEM, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key algorithm: %s", algo)
	}
}

func parseCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func generateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func serialHex(sn *big.Int) string {
	return fmt.Sprintf("%X", sn)
}

func parsePrivateKey(keyPEM []byte) (any, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

const minRSAKeySize = 2048

// validateCSRKey checks that the CSR's public key meets minimum strength requirements.
func validateCSRKey(csr *x509.CertificateRequest) error {
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSAKeySize {
			return fmt.Errorf("RSA key size %d bits is below minimum %d bits", pub.N.BitLen(), minRSAKeySize)
		}
	case *ecdsa.PublicKey:
		curve := pub.Curve.Params().Name
		switch curve {
		case "P-256", "P-384", "P-521":
			// ok
		default:
			return fmt.Errorf("unsupported ECDSA curve: %s", curve)
		}
	default:
		return fmt.Errorf("unsupported public key algorithm: %T", csr.PublicKey)
	}
	return nil
}

func parseCSRPEMBytes(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	return csr, nil
}

// publicKeyFingerprint returns the SHA-256 fingerprint of a public key as
// "SHA256:" followed by colon-separated lowercase hex bytes.
func publicKeyFingerprint(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(der)
	parts := make([]string, sha256.Size)
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return "SHA256:" + strings.Join(parts, ":")
}

// publicKeyRaw returns the raw public key material as colon-separated uppercase hex.
// For RSA, this is the modulus N. For ECDSA, this is the uncompressed EC point.
func publicKeyRaw(pub any) string {
	var raw []byte
	switch k := pub.(type) {
	case *rsa.PublicKey:
		raw = k.N.Bytes()
	case *ecdsa.PublicKey:
		raw = elliptic.Marshal(k.Curve, k.X, k.Y)
	default:
		return ""
	}
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func parseCertPEMBytes(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
