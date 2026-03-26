package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerCheck(t *testing.T) {
	// Start a local TLS server with a self-signed cert
	cert, certPEM, _ := generateSelfSignedCert(t, "localhost")

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port

	go server.ServeTLS(l, "", "")
	defer server.Close()

	waitForServer(t, port)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"sclient", fmt.Sprintf("localhost:%d", port)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("server check: %v", err)
	}

	// Test with custom CA file
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caPath, certPEM, 0644)

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"sclient", fmt.Sprintf("localhost:%d", port), "--ca-file", caPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("server check --ca-file: %v", err)
	}
}

func TestServerCheck_WithSNI(t *testing.T) {
	cert, _, _ := generateSelfSignedCert(t, "custom.example.com")

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port

	go server.ServeTLS(l, "", "")
	defer server.Close()

	waitForServer(t, port)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"sclient", fmt.Sprintf("localhost:%d", port), "--sni", "custom.example.com"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("server check --sni: %v", err)
	}
}

func TestServerCheck_Timeout(t *testing.T) {
	// Use a port that's not listening — should timeout quickly
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"sclient", "localhost:1", "--timeout", "500ms"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("server check unreachable host expected error")
	}
}

func TestServerCheck_DefaultPort(t *testing.T) {
	// host without port should default to :443
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"sclient", "localhost", "--timeout", "500ms"})
	// Will fail to connect but exercises the port-defaulting code path
	cmd.Execute()
}

func generateSelfSignedCert(t *testing.T, cn string) (tls.Certificate, []byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	return tlsCert, certPEM, keyPEM
}
