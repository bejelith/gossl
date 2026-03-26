//go:build integration

package system

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/bejelith/gossl/internal/cli"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestSClient_InspectNginx(t *testing.T) {
	ctx := context.Background()
	dbPath, serverCertPath, serverKeyPath, caBundlePath := setupNginxTLS(t, "SClient Root CA", "SClient Intermediate")
	tmpDir := filepath.Dir(serverCertPath)

	// Issue client cert for mTLS sclient test
	gossl(t, "cert", "issue", "--cn", "sclient-user", "--db", dbPath, "--key-size", "2048")
	clientSerial := getCertSerial(t, dbPath, "sclient-user")
	clientCertPath := filepath.Join(tmpDir, "client.pem")
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")
	gossl(t, "cert", "export", "--serial", clientSerial, "--db", dbPath, "--out", clientCertPath, "--chain")
	exportKey(t, dbPath, clientSerial, clientKeyPath)

	nginxConf := filepath.Join(tmpDir, "nginx.conf")
	writeFile(t, nginxConf, `
events {}
http {
    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/certs/server.pem;
        ssl_certificate_key /etc/nginx/certs/server-key.pem;
        location / { return 200 "ok\n"; }
    }
    server {
        listen 8443 ssl;
        ssl_certificate /etc/nginx/certs/server.pem;
        ssl_certificate_key /etc/nginx/certs/server-key.pem;
        ssl_client_certificate /etc/nginx/certs/ca-bundle.pem;
        ssl_verify_client on;
        location / { return 200 "mtls ok\n"; }
    }
}
`)

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "nginx:alpine",
			ExposedPorts: []string{"443/tcp", "8443/tcp"},
			WaitingFor:   wait.ForListeningPort("443/tcp").WithStartupTimeout(30 * time.Second),
			Files: []testcontainers.ContainerFile{
				{HostFilePath: serverCertPath, ContainerFilePath: "/etc/nginx/certs/server.pem"},
				{HostFilePath: serverKeyPath, ContainerFilePath: "/etc/nginx/certs/server-key.pem"},
				{HostFilePath: caBundlePath, ContainerFilePath: "/etc/nginx/certs/ca-bundle.pem"},
				{HostFilePath: nginxConf, ContainerFilePath: "/etc/nginx/nginx.conf"},
			},
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("starting nginx container: %v", err)
	}
	defer container.Terminate(ctx)

	tlsPort, _ := container.MappedPort(ctx, "443")
	mtlsPort, _ := container.MappedPort(ctx, "8443")
	host, _ := container.Host(ctx)

	t.Run("basic", func(t *testing.T) {
		cmd := cli.NewRoot("test", "test")
		cmd.SetArgs([]string{"sclient", fmt.Sprintf("%s:%s", host, tlsPort.Port()), "--sni", "localhost"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("sclient: %v", err)
		}
	})

	t.Run("custom_ca_verify", func(t *testing.T) {
		cmd := cli.NewRoot("test", "test")
		cmd.SetArgs([]string{"sclient", fmt.Sprintf("%s:%s", host, tlsPort.Port()), "--sni", "localhost", "--ca-file", caBundlePath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("sclient --ca-file: %v", err)
		}
	})

	t.Run("show_certs", func(t *testing.T) {
		cmd := cli.NewRoot("test", "test")
		cmd.SetArgs([]string{"sclient", fmt.Sprintf("%s:%s", host, tlsPort.Port()), "--sni", "localhost", "--show-certs"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("sclient --show-certs: %v", err)
		}
	})

	t.Run("mtls_client_cert", func(t *testing.T) {
		cmd := cli.NewRoot("test", "test")
		cmd.SetArgs([]string{
			"sclient", fmt.Sprintf("%s:%s", host, mtlsPort.Port()),
			"--sni", "localhost",
			"--cert", clientCertPath,
			"--key", clientKeyPath,
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("sclient --cert --key: %v", err)
		}
	})
}
