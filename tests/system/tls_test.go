//go:build integration

package system

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestTLS_ServerCertVerification(t *testing.T) {
	ctx := context.Background()
	_, serverCertPath, serverKeyPath, caBundlePath := setupNginxTLS(t, "TLS Root CA", "TLS Intermediate")
	tmpDir := filepath.Dir(serverCertPath)

	nginxConf := filepath.Join(tmpDir, "nginx.conf")
	writeFile(t, nginxConf, `
events {}
http {
    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/certs/server.pem;
        ssl_certificate_key /etc/nginx/certs/server-key.pem;

        location / {
            return 200 "TLS OK\n";
            add_header Content-Type text/plain;
        }
    }
}
`)

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "nginx:alpine",
			ExposedPorts: []string{"443/tcp"},
			WaitingFor:   wait.ForListeningPort("443/tcp").WithStartupTimeout(30 * time.Second),
			Files: []testcontainers.ContainerFile{
				{HostFilePath: serverCertPath, ContainerFilePath: "/etc/nginx/certs/server.pem"},
				{HostFilePath: serverKeyPath, ContainerFilePath: "/etc/nginx/certs/server-key.pem"},
				{HostFilePath: nginxConf, ContainerFilePath: "/etc/nginx/nginx.conf"},
			},
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("starting nginx container: %v", err)
	}
	defer container.Terminate(ctx)

	mappedPort, _ := container.MappedPort(ctx, "443")
	host, _ := container.Host(ctx)
	addr := fmt.Sprintf("https://%s:%s", host, mappedPort.Port())

	rootCAs := x509.NewCertPool()
	caPEM, _ := os.ReadFile(caBundlePath)
	rootCAs.AppendCertsFromPEM(caPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				ServerName: "localhost",
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(addr)
	if err != nil {
		t.Fatalf("GET %s: %v", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response: %s", body)
}
