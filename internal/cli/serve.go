package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bejelith/gossl/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func newServeCmd() *cobra.Command {
	var (
		db             string
		dn             string
		certF          string
		pkeyF          string
		addr           string
		port           int
		metricsHandler string
		mtls           bool
		verbose        bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start an HTTPS echo server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if (db != "" && dn != "") && (certF != "" || pkeyF != "") {
				return fmt.Errorf("--db/--dn and --cert/--pkey are mutually exclusive")
			}
			if certF != "" || pkeyF != "" {
				if certF == "" || pkeyF == "" {
					return fmt.Errorf("both --cert and --pkey are required")
				}
				return runServeFile(cmd.Context(), certF, pkeyF, addr, port, metricsHandler, mtls, verbose)
			}
			if dn == "" {
				return fmt.Errorf("provide --dn (with --db) or --cert/--pkey")
			}
			return runServeDB(cmd.Context(), db, dn, addr, port, metricsHandler, mtls, verbose)
		},
	}

	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&dn, "dn", "", "Certificate common name from the database")
	cmd.Flags().StringVar(&certF, "cert", "", "Certificate PEM file")
	cmd.Flags().StringVar(&pkeyF, "pkey", "", "Private key PEM file")
	cmd.Flags().StringVar(&addr, "addr", "0.0.0.0", "Listen address (e.g. 127.0.0.1, 0.0.0.0)")
	cmd.Flags().IntVar(&port, "port", 8443, "Listen port")
	cmd.Flags().StringVar(&metricsHandler, "metrics-handler", "/metrics", "Path for metrics (e.g. /metrics, /metrics/prometheus), seto to empty string to disable")
	cmd.Flags().BoolVar(&mtls, "mtls", false, "Require and verify client certificates")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Include request headers in response")

	return cmd
}

func runServeDB(ctx context.Context, dbPath, dn, addr string, port int, metricsHandler string, mtls, verbose bool) error {
	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())

	certRow, err := q.GetCertByCN(ctx, dn)
	if err != nil {
		return fmt.Errorf("certificate %q not found", dn)
	}

	keyPEM, err := q.LoadKey(ctx, certRow.Serial)
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair([]byte(certRow.CertPem), keyPEM)
	if err != nil {
		return fmt.Errorf("loading TLS keypair: %w", err)
	}

	// Load all CAs for mTLS verification
	var clientCAs *x509.CertPool
	if mtls {
		clientCAs = x509.NewCertPool()
		cas, err := q.ListCAs(ctx)
		if err == nil {
			for _, c := range cas {
				clientCAs.AppendCertsFromPEM([]byte(c.CertPem))
			}
		}
	}

	return startServer(tlsCert, clientCAs, addr, port, metricsHandler, mtls, verbose)
}

func runServeFile(_ context.Context, certFile, pkeyFile, addr string, port int, metricsHandler string, mtls, verbose bool) error {
	tlsCert, err := tls.LoadX509KeyPair(certFile, pkeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS keypair: %w", err)
	}

	var clientCAs *x509.CertPool
	if mtls {
		clientCAs, err = x509.SystemCertPool()
		if err != nil {
			clientCAs = x509.NewCertPool()
		}
	}

	return startServer(tlsCert, clientCAs, addr, port, metricsHandler, mtls, verbose)
}

type stateEntry struct {
	cs http.ConnState
	lastActivity time.Time
}

type LatencyTracker struct {
	mu                sync.RWMutex
	states            map[net.Conn]*stateEntry
	connSetupDuration otelmetric.Float64Histogram
}

func newLatencyTracker(mp *sdkmetric.MeterProvider) (*LatencyTracker, error) {
	meter := mp.Meter("gossl")
	h, err := meter.Float64Histogram("gossl.conn.setup.duration",
		otelmetric.WithUnit("ns"),
		otelmetric.WithDescription("Time from new connection to first active state (TLS handshake)."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating histogram: %w", err)
	}
	return &LatencyTracker{
		states:            make(map[net.Conn]*stateEntry),
		connSetupDuration: h,
	}, nil
}

func initMeter() (*sdkmetric.MeterProvider, http.Handler, error) {
	reg := prometheus.NewRegistry()
	exporter, err := otelprometheus.New(otelprometheus.WithRegisterer(reg))
	if err != nil {
		return nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	return mp, handler, nil
}

func (lt *LatencyTracker) track(c net.Conn, cs http.ConnState) {
	now := time.Now()
	var entry *stateEntry
	var found bool
	switch cs {
	case http.StateNew:
		entry = &stateEntry{
			cs: cs,
			lastActivity: now,
		}
		lt.mu.Lock()
		lt.states[c] = entry
		lt.mu.Unlock()
	case http.StateActive: 
		lt.mu.RLock()
		entry, found = lt.states[c]
		lt.mu.RUnlock()
		if !found {
			return
		}
		if entry.cs == http.StateNew {
			lt.connSetupDuration.Record(context.Background(),
				float64(now.Sub(entry.lastActivity).Nanoseconds()),
				otelmetric.WithAttributes(attribute.String("transport", "tls")),
			)
		}
		lt.remove(c)
	case http.StateClosed:
		lt.remove(c)
	}
}

func (lt *LatencyTracker) remove(c net.Conn) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.states, c)
}

func startServer(cert tls.Certificate, clientCAs *x509.CertPool, addr string, port int, metricsHandler string, mtls, verbose bool) error {
	mp, metricsHTTP, err := initMeter()
	if err != nil {
		return err
	}
	defer mp.Shutdown(context.Background())

	lt, err := newLatencyTracker(mp)
	if err != nil {
		return err
	}

	clientAuth := tls.NoClientCert
	if mtls {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
	}

	mux := &http.ServeMux{}
	mux.HandleFunc("/", echoHandler(verbose))
	
	server := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", addr, port),
		Handler:   mux,
		TLSConfig: tlsConf,
		ConnState: lt.track,
	}

	if metricsHandler != "" {
		mux.Handle(metricsHandler, metricsHTTP)
		server.ConnState = lt.track
	}

	fmt.Printf("Listening on https://%s:%d", addr, port)
	if mtls {
		fmt.Print(" (mTLS enabled)")
	}
	fmt.Println()

	return server.ListenAndServeTLS("", "")
}

type echoResponse struct {
	URI     string            `json:"uri"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Form    map[string]string `json:"form,omitempty"`
	Body    string            `json:"body,omitempty"`
	Peer    *peerInfo         `json:"peer,omitempty"`
}

type peerInfo struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Serial  string `json:"serial"`
	Expiry  string `json:"expiry"`
}

func echoHandler(verbose bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := echoResponse{
			URI:    r.RequestURI,
			Method: r.Method,
		}

		if verbose {
			resp.Headers = make(map[string]string)
			for k, v := range r.Header {
				resp.Headers[k] = strings.Join(v, ",")
			}
		}

		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer := r.TLS.PeerCertificates[0]
			resp.Peer = &peerInfo{
				Subject: peer.Subject.String(),
				Issuer:  peer.Issuer.String(),
				Serial:  fmt.Sprintf("%X", peer.SerialNumber),
				Expiry:  peer.NotAfter.Format(time.RFC3339),
			}
		}
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		if _, err := io.Copy(w, r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
