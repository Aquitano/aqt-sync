package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadTLSSettings(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr bool
		enabled bool
	}{
		{name: "plain", env: nil, enabled: false},
		{
			name:    "static ok",
			env:     map[string]string{"AQT_TLS_CERT": "c.pem", "AQT_TLS_KEY": "k.pem"},
			enabled: true,
		},
		{
			name:    "cert without key",
			env:     map[string]string{"AQT_TLS_CERT": "c.pem"},
			wantErr: true,
		},
		{
			name:    "key without cert",
			env:     map[string]string{"AQT_TLS_KEY": "k.pem"},
			wantErr: true,
		},
		{
			name:    "autocert ok",
			env:     map[string]string{"AQT_TLS_AUTOCERT_DOMAINS": "aqt.example.com"},
			enabled: true,
		},
		{
			name: "static and autocert conflict",
			env: map[string]string{
				"AQT_TLS_CERT": "c.pem", "AQT_TLS_KEY": "k.pem",
				"AQT_TLS_AUTOCERT_DOMAINS": "aqt.example.com",
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"AQT_TLS_CERT", "AQT_TLS_KEY", "AQT_TLS_AUTOCERT_DOMAINS", "AQT_TLS_AUTOCERT_CACHE", "AQT_TLS_AUTOCERT_EMAIL"} {
				t.Setenv(k, tc.env[k])
			}
			s, err := loadTLSSettings()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s.enabled() != tc.enabled {
				t.Fatalf("enabled() = %v, want %v", s.enabled(), tc.enabled)
			}
		})
	}
}

// TestServeTLSRoundTrip proves the static-cert path actually terminates TLS: a
// client that trusts the generated cert completes an HTTPS request against a
// server started through serveListenerLifecycle, and a context cancel shuts it down cleanly.
func TestServeTLSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedCert(t)
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	s := tlsSettings{certFile: certFile, keyFile: keyFile}
	cfg, err := s.tlsConfig(dir)
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("tlsConfig returned nil for a static-cert setting")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{Handler: mux}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveListenerLifecycle(ctx, srv, ln, cfg, shutdownGrace, nil, nil) }()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add cert to pool")
	}
	// ForceAttemptHTTP2 makes the client offer "h2" via ALPN. The server advertises
	// h2 (autocert's config does), so it must actually speak it: if TLS were served
	// via a hand-wrapped Serve (no HTTP/2 setup) this request would break.
	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true},
	}
	url := "https://" + ln.Addr().String() + "/healthz"
	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("connection was not over TLS")
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 negotiation, got %s (server did not enable h2)", resp.Proto)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveListenerLifecycle returned %v on graceful shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveListenerLifecycle did not return after context cancel")
	}
}

// TestServeListenerReportsServeError checks the non-signal exit: if the underlying
// server fails, serveListenerLifecycle surfaces the error instead of hanging.
func TestServeListenerReportsServeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // Serve on a closed listener returns immediately

	srv := &http.Server{Handler: http.NewServeMux()}
	errCh := make(chan error, 1)
	go func() { errCh <- serveListenerLifecycle(context.Background(), srv, ln, nil, shutdownGrace, nil, nil) }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected a serve error from a closed listener")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveListenerLifecycle hung on a serve error")
	}
}

type orderedCloseListener struct {
	net.Listener
	seq        *atomic.Int64
	closeOrder atomic.Int64
}

func (l *orderedCloseListener) Close() error {
	l.closeOrder.Store(l.seq.Add(1))
	return l.Listener.Close()
}

// Readiness must flip before http.Server.Shutdown closes the listener. Starting a
// goroutine that will eventually flip it is not sufficient: the waiting goroutine
// can close the listener as soon as it is unblocked.
func TestServeListenerMarksUnreadyBeforeClosingListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var seq atomic.Int64
	ln := &orderedCloseListener{Listener: raw, seq: &seq}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var readyOrder atomic.Int64
	go func() {
		done <- serveListenerLifecycle(ctx, srv, ln, nil, time.Second, func() {
			readyOrder.Store(seq.Add(1))
		}, nil)
	}()

	resp, err := (&http.Client{Timeout: time.Second}).Get("http://" + raw.Addr().String())
	if err != nil {
		t.Fatalf("server did not start: %v", err)
	}
	resp.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveListenerLifecycle: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveListenerLifecycle did not return after cancellation")
	}
	if readyOrder.Load() == 0 {
		t.Fatal("shutdown did not mark readiness false")
	}
	if ln.closeOrder.Load() <= readyOrder.Load() {
		t.Fatalf("listener close order %d did not follow readiness order %d", ln.closeOrder.Load(), readyOrder.Load())
	}
}

func selfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestValidateListenAddressRequiresTLSOrExplicitOverride(t *testing.T) {
	cases := []struct {
		addr                string
		tls, allow, wantErr bool
	}{
		{"127.0.0.1:8080", false, false, false},
		{"0.0.0.0:8080", false, false, true},
		{":443", false, false, true},
		{"0.0.0.0:443", true, false, false},
		{"0.0.0.0:8080", false, true, false},
		{"not-an-address", true, false, true},
	}
	for _, tc := range cases {
		err := validateListenAddress(tc.addr, tc.tls, tc.allow)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateListenAddress(%q, tls=%v, allow=%v) = %v", tc.addr, tc.tls, tc.allow, err)
		}
	}
}

func TestLoadServerConfigRejectsTyposAndNegativeValues(t *testing.T) {
	cases := []struct{ key, value string }{
		{"AQT_REGISTRATION", "invte"},
		{"AQT_QUOTA_BYTES", "-1"},
		{"AQT_MAX_RESOURCES", "-1"},
		{"AQT_AUTH_RATE", "-0.1"},
		{"AQT_TRUSTED_PROXIES", "not-a-proxy"},
		{"AQT_MAX_OBJECTS", "lots"},
	}
	keys := []string{"AQT_REGISTRATION", "AQT_INVITE_TOKENS", "AQT_QUOTA_BYTES", "AQT_MAX_DEVICES", "AQT_MAX_RESOURCES", "AQT_MAX_SNAPSHOTS", "AQT_MAX_OBJECTS", "AQT_AUTH_RATE", "AQT_AUTH_BURST", "AQT_TRUSTED_PROXIES"}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			for _, key := range keys {
				t.Setenv(key, "")
			}
			t.Setenv(tc.key, tc.value)
			if _, err := loadServerConfig(); err == nil {
				t.Fatal("expected actionable config error")
			}
		})
	}
}

func TestEnvDurationValueRejectsInvalidAndNegative(t *testing.T) {
	for _, value := range []string{"tomorrow", "-1s"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("AQT_TEST_DURATION", value)
			if _, err := envDurationValue("AQT_TEST_DURATION", "1s", true); err == nil {
				t.Fatal("expected duration error")
			}
		})
	}
	t.Setenv("AQT_TEST_DURATION", "0")
	if _, err := envDurationValue("AQT_TEST_DURATION", "1s", false); err == nil {
		t.Fatal("zero shutdown grace was accepted")
	}
}
