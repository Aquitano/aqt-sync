// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// tlsSettings selects how the server terminates TLS. The zero value serves plain
// HTTP, for local dev or behind a TLS-terminating reverse proxy. The client
// refuses to send its bearer token over plain HTTP to any non-loopback host, so a
// real offsite deployment must set one of the TLS modes below (or front the server
// with a proxy that adds HTTPS).
//
//	AQT_TLS_CERT / AQT_TLS_KEY        PEM cert + key paths (static certificates)
//	AQT_TLS_AUTOCERT_DOMAINS          comma-separated hostnames -> Let's Encrypt
//	AQT_TLS_AUTOCERT_CACHE            cert cache dir (default <dataDir>/autocert)
//	AQT_TLS_AUTOCERT_EMAIL            optional ACME contact address
type tlsSettings struct {
	certFile string
	keyFile  string

	autocertDomains []string
	autocertCache   string
	autocertEmail   string
}

// loadTLSSettings reads the TLS env vars and validates the combination. A cert
// without its key (or vice versa) is a misconfiguration, and static certs and
// autocert are mutually exclusive, so both are hard errors rather than a silent
// fall back to plaintext.
func loadTLSSettings() (tlsSettings, error) {
	s := tlsSettings{
		certFile:        os.Getenv("AQT_TLS_CERT"),
		keyFile:         os.Getenv("AQT_TLS_KEY"),
		autocertDomains: splitCSV(os.Getenv("AQT_TLS_AUTOCERT_DOMAINS")),
		autocertCache:   os.Getenv("AQT_TLS_AUTOCERT_CACHE"),
		autocertEmail:   os.Getenv("AQT_TLS_AUTOCERT_EMAIL"),
	}
	if (s.certFile == "") != (s.keyFile == "") {
		return tlsSettings{}, errors.New("AQT_TLS_CERT and AQT_TLS_KEY must be set together")
	}
	if s.certFile != "" && len(s.autocertDomains) > 0 {
		return tlsSettings{}, errors.New("set either AQT_TLS_CERT/AQT_TLS_KEY or AQT_TLS_AUTOCERT_DOMAINS, not both")
	}
	return s, nil
}

func (s tlsSettings) enabled() bool {
	return s.certFile != "" || len(s.autocertDomains) > 0
}

// tlsConfig builds the *tls.Config for the selected mode, or nil when TLS is off.
// Static certs are loaded eagerly so a bad path fails startup rather than the first
// handshake; autocert fetches per-host certificates on demand over the TLS-ALPN-01
// challenge, which needs no separate :80 listener as long as the server is reachable
// on :443. dataDir supplies the default autocert cache location.
func (s tlsSettings) tlsConfig(dataDir string) (*tls.Config, error) {
	switch {
	case s.certFile != "":
		cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS keypair: %w", err)
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
	case len(s.autocertDomains) > 0:
		cache := s.autocertCache
		if cache == "" {
			cache = filepath.Join(dataDir, "autocert")
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.autocertDomains...),
			Cache:      autocert.DirCache(cache),
			Email:      s.autocertEmail,
		}
		cfg := m.TLSConfig() // wires GetCertificate and the acme-tls/1 ALPN protocol
		cfg.MinVersion = tls.VersionTLS12
		return cfg, nil
	default:
		return nil, nil
	}
}

func validateListenAddress(addr string, tlsEnabled, allowInsecure bool) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("invalid AQT_ADDR %q: %w", addr, err)
	}
	if tlsEnabled || allowInsecure {
		return nil
	}
	if tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("plain HTTP on non-loopback %q requires AQT_ALLOW_INSECURE_HTTP=1", addr)
	}
	return nil
}

// shutdownGrace bounds how long a SIGINT/SIGTERM lets in-flight requests drain
// before the process exits, so a deploy restart neither hangs nor severs an upload
// mid-write.
const shutdownGrace = 20 * time.Second

// serveWithShutdown binds srv.Addr and runs the server until a termination signal
// arrives. It binds the listener up front (so a port-in-use failure is reported before
// the "listening" log) and returns cleanly on shutdown, so the caller's deferred
// store.Close() actually runs — log.Fatal on the raw ListenAndServe would skip it.
func serveWithShutdown(srv *http.Server, tlsCfg *tls.Config, grace time.Duration, begin func(), drain func(context.Context) error) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveListenerLifecycle(ctx, srv, ln, tlsCfg, grace, begin, drain)
}

// serveListenerLifecycle serves ln until it errors or ctx is cancelled, then drains
// in-flight requests within grace. Splitting the listener and cancellation out of
// serveWithShutdown lets a test drive shutdown without an OS signal, and exercise the
// real TLS handshake over a listener whose ephemeral port it can read back.
//
// The TLS path uses ServeTLS rather than Serve over a hand-wrapped tls.Listener so
// that HTTP/2 is configured (Serve does not auto-enable it) — which matters because
// autocert's TLSConfig advertises "h2" via ALPN; a client that negotiated h2 against
// a server that only speaks HTTP/1.1 would break. ServeTLS also preserves the
// acme-tls/1 challenge protocol needed for autocert issuance.
func serveListenerLifecycle(ctx context.Context, srv *http.Server, ln net.Listener, tlsCfg *tls.Config, grace time.Duration, begin func(), drain func(context.Context) error) error {
	serve := srv.Serve
	scheme := "http"
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
		serve = func(l net.Listener) error { return srv.ServeTLS(l, "", "") }
		scheme = "https"
	}
	log.Printf("aqt-server listening on %s (%s)", ln.Addr(), scheme)

	serveErr := make(chan error, 1)
	go func() { serveErr <- serve(ln) }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Print("shutting down; draining in-flight requests")
		shutCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		// Readiness must fail synchronously before Shutdown closes the listeners.
		// Merely starting a goroutine whose first action flips readiness does not order
		// that action before the close: the scheduler may resume this goroutine as soon
		// as the start signal is sent. Keep the fast readiness transition separate from
		// the potentially blocking component drain below.
		if begin != nil {
			begin()
		}
		errCh := make(chan error, 2)
		n := 1
		if drain != nil {
			n++
			go func() { errCh <- drain(shutCtx) }()
		}
		go func() { errCh <- srv.Shutdown(shutCtx) }()
		var first error
		for range n {
			select {
			case err := <-errCh:
				if first == nil && err != nil {
					first = err
				}
			case <-shutCtx.Done():
				return shutCtx.Err()
			}
		}
		return first
	}
}
