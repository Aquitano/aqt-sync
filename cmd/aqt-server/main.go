// SPDX-License-Identifier: AGPL-3.0-or-later

// Command aqt-server runs the aqt zero-knowledge sync API.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/server"
)

// version is reported by `aqt-server version` and logged at startup, overridable at
// build time via -ldflags "-X main.version=...". The release workflow passes that
// flag to every shipped binary, but the linker drops it for a package that declares
// no such variable, so until this existed a running server could not say which
// release it was. The default names no release on purpose: claiming a version this
// build is not is worse than admitting it has none.
var version = "dev"

// buildKind records where this binary came from; the release workflow stamps
// "release" on a tagged build. An untagged build takes its version from
// `git describe`, which reads like a release at a glance, so anything that is not
// one says so rather than being left to look official. Overridable at build time via
// -ldflags "-X main.buildKind=release", so the value stays a plain string literal.
var buildKind = "dev"

// versionString is this build's release, with a non-release build marked as such.
func versionString() string {
	if buildKind == "release" {
		return version
	}
	return version + " (" + buildKind + " build)"
}

func main() {
	// `aqt-server admin ...` is operator tooling against the data dir, not a server
	// run, and `version` answers which release a binary is without starting it.
	// Everything else, including no arguments at all, starts the server exactly as
	// before, so existing systemd units and container commands are unaffected.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "admin":
			os.Exit(runAdmin(os.Args[1:]))
		case "version", "--version", "-v":
			fmt.Println("aqt-server " + versionString())
			os.Exit(0)
		}
	}
	os.Exit(run())
}

// run starts the server and returns the process exit code. Every failure to serve
// returns non-zero: a supervisor (the systemd unit ships Restart=on-failure) must be
// able to tell a port conflict or a lost CAP_NET_BIND_SERVICE from a clean shutdown,
// and an exit code of 0 makes it treat a server that never came up as an intentional
// stop and never restart it.
func run() int {
	// First line of the log, so a start that dies before the listener is still
	// attributable to a build — which release is running is the first question a
	// lockstep upgrade asks.
	log.Printf("aqt-server %s", versionString())
	rt, err := loadRuntime()
	if err != nil {
		log.Printf("%v", err)
		return 1
	}
	if rt.Debug == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	return serve(rt)
}

// environment is every variable the server reads. docs/deploy.md is the reference
// for each of them.
type environment struct {
	DataDir            string                  `env:"AQT_DATA_DIR" envDefault:"./aqt-data"`
	Addr               string                  `env:"AQT_ADDR" envDefault:"127.0.0.1:8080"`
	Debug              string                  `env:"AQT_DEBUG"`
	TLSCert            string                  `env:"AQT_TLS_CERT"`
	TLSKey             string                  `env:"AQT_TLS_KEY"`
	TLSAutocertDomains string                  `env:"AQT_TLS_AUTOCERT_DOMAINS"`
	TLSAutocertCache   string                  `env:"AQT_TLS_AUTOCERT_CACHE"`
	TLSAutocertEmail   string                  `env:"AQT_TLS_AUTOCERT_EMAIL"`
	AllowInsecureHTTP  string                  `env:"AQT_ALLOW_INSECURE_HTTP"`
	Registration       server.RegistrationMode `env:"AQT_REGISTRATION" envDefault:"open"`
	InviteTokens       string                  `env:"AQT_INVITE_TOKENS"`
	QuotaBytes         int64                   `env:"AQT_QUOTA_BYTES"`
	MaxResources       int                     `env:"AQT_MAX_RESOURCES"`
	MaxSnapshots       int                     `env:"AQT_MAX_SNAPSHOTS"`
	MaxObjects         int                     `env:"AQT_MAX_OBJECTS"`
	MaxDevices         int                     `env:"AQT_MAX_DEVICES"`
	AuthRate           float64                 `env:"AQT_AUTH_RATE"`
	AuthBurst          int                     `env:"AQT_AUTH_BURST"`
	TrustedProxies     string                  `env:"AQT_TRUSTED_PROXIES" envDefault:"127.0.0.1,::1"`
	SnapshotInterval   time.Duration           `env:"AQT_SNAPSHOT_INTERVAL" envDefault:"24h"`
	SnapshotKeep       int                     `env:"AQT_SNAPSHOT_KEEP" envDefault:"30"`
	GCInterval         time.Duration           `env:"AQT_GC_INTERVAL" envDefault:"6h"`
	ShutdownGrace      time.Duration           `env:"AQT_SHUTDOWN_GRACE" envDefault:"20s"`
	MetricsAddr        string                  `env:"AQT_METRICS_ADDR"`
	SourceURL          string                  `env:"AQT_SOURCE_URL"`
}

// On error the result still holds every field that parsed; the admin commands
// rely on that to tolerate an unrelated malformed variable.
func loadEnvironment() (environment, error) {
	return env.ParseAsWithOptions[environment](env.Options{
		FuncMap: map[reflect.Type]env.ParserFunc{
			// env parses int as 32-bit, which would reject quotas above 2^31.
			reflect.TypeFor[int](): func(v string) (any, error) { return strconv.Atoi(v) },
		},
	})
}

// runtimeConfig is everything a server run takes from the environment.
type runtimeConfig struct {
	environment
	serverConfig server.Config
	tlsConfig    *tls.Config
}

// loadRuntime resolves and validates the environment before anything is opened or
// bound. Its errors are already phrased for the operator log, so the caller reports
// them as they are.
func loadRuntime() (runtimeConfig, error) {
	e, err := loadEnvironment()
	if err != nil {
		return runtimeConfig{}, err
	}
	rt := runtimeConfig{environment: e}

	if rt.serverConfig, err = loadServerConfig(e); err != nil {
		return runtimeConfig{}, fmt.Errorf("server config: %w", err)
	}

	// A snapshot is keyless (it copies already-sealed ciphertext), so the server runs
	// the job itself. AQT_SNAPSHOT_KEEP caps how many scheduled snapshots each resource
	// retains so storage converges; manual snapshots are never pruned.
	if e.SnapshotInterval < 0 {
		return runtimeConfig{}, fmt.Errorf("invalid AQT_SNAPSHOT_INTERVAL %q: expected a non-negative duration", e.SnapshotInterval)
	}
	if e.SnapshotKeep < 0 {
		return runtimeConfig{}, fmt.Errorf("invalid AQT_SNAPSHOT_KEEP: %d", e.SnapshotKeep)
	}

	// Scheduled maintenance: link expiry (retire or reclaim, per the resource's
	// on_expiry) and pack tidying. Clients trigger the same pass after a sync, and
	// this timer covers an account whose devices have stopped. Expiry is the server's
	// own decision; pack tidying is not — it sweeps emptied packs and compacts sparse
	// ones, but only ever after an `aqt prune` deleted the object rows, since the
	// server cannot see which objects a resource references.
	if e.GCInterval < 0 {
		return runtimeConfig{}, fmt.Errorf("invalid AQT_GC_INTERVAL %q: expected a non-negative duration", e.GCInterval)
	}

	// The metrics enumerate opaque per-account owner handles and storage totals, so
	// the endpoint belongs on a loopback or private interface, never on AQT_ADDR.
	if e.MetricsAddr != "" {
		if err := validateListenAddress(e.MetricsAddr, true, true); err != nil {
			return runtimeConfig{}, fmt.Errorf("metrics address: %w", err)
		}
	}

	tlsSet, err := loadTLSSettings(e)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("tls config: %w", err)
	}
	if rt.tlsConfig, err = tlsSet.tlsConfig(e.DataDir); err != nil {
		return runtimeConfig{}, fmt.Errorf("tls config: %w", err)
	}
	if err := validateListenAddress(e.Addr, rt.tlsConfig != nil, e.AllowInsecureHTTP == "1"); err != nil {
		return runtimeConfig{}, fmt.Errorf("listen address: %w", err)
	}

	if e.ShutdownGrace <= 0 {
		return runtimeConfig{}, fmt.Errorf("invalid AQT_SHUTDOWN_GRACE %q: expected a positive duration", e.ShutdownGrace)
	}
	return rt, nil
}

// serve opens the store, starts the background jobs and runs the API until shutdown,
// returning the process exit code. Returning rather than calling log.Fatal lets the
// deferred store.Close run, so the SQLite WAL is checkpointed on the way out.
func serve(rt runtimeConfig) (code int) {
	store, err := server.OpenStore(rt.DataDir)
	if err != nil {
		log.Printf("open store: %v", err)
		return 1
	}
	// A close that fails is an unclean database shutdown — the WAL checkpoint did not
	// land — which is exactly as invisible to a supervisor at exit 0 as the serve
	// failure this function exists to report. It never downgrades an existing failure.
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("close store: %v", err)
			if code == 0 {
				code = 1
			}
		}
	}()

	api := server.NewWithConfig(store, rt.serverConfig)
	workerStop := make(chan struct{})
	if rt.SnapshotInterval > 0 {
		log.Printf("scheduled snapshots every %s (keeping last %d per resource; 0 = all)", rt.SnapshotInterval, rt.SnapshotKeep)
		api.StartAutoSnapshot(rt.SnapshotInterval, rt.SnapshotKeep, workerStop)
	}
	if rt.GCInterval > 0 {
		log.Printf("scheduled gc every %s", rt.GCInterval)
		api.StartGC(rt.GCInterval, workerStop)
	}

	// Keeping the metrics endpoint a separate plain-HTTP server makes its binding
	// explicit; see loadRuntime for why it must not share AQT_ADDR.
	var metricsServer *http.Server
	if rt.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", api.MetricsHandler())
		metricsServer = &http.Server{
			Addr:              rt.MetricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Printf("metrics on http://%s/metrics", rt.MetricsAddr)
		go func() {
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics server exited: %v", err)
			}
		}()
	}

	// No ReadTimeout/WriteTimeout: they span the full body transfer, capping a
	// 32 MiB pack at ~4.3 Mbps and permanently failing slower links. Handlers
	// already cap body sizes, ReadHeaderTimeout bounds header slowloris, and
	// IdleTimeout reaps idle keep-alives.
	srv := &http.Server{
		Addr:              rt.Addr,
		Handler:           api.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("data dir: %s", rt.DataDir)
	// serveWithShutdown flips readiness synchronously before closing listeners, then
	// runs the component drain on the same context as HTTP shutdown. The calls after
	// it returns are fallbacks for paths that never entered that drain (a listener that
	// never came up, or a serve error); the Once guards keep them idempotent and avoid
	// consuming a second AQT_SHUTDOWN_GRACE window.
	var (
		readyOnce sync.Once
		stopOnce  sync.Once
		drainOnce sync.Once
		drainErr  error
	)
	beginShutdown := func() { readyOnce.Do(api.BeginShutdown) }
	shutdownComponents := func(ctx context.Context) error {
		drainOnce.Do(func() {
			stopOnce.Do(func() { close(workerStop) })
			if metricsServer != nil {
				_ = metricsServer.Shutdown(ctx)
			}
			drainErr = api.WaitWorkers(ctx)
		})
		return drainErr
	}
	serveErr := serveWithShutdown(srv, rt.tlsConfig, rt.ShutdownGrace, beginShutdown, shutdownComponents)
	beginShutdown()
	ctx, cancel := context.WithTimeout(context.Background(), rt.ShutdownGrace)
	shutdownErr := shutdownComponents(ctx)
	cancel()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Printf("server exited: %v", serveErr)
		return 1
	}
	// A drain that did not finish inside AQT_SHUTDOWN_GRACE means background work was
	// cut off mid-flight, so it is a failed exit too. systemd tracks stop-was-requested
	// separately from the exit code, so this does not resurrect a `systemctl stop`; it
	// only makes the unit report the truth.
	if shutdownErr != nil {
		log.Printf("shutdown: %v", shutdownErr)
		return 1
	}
	return 0
}

// loadServerConfig builds the hardening config from the environment. Every knob has
// a safe default: open registration, unlimited storage and devices, and
// loopback-only trusted proxies.
func loadServerConfig(e environment) (server.Config, error) {
	proxies := splitCSV(e.TrustedProxies)
	if strings.EqualFold(e.TrustedProxies, "none") {
		proxies = nil
	}
	cfg := server.Config{
		Registration: e.Registration,
		InviteTokens: splitCSV(e.InviteTokens), QuotaBytes: e.QuotaBytes,
		MaxDevices: e.MaxDevices, MaxResources: e.MaxResources, MaxSnapshots: e.MaxSnapshots, MaxObjects: e.MaxObjects,
		AuthedRatePerSec: e.AuthRate, AuthedBurst: e.AuthBurst,
		SourceURL: e.SourceURL,
	}.WithTrustedProxies(proxies)
	if err := cfg.Validate(); err != nil {
		return server.Config{}, err
	}
	return cfg, nil
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
