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
	"strconv"
	"strings"
	"sync"
	"time"

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
	if os.Getenv("AQT_DEBUG") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	rt, err := loadRuntime()
	if err != nil {
		log.Printf("%v", err)
		return 1
	}
	return serve(rt)
}

// runtimeConfig is everything a server run takes from the environment.
type runtimeConfig struct {
	dataDir          string
	addr             string
	serverConfig     server.Config
	snapshotInterval time.Duration
	snapshotKeep     int
	gcInterval       time.Duration
	metricsAddr      string
	tlsConfig        *tls.Config
	shutdownGrace    time.Duration
}

// loadRuntime resolves and validates the environment before anything is opened or
// bound. Its errors are already phrased for the operator log, so the caller reports
// them as they are. docs/deploy.md is the reference for every variable read here.
func loadRuntime() (runtimeConfig, error) {
	rt := runtimeConfig{
		dataDir: envOr("AQT_DATA_DIR", "./aqt-data"),
		addr:    envOr("AQT_ADDR", "127.0.0.1:8080"),
	}

	cfg, err := loadServerConfig()
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("server config: %w", err)
	}
	rt.serverConfig = cfg

	// A snapshot is keyless (it copies already-sealed ciphertext), so the server runs
	// the job itself. AQT_SNAPSHOT_KEEP caps how many scheduled snapshots each resource
	// retains so storage converges; manual snapshots are never pruned.
	if rt.snapshotInterval, err = envDurationValue("AQT_SNAPSHOT_INTERVAL", "24h", true); err != nil {
		return runtimeConfig{}, err
	}
	rawKeep := envOr("AQT_SNAPSHOT_KEEP", "30")
	keep, err := strconv.Atoi(rawKeep)
	if err != nil || keep < 0 {
		return runtimeConfig{}, fmt.Errorf("invalid AQT_SNAPSHOT_KEEP: %s", rawKeep)
	}
	rt.snapshotKeep = keep

	// Scheduled maintenance: link expiry (retire or reclaim, per the resource's
	// on_expiry) and pack tidying. Clients trigger the same pass after a sync, and
	// this timer covers an account whose devices have stopped. Expiry is the server's
	// own decision; pack tidying is not — it sweeps emptied packs and compacts sparse
	// ones, but only ever after an `aqt prune` deleted the object rows, since the
	// server cannot see which objects a resource references.
	if rt.gcInterval, err = envDurationValue("AQT_GC_INTERVAL", "6h", true); err != nil {
		return runtimeConfig{}, err
	}

	// The metrics enumerate opaque per-account owner handles and storage totals, so
	// the endpoint belongs on a loopback or private interface, never on AQT_ADDR.
	if rt.metricsAddr = os.Getenv("AQT_METRICS_ADDR"); rt.metricsAddr != "" {
		if err := validateListenAddress(rt.metricsAddr, true, true); err != nil {
			return runtimeConfig{}, fmt.Errorf("metrics address: %w", err)
		}
	}

	tlsSet, err := loadTLSSettings()
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("tls config: %w", err)
	}
	if rt.tlsConfig, err = tlsSet.tlsConfig(rt.dataDir); err != nil {
		return runtimeConfig{}, fmt.Errorf("tls config: %w", err)
	}
	allowInsecure := os.Getenv("AQT_ALLOW_INSECURE_HTTP") == "1"
	if err := validateListenAddress(rt.addr, rt.tlsConfig != nil, allowInsecure); err != nil {
		return runtimeConfig{}, fmt.Errorf("listen address: %w", err)
	}

	if rt.shutdownGrace, err = envDurationValue("AQT_SHUTDOWN_GRACE", shutdownGrace.String(), false); err != nil {
		return runtimeConfig{}, err
	}
	return rt, nil
}

// serve opens the store, starts the background jobs and runs the API until shutdown,
// returning the process exit code. Returning rather than calling log.Fatal lets the
// deferred store.Close run, so the SQLite WAL is checkpointed on the way out.
func serve(rt runtimeConfig) (code int) {
	store, err := server.OpenStore(rt.dataDir)
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
	if rt.snapshotInterval > 0 {
		log.Printf("scheduled snapshots every %s (keeping last %d per resource; 0 = all)", rt.snapshotInterval, rt.snapshotKeep)
		api.StartAutoSnapshot(rt.snapshotInterval, rt.snapshotKeep, workerStop)
	}
	if rt.gcInterval > 0 {
		log.Printf("scheduled gc every %s", rt.gcInterval)
		api.StartGC(rt.gcInterval, workerStop)
	}

	// Keeping the metrics endpoint a separate plain-HTTP server makes its binding
	// explicit; see loadRuntime for why it must not share AQT_ADDR.
	var metricsServer *http.Server
	if rt.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", api.MetricsHandler())
		metricsServer = &http.Server{
			Addr:              rt.metricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Printf("metrics on http://%s/metrics", rt.metricsAddr)
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
		Addr:              rt.addr,
		Handler:           api.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("data dir: %s", rt.dataDir)
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
	serveErr := serveWithShutdown(srv, rt.tlsConfig, rt.shutdownGrace, beginShutdown, shutdownComponents)
	beginShutdown()
	ctx, cancel := context.WithTimeout(context.Background(), rt.shutdownGrace)
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

// loadServerConfig builds the hardening config from env vars. Every knob has a safe
// default: open registration, unlimited storage and devices, and loopback-only
// trusted proxies.
//
//	AQT_REGISTRATION     open (default) | invite
//	AQT_INVITE_TOKENS    comma-separated invite secrets (invite mode only)
//	AQT_QUOTA_BYTES      per-owner physical storage cap; 0 (default) = unlimited
//	AQT_MAX_DEVICES      per-account device cap; 0 (default) = unlimited
//	AQT_AUTH_RATE        per-token authed requests/sec; 0 = package default
//	AQT_AUTH_BURST       per-token authed burst; 0 = package default
//	AQT_TRUSTED_PROXIES  comma-separated proxy CIDRs/hosts whose X-Forwarded-* is
//	                     trusted; unset = loopback only; "none" = trust none
//	AQT_SOURCE_URL       source link the share page offers; set it when running
//	                     modified code
func loadServerConfig() (server.Config, error) {
	quota, err := envInt64Value("AQT_QUOTA_BYTES")
	if err != nil {
		return server.Config{}, err
	}
	maxDevices, err := envIntValue("AQT_MAX_DEVICES")
	if err != nil {
		return server.Config{}, err
	}
	maxResources, err := envIntValue("AQT_MAX_RESOURCES")
	if err != nil {
		return server.Config{}, err
	}
	maxSnapshots, err := envIntValue("AQT_MAX_SNAPSHOTS")
	if err != nil {
		return server.Config{}, err
	}
	maxObjects, err := envIntValue("AQT_MAX_OBJECTS")
	if err != nil {
		return server.Config{}, err
	}
	rate, err := envFloatValue("AQT_AUTH_RATE")
	if err != nil {
		return server.Config{}, err
	}
	burst, err := envFloatValue("AQT_AUTH_BURST")
	if err != nil {
		return server.Config{}, err
	}
	cfg := server.Config{
		Registration: server.RegistrationMode(envOr("AQT_REGISTRATION", string(server.RegistrationOpen))),
		InviteTokens: splitCSV(os.Getenv("AQT_INVITE_TOKENS")), QuotaBytes: quota,
		MaxDevices: maxDevices, MaxResources: maxResources, MaxSnapshots: maxSnapshots, MaxObjects: maxObjects,
		AuthedRatePerSec: rate, AuthedBurst: burst,
		SourceURL: os.Getenv("AQT_SOURCE_URL"),
	}
	switch raw := os.Getenv("AQT_TRUSTED_PROXIES"); {
	case raw == "":
		cfg = cfg.WithTrustedProxies([]string{"127.0.0.1", "::1"})
	case strings.EqualFold(raw, "none"):
		cfg = cfg.WithTrustedProxies(nil)
	default:
		cfg = cfg.WithTrustedProxies(splitCSV(raw))
	}
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

func envDurationValue(key, fallback string, allowZero bool) (time.Duration, error) {
	raw := envOr(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 || (!allowZero && d == 0) {
		want := "a non-negative duration"
		if !allowZero {
			want = "a positive duration"
		}
		return 0, fmt.Errorf("invalid %s %q: expected %s", key, raw, want)
	}
	return d, nil
}

func envInt64Value(key string) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: expected an integer", key, v)
	}
	return n, nil
}

func envIntValue(key string) (int, error) {
	n, err := envInt64Value(key)
	if err != nil {
		return 0, err
	}
	if int64(int(n)) != n {
		return 0, fmt.Errorf("invalid %s: value is outside integer range", key)
	}
	return int(n), nil
}

func envFloatValue(key string) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: expected a number", key, v)
	}
	return n, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
