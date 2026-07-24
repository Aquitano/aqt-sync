// Command aqt-server runs the aqt zero-knowledge sync API.
package main

import (
	"context"
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

func main() {
	dataDir := envOr("AQT_DATA_DIR", "./aqt-data")
	addr := envOr("AQT_ADDR", "127.0.0.1:8080")

	if os.Getenv("AQT_DEBUG") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	store, err := server.OpenStore(dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	cfg, err := loadServerConfig()
	if err != nil {
		log.Fatalf("server config: %v", err)
	}
	api := server.NewWithConfig(store, cfg)
	workerStop := make(chan struct{})

	// Scheduled snapshots. A snapshot is keyless (it copies already-sealed
	// ciphertext), so the server runs the job itself; AQT_SNAPSHOT_INTERVAL=0 disables
	// it. Default daily. AQT_SNAPSHOT_KEEP caps how many scheduled snapshots each
	// resource retains (0 keeps all) so storage converges; manual snapshots are
	// never pruned.
	interval, err := envDurationValue("AQT_SNAPSHOT_INTERVAL", "24h", true)
	if err != nil {
		log.Fatalf("%v", err)
	}
	keep, err := strconv.Atoi(envOr("AQT_SNAPSHOT_KEEP", "30"))
	if err != nil || keep < 0 {
		log.Fatalf("invalid AQT_SNAPSHOT_KEEP: %v", envOr("AQT_SNAPSHOT_KEEP", "30"))
	}
	if interval > 0 {
		log.Printf("scheduled snapshots every %s (keeping last %d per resource; 0 = all)", interval, keep)
		api.StartAutoSnapshot(interval, keep, workerStop)
	}

	// Scheduled GC. Clients trigger a sweep after a sync, but an account whose
	// devices stop syncing would otherwise never reclaim space; the server-side
	// timer covers that. AQT_GC_INTERVAL=0 disables it. Default 6h.
	gcInterval, err := envDurationValue("AQT_GC_INTERVAL", "6h", true)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if gcInterval > 0 {
		log.Printf("scheduled gc every %s", gcInterval)
		api.StartGC(gcInterval, workerStop)
	}

	var metricsServer *http.Server
	// Prometheus metrics on their own listener, off by default. The metrics
	// enumerate opaque per-account owner handles and storage totals, so the
	// endpoint belongs on a loopback or private interface, never on AQT_ADDR;
	// keeping it a separate plain-HTTP server makes that binding explicit.
	if maddr := os.Getenv("AQT_METRICS_ADDR"); maddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", api.MetricsHandler())
		if err := validateListenAddress(maddr, true, true); err != nil {
			log.Fatalf("metrics address: %v", err)
		}
		metricsServer = &http.Server{
			Addr:              maddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Printf("metrics on http://%s/metrics", maddr)
		go func() {
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics server exited: %v", err)
			}
		}()
	}

	tlsSet, err := loadTLSSettings()
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}
	tlsCfg, err := tlsSet.tlsConfig(dataDir)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}
	allowInsecure := os.Getenv("AQT_ALLOW_INSECURE_HTTP") == "1"
	if err := validateListenAddress(addr, tlsCfg != nil, allowInsecure); err != nil {
		log.Fatalf("listen address: %v", err)
	}

	grace, err := envDurationValue("AQT_SHUTDOWN_GRACE", shutdownGrace.String(), false)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// No ReadTimeout/WriteTimeout: they span the full body transfer, capping a
	// 32 MiB pack at ~4.3 Mbps and permanently failing slower links. Handlers
	// already cap body sizes, ReadHeaderTimeout bounds header slowloris, and
	// IdleTimeout reaps idle keep-alives.
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("data dir: %s", dataDir)
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
	serveErr := serveWithShutdown(srv, tlsCfg, grace, beginShutdown, shutdownComponents)
	beginShutdown()
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	shutdownErr := shutdownComponents(ctx)
	cancel()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Printf("server exited: %v", serveErr)
		return
	}
	if shutdownErr != nil {
		log.Printf("shutdown: %v", shutdownErr)
	}
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
