// Command aqt-server runs the aqt zero-knowledge sync API.
package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/server"
)

func main() {
	dataDir := envOr("AQT_DATA_DIR", "./aqt-data")
	addr := envOr("AQT_ADDR", ":8080")

	if os.Getenv("AQT_DEBUG") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	store, err := server.OpenStore(dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	api := server.NewWithConfig(store, loadServerConfig())

	// Scheduled snapshots. A snapshot is keyless (it copies already-sealed
	// ciphertext), so the server runs the job itself; AQT_SNAPSHOT_INTERVAL=0 disables
	// it. Default daily. AQT_SNAPSHOT_KEEP caps how many scheduled snapshots each
	// resource retains (0 keeps all) so storage converges; manual snapshots are
	// never pruned.
	interval, err := time.ParseDuration(envOr("AQT_SNAPSHOT_INTERVAL", "24h"))
	if err != nil {
		log.Fatalf("invalid AQT_SNAPSHOT_INTERVAL: %v", err)
	}
	keep, err := strconv.Atoi(envOr("AQT_SNAPSHOT_KEEP", "30"))
	if err != nil || keep < 0 {
		log.Fatalf("invalid AQT_SNAPSHOT_KEEP: %v", envOr("AQT_SNAPSHOT_KEEP", "30"))
	}
	if interval > 0 {
		log.Printf("scheduled snapshots every %s (keeping last %d per resource; 0 = all)", interval, keep)
		api.StartAutoSnapshot(interval, keep, nil)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("aqt-server listening on %s (data dir: %s)", addr, dataDir)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// loadServerConfig builds the hardening config from env vars. Every knob has a safe
// default: open registration, unlimited storage and devices, and loopback-only
// trusted proxies.
//
//	AQT_REGISTRATION     open (default) | invite
//	AQT_INVITE_TOKENS    comma-separated invite secrets (invite mode only)
//	AQT_QUOTA_BYTES      per-owner stored-pack-byte cap; 0 (default) = unlimited
//	AQT_MAX_DEVICES      per-account device cap; 0 (default) = unlimited
//	AQT_AUTH_RATE        per-token authed requests/sec; 0 = package default
//	AQT_AUTH_BURST       per-token authed burst; 0 = package default
//	AQT_TRUSTED_PROXIES  comma-separated proxy CIDRs/hosts whose X-Forwarded-* is
//	                     trusted; unset = loopback only; "none" = trust none
func loadServerConfig() server.Config {
	cfg := server.Config{
		Registration:     server.RegistrationMode(envOr("AQT_REGISTRATION", string(server.RegistrationOpen))),
		InviteTokens:     splitCSV(os.Getenv("AQT_INVITE_TOKENS")),
		QuotaBytes:       envInt64("AQT_QUOTA_BYTES"),
		MaxDevices:       int(envInt64("AQT_MAX_DEVICES")),
		AuthedRatePerSec: envFloat("AQT_AUTH_RATE"),
		AuthedBurst:      envFloat("AQT_AUTH_BURST"),
	}
	if cfg.Registration == server.RegistrationInvite && len(cfg.InviteTokens) == 0 {
		log.Fatal("AQT_REGISTRATION=invite requires AQT_INVITE_TOKENS")
	}

	switch raw := os.Getenv("AQT_TRUSTED_PROXIES"); {
	case raw == "":
		cfg = cfg.WithTrustedProxies([]string{"127.0.0.1", "::1"})
	case strings.EqualFold(raw, "none"):
		cfg = cfg.WithTrustedProxies(nil)
	default:
		cfg = cfg.WithTrustedProxies(splitCSV(raw))
	}
	return cfg
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

func envInt64(key string) int64 {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Fatalf("invalid %s: %v", key, err)
	}
	return n
}

func envFloat(key string) float64 {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		log.Fatalf("invalid %s: %v", key, err)
	}
	return n
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
