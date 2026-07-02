// Command aqt-server runs the aqt zero-knowledge sync API.
package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
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

	api := server.New(store)

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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
