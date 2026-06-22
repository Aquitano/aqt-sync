// Command aqt-server runs the aqt zero-knowledge sync API.
package main

import (
	"log"
	"os"

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

	log.Printf("aqt-server listening on %s (data dir: %s)", addr, dataDir)
	if err := server.New(store).Router().Run(addr); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
