// SPDX-License-Identifier: AGPL-3.0-or-later

package packio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

type countingProgress struct{ done atomic.Int64 }

func (p *countingProgress) Add(n int64) { p.done.Add(n) }

// TestUploaderCountsProgress drives the real upload pipeline against a fake that
// reports every chunk missing, and asserts progress credits each pack's plaintext
// bytes once it is confirmed on the server.
func TestUploaderCountsProgress(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chunks/check", func(w http.ResponseWriter, r *http.Request) {
		var req api.ChunkCheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(api.ChunkCheckResponse{Missing: req.IDs}) // all missing
	})
	mux.HandleFunc("/v1/packs/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // accept the PutPack
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cl, err := client.New(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}

	prog := &countingProgress{}
	up := NewUploader(context.Background(), cl, prog, 4)
	for _, id := range []string{"a", "b", "c"} {
		if err := up.Add(crypto.Chunk{ID: id, Len: 100}, bytes.Repeat([]byte(id), 8)); err != nil {
			t.Fatal(err)
		}
	}
	if err := up.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := prog.done.Load(); got != 300 {
		t.Errorf("upload progress = %d, want 300", got)
	}
}

// A ^C between packs cancels the uploader's group without any worker error (the
// group parents on the caller's signal context, not only on failing workers). The
// batch under dispatch is dropped at that point, so Add/Flush must surface the
// cancellation — returning nil made a canceled push keep sealing the rest of
// the tree and report every dropped pack as uploaded.
func TestUploaderSurfacesRootCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cl, err := client.New("https://127.0.0.1:1/", "")
	if err != nil {
		t.Fatal(err)
	}
	up := NewUploader(ctx, cl.WithContext(ctx), nil, 4)
	cancel()

	var failed error
	for i := 0; i < 64 && failed == nil; i++ {
		failed = up.Add(crypto.Chunk{ID: fmt.Sprintf("chunk-%03d", i), Len: 1 << 20}, make([]byte, 1<<20))
	}
	if failed == nil {
		failed = up.Flush()
	}
	if failed == nil {
		t.Fatal("uploader reported success after cancel; every pack was dropped")
	}
	if !errors.Is(failed, context.Canceled) {
		t.Fatalf("cancel surfaced as %v, want context.Canceled", failed)
	}
}
