// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/server"
)

// newE2EOldServer fronts the server with a proxy that strips the gcMode echo from
// every JSON response, so the client sees exactly what a pre-capability-5 server
// would send.
func newE2EOldServer(t *testing.T) *e2eHarness {
	t.Helper()
	strip := func(resp *http.Response) error {
		if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
			return nil
		}
		body := resp.Body
		gzipped := resp.Header.Get("Content-Encoding") == "gzip"
		if gzipped {
			gz, err := gzip.NewReader(body)
			if err != nil {
				return err
			}
			body = gz
		}
		raw, err := io.ReadAll(body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			if _, ok := m["gcMode"]; ok {
				delete(m, "gcMode")
				if raw, err = json.Marshal(m); err != nil {
					return err
				}
			}
		}
		if gzipped {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			gw.Write(raw)
			gw.Close()
			raw = buf.Bytes()
		}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		return nil
	}

	gin.SetMode(gin.TestMode)
	isolateConfigEnv(t, t.TempDir())
	dataDir := t.TempDir()
	store, err := server.OpenStore(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	backend := httptest.NewServer(server.NewWithConfig(store, server.Config{}).Router())
	t.Cleanup(backend.Close)
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	proxy.ModifyResponse = strip
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)

	h := &e2eHarness{t: t, url: front.URL, dataDir: dataDir, store: store}
	h.signup("old-server@example.com", "correct horse battery staple")
	return h
}

// Against a server that never echoes a gcMode, the client must stay refs-full
// forever: no mode is cached, every sync replaces the ref rows, the account never
// flips, and prune refuses to run.
func TestClientGCOldServerKeepsRefs(t *testing.T) {
	h := newE2EOldServer(t)
	dir := t.TempDir()
	h.init(dir)

	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.GCMode != "" {
		t.Fatalf("state GCMode = %q, want empty without an echo", st.GCMode)
	}
	createRows, err := h.store.ResourceChunkRowsForTest(st.ID)
	if err != nil {
		t.Fatal(err)
	}

	writeTree(t, dir, "a.txt", strings.Repeat("content ", 2048))
	h.sync(dir)
	rows, err := h.store.ResourceChunkRowsForTest(st.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rows <= createRows {
		t.Fatalf("refs rows after sync = %d, want more than the create's %d (sync must stay refs-full)", rows, createRows)
	}

	if err := runPrune(true, false); err == nil {
		t.Fatal("prune against a no-echo server must refuse, got nil")
	}
}

// usageObjects reports the account's stored-object count, for asserting what a
// prune reclaimed.
func (h *e2eHarness) usageObjects() int64 {
	h.t.Helper()
	cl, _, err := authedClient()
	if err != nil {
		h.t.Fatalf("authed client: %v", err)
	}
	u, err := cl.Usage()
	if err != nil {
		h.t.Fatalf("usage: %v", err)
	}
	return u.Objects
}

// The client-GC round trip: init learns the server's mode from the create echo,
// the first sync pushes refs-less (the stored ref rows stay at the create-time
// count while the object store grows), and after a delete an aged prune reclaims
// exactly the unreachable chunks — what survives still clones intact.
func TestClientGCSyncAndPrune(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.GCMode != "client" {
		t.Fatalf("state GCMode = %q, want client (create echo not recorded)", st.GCMode)
	}
	createRows, err := h.store.ResourceChunkRowsForTest(st.ID)
	if err != nil {
		t.Fatalf("count refs: %v", err)
	}

	keep := strings.Repeat("keep this content ", 4096)
	drop := strings.Repeat("drop this content ", 4096)
	writeTree(t, dir, "keep.txt", keep)
	writeTree(t, dir, "sub/drop.txt", drop)
	h.sync(dir)

	rows, err := h.store.ResourceChunkRowsForTest(st.ID)
	if err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if rows != createRows {
		t.Fatalf("refs rows after sync = %d, want the create-time %d (sync should push refs-less)", rows, createRows)
	}

	objectsBefore := h.usageObjects()
	if objectsBefore <= 1 {
		t.Fatalf("objects after sync = %d, want the synced tree's objects", objectsBefore)
	}

	if err := os.Remove(filepath.Join(dir, "sub", "drop.txt")); err != nil {
		t.Fatal(err)
	}
	h.sync(dir)

	if err := h.store.BackdatePacksForTest(st.Account, 2*time.Hour); err != nil {
		t.Fatalf("backdate packs: %v", err)
	}
	if err := runPrune(false, false); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if after := h.usageObjects(); after >= objectsBefore {
		t.Fatalf("objects after prune = %d, want fewer than %d", after, objectsBefore)
	}

	clone := t.TempDir()
	h.clone(st.ID, clone)
	got, err := os.ReadFile(filepath.Join(clone, "keep.txt"))
	if err != nil || string(got) != keep {
		t.Fatalf("surviving file after prune: err=%v, content match=%v", err, string(got) == keep)
	}
	if _, err := os.Stat(filepath.Join(clone, "sub", "drop.txt")); !os.IsNotExist(err) {
		t.Fatalf("deleted file present in clone (stat err %v)", err)
	}
}
