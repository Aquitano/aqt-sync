// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// fakePackServer serves /v1/chunks/locate and /v1/packs/<id> from an in-memory
// pack layout, counting GETs per pack so a test can assert the download path
// fetches each pack once even under the concurrent worker pool.
type fakePackServer struct {
	packs   map[string][]byte
	locs    map[string]api.ObjectLocation
	getHits map[string]*int32
	failGet bool
}

func (f *fakePackServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chunks/locate", func(w http.ResponseWriter, r *http.Request) {
		var req api.LocateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var resp api.LocateResponse
		for _, id := range req.IDs {
			if loc, ok := f.locs[id]; ok {
				resp.Locations = append(resp.Locations, loc)
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/packs/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/packs/")
		if c := f.getHits[id]; c != nil {
			atomic.AddInt32(c, 1)
		}
		if f.failGet {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		body, ok := f.packs[id]
		if !ok {
			http.Error(w, "no pack", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body) // whole body; getRange slices the requested window out of a 200
	})
	return mux
}

func newFakePackClient(t *testing.T, f *fakePackServer) *client.Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	cl, err := client.New(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// TestRunDownloadsPropagatesFetchError checks the worker pool surfaces the first
// fetch failure rather than writing a corrupt file: a pack GET that 500s must fail
// the whole pull.
func TestRunDownloadsPropagatesFetchError(t *testing.T) {
	f := &fakePackServer{
		packs:   map[string][]byte{"p1": make([]byte, 100)},
		locs:    map[string]api.ObjectLocation{"a": {ID: "a", PackID: "p1", Off: 0, Len: 100}},
		getHits: map[string]*int32{"p1": new(int32)},
		failGet: true,
	}
	cl := newFakePackClient(t, f)
	entries := []syncengine.Entry{
		{Path: "f.bin", Mode: 0o644, Size: 100, Hash: "h", Chunks: []crypto.Chunk{{ID: "a", Key: make([]byte, crypto.KeySize), Len: 100}}},
	}
	if _, err := runDownloads(cl, t.TempDir(), entries, nil); err == nil {
		t.Fatal("runDownloads must fail when a pack fetch errors")
	}
}

// A download resolves chunk locations in bounded batches so its index does not scale
// with the whole tree. Batches never split a file — a file's chunks have to be located
// together to materialize it — so one oversized file is simply its own batch.
func TestBatchByChunks(t *testing.T) {
	entry := func(path string, chunks int) syncengine.Entry {
		e := syncengine.Entry{Path: path}
		for range chunks {
			e.Chunks = append(e.Chunks, crypto.Chunk{ID: path})
		}
		return e
	}
	entries := []syncengine.Entry{
		entry("a", 2), entry("b", 2), // fills the first batch exactly
		entry("c", 1), entry("d", 1),
		entry("huge", 9), // over the bound on its own
		entry("e", 1),
	}
	var got [][]string
	for _, batch := range batchByChunks(entries, 4) {
		var paths []string
		for _, e := range batch {
			paths = append(paths, e.Path)
		}
		got = append(got, paths)
	}
	want := [][]string{{"a", "b"}, {"c", "d"}, {"huge"}, {"e"}}
	if len(got) != len(want) {
		t.Fatalf("batches = %v, want %v", got, want)
	}
	for i := range want {
		if strings.Join(got[i], ",") != strings.Join(want[i], ",") {
			t.Fatalf("batch %d = %v, want %v", i, got[i], want[i])
		}
	}
	if batchByChunks(nil, 4) != nil {
		t.Fatal("no entries must produce no batches")
	}
	// A file with no chunks (inline content) needs no locate, so those never force a split.
	if n := len(batchByChunks([]syncengine.Entry{entry("i", 0), entry("j", 0)}, 1)); n != 1 {
		t.Fatalf("inline entries split into %d batches, want 1", n)
	}
}

// TestBatchNodeFetcherSharesPackAcrossLevels drives the level-batched fetcher the
// way a tree walk does — one call per level — against a pack holding nodes from two
// levels. The shared packio.Source must serve the second level's node from the span the
// first level already fetched: exactly one pack GET across both calls.
func TestBatchNodeFetcherSharesPackAcrossLevels(t *testing.T) {
	pack := []byte(strings.Repeat("A", 100) + strings.Repeat("B", 100) + strings.Repeat("C", 100))
	f := &fakePackServer{
		packs: map[string][]byte{"p1": pack},
		locs: map[string]api.ObjectLocation{
			"a": {ID: "a", PackID: "p1", Off: 0, Len: 100},
			"b": {ID: "b", PackID: "p1", Off: 100, Len: 100},
			"c": {ID: "c", PackID: "p1", Off: 200, Len: 100},
		},
		getHits: map[string]*int32{"p1": new(int32)},
	}
	cl := newFakePackClient(t, f)

	fetch := newBatchNodeFetcher(cl, nil)
	level1, err := fetch([]string{"a", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if string(level1["a"][:1]) != "A" || string(level1["c"][:1]) != "C" {
		t.Fatal("level 1 nodes came back wrong")
	}
	level2, err := fetch([]string{"b"})
	if err != nil {
		t.Fatal(err)
	}
	if string(level2["b"][:1]) != "B" {
		t.Fatal("level 2 node came back wrong")
	}
	if n := atomic.LoadInt32(f.getHits["p1"]); n != 1 {
		t.Fatalf("pack p1 fetched %d times across levels, want exactly 1", n)
	}
}
