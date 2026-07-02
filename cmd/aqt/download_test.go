package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
		w.Write(body) // whole body; getRange slices the requested window out of a 200
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

// TestPackSourceConcurrentGet proves the download-side packSource is safe under the
// worker pool and dedups a shared pack: many goroutines fetching objects from the
// same pack trigger exactly one GetPackRange (singleflight + LRU), and every object
// comes back byte-correct. Run under -race, it also guards the cache mutation paths.
func TestPackSourceConcurrentGet(t *testing.T) {
	p1 := []byte(strings.Repeat("A", 100) + strings.Repeat("B", 100) + strings.Repeat("C", 100))
	p2 := []byte(strings.Repeat("D", 100))
	f := &fakePackServer{
		packs: map[string][]byte{"p1": p1, "p2": p2},
		locs: map[string]api.ObjectLocation{
			"a": {ID: "a", PackID: "p1", Off: 0, Len: 100},
			"b": {ID: "b", PackID: "p1", Off: 100, Len: 100},
			"c": {ID: "c", PackID: "p1", Off: 200, Len: 100},
			"d": {ID: "d", PackID: "p2", Off: 0, Len: 100},
		},
		getHits: map[string]*int32{"p1": new(int32), "p2": new(int32)},
	}
	cl := newFakePackClient(t, f)

	src, err := newPackSource(cl, []string{"a", "b", "c", "d"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]byte{"a": 'A', "b": 'B', "c": 'C', "d": 'D'}

	var wg sync.WaitGroup
	ids := []string{"a", "b", "c", "d"}
	errs := make(chan error, 200)
	for i := 0; i < 200; i++ {
		id := ids[i%len(ids)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := src.get(id)
			if err != nil {
				errs <- err
				return
			}
			if len(got) != 100 || got[0] != want[id] || got[99] != want[id] {
				errs <- errUnexpectedBytes
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent get: %v", err)
	}
	if n := atomic.LoadInt32(f.getHits["p1"]); n != 1 {
		t.Fatalf("pack p1 fetched %d times, want exactly 1 (dedup failed)", n)
	}
	if n := atomic.LoadInt32(f.getHits["p2"]); n != 1 {
		t.Fatalf("pack p2 fetched %d times, want exactly 1", n)
	}
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
	if err := runDownloads(cl, t.TempDir(), entries); err == nil {
		t.Fatal("runDownloads must fail when a pack fetch errors")
	}
}

var errUnexpectedBytes = errBytes("unexpected object bytes")

type errBytes string

func (e errBytes) Error() string { return string(e) }
