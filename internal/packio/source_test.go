// SPDX-License-Identifier: AGPL-3.0-or-later

package packio

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
)

// fakePackServer serves /v1/chunks/locate and /v1/packs/<id> from an in-memory pack
// layout, counting GETs per pack so a test can assert a span is fetched once even
// under the concurrent worker pool.
type fakePackServer struct {
	packs   map[string][]byte
	locs    map[string]api.ObjectLocation
	getHits map[string]*int32
}

func (f *fakePackServer) client(t *testing.T) *client.Client {
	t.Helper()
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
		body, ok := f.packs[id]
		if !ok {
			http.Error(w, "no pack", http.StatusNotFound)
			return
		}
		w.Write(body) // whole body; the client slices the requested window out of a 200
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cl, err := client.New(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// TestSourceConcurrentGet proves the download-side source is safe under the worker
// pool and dedups a shared pack: many goroutines fetching objects from the same pack
// trigger exactly one GetPackRange (singleflight + LRU), and every object comes back
// byte-correct. Run under -race, it also guards the cache mutation paths.
func TestSourceConcurrentGet(t *testing.T) {
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

	src, err := NewSource(f.client(t), []string{"a", "b", "c", "d"})
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
			got, err := src.Get(id)
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

// Dropping a batch's location index must not drop the fetched bytes with it: a chunk
// two batches share is located twice but fetched once, which is what keeps batching
// from costing extra round-trips.
func TestForgetLocationsKeepsFetchedSpans(t *testing.T) {
	f := &fakePackServer{
		packs:   map[string][]byte{"p1": []byte(strings.Repeat("A", 100))},
		locs:    map[string]api.ObjectLocation{"a": {ID: "a", PackID: "p1", Off: 0, Len: 100}},
		getHits: map[string]*int32{"p1": new(int32)},
	}
	src := NewEmptySource(f.client(t))
	for i := 0; i < 2; i++ {
		if err := src.Locate([]string{"a"}); err != nil {
			t.Fatal(err)
		}
		if _, err := src.Get("a"); err != nil {
			t.Fatal(err)
		}
		src.ForgetLocations()
		if len(src.locs) != 0 || len(src.objSpan) != 0 {
			t.Fatal("ForgetLocations must drop the per-chunk index")
		}
	}
	if n := atomic.LoadInt32(f.getHits["p1"]); n != 1 {
		t.Fatalf("pack fetched %d times across batches, want 1", n)
	}
}

// TestSourceSpanSplitting checks that needed objects close together share one span
// (one range), but a gap wider than spanSplitGap opens a new span so the dead bytes
// between them are never downloaded.
func TestSourceSpanSplitting(t *testing.T) {
	s := &Source{objSpan: map[string]packSpan{}, spans: map[string][]packSpan{}}
	bEnd := int64(100 + 1000 + 100)  // a: [0,100), b: [1100,1200); gap 1000 < threshold
	cBase := bEnd + spanSplitGap + 1 // c starts a fresh span (gap beyond threshold)
	s.assignSpans([]api.ObjectLocation{
		{ID: "a", PackID: "p", Off: 0, Len: 100},
		{ID: "b", PackID: "p", Off: 1100, Len: 100},
		{ID: "c", PackID: "p", Off: cBase, Len: 100},
	})

	if s.objSpan["a"] != s.objSpan["b"] {
		t.Fatal("objects within the gap threshold must share a span")
	}
	if s.objSpan["a"] == s.objSpan["c"] {
		t.Fatal("an object beyond the gap threshold must open its own span")
	}
	if ab := s.objSpan["a"]; ab.base != 0 || ab.end != bEnd {
		t.Fatalf("a/b span = %+v, want base 0 end %d", ab, bEnd)
	}
	if c := s.objSpan["c"]; c.base != cBase || c.end != cBase+100 {
		t.Fatalf("c span = %+v, want base %d end %d", c, cBase, cBase+100)
	}
}

// A located-but-missing object surfaces client.ErrNotFound, which the reconcile
// loop maps to a conflict-retry: a manifest whose objects were GC'd by a concurrent
// supersede is re-read against the current version instead of hard-failing.
func TestSourceMissingObjectIsNotFound(t *testing.T) {
	src := &Source{
		locs:    map[string]api.ObjectLocation{},
		objSpan: map[string]packSpan{},
		cache:   NewCache(1),
	}
	if _, err := src.Get("deadbeef"); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("get of an unlocated object = %v, want client.ErrNotFound", err)
	}
}

var errUnexpectedBytes = errors.New("unexpected object bytes")
