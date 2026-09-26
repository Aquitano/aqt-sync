// SPDX-License-Identifier: AGPL-3.0-or-later

package packio

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
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
		_, _ = w.Write(body) // whole body; the client slices the requested window out of a 200
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
	for i := range 200 {
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
	for range 2 {
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

// A locate response the span arithmetic cannot use must fail the pull at Locate,
// not panic the download worker that later slices its object out of a span.
func TestSourceRejectsImpossibleLocations(t *testing.T) {
	cases := map[string][]api.ObjectLocation{
		"negative length":   {{ID: "a", PackID: "p", Off: 0, Len: -1}},
		"overflowing range": {{ID: "a", PackID: "p", Off: math.MaxInt64 - 1, Len: 16}},
		"object in two packs": {
			{ID: "a", PackID: "p", Off: 0, Len: 16},
			{ID: "a", PackID: "q", Off: 40, Len: 16},
		},
	}
	for name, locs := range cases {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/v1/chunks/locate", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(api.LocateResponse{Locations: locs})
			})
			mux.HandleFunc("/v1/packs/", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("P", 64)))
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			cl, err := client.New(srv.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			src := NewEmptySource(cl)
			if err := src.Locate([]string{"a"}); err == nil {
				_, getErr := src.Get("a")
				t.Fatalf("Locate accepted %+v (Get: %v)", locs, getErr)
			}
		})
	}
}

// A tree level with identical subtrees asks for one node id more than once, and the
// same location coming back twice must not fail the pull.
func TestSourceAcceptsARepeatedLocation(t *testing.T) {
	f := &fakePackServer{
		packs: map[string][]byte{"p1": []byte(strings.Repeat("A", 100))},
		locs:  map[string]api.ObjectLocation{"a": {ID: "a", PackID: "p1", Off: 0, Len: 100}},
	}
	src, err := NewSource(f.client(t), []string{"a", "a"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := src.Get("a"); err != nil || string(got) != strings.Repeat("A", 100) {
		t.Fatalf("Get(a) = %q, %v", got, err)
	}
}

// FuzzLocationSpans decodes arbitrary bytes into one or two locate responses, as a
// level-by-level walk issues them. Whatever checkLocations accepts, every object must
// lie inside the span assigned to it and every span inside one pack, because Get
// slices an object out of its span with no further check.
func FuzzLocationSpans(f *testing.F) {
	loc := func(id, pack byte, off, n int64) []byte {
		b := []byte{id, pack}
		b = binary.BigEndian.AppendUint64(b, uint64(off))
		return binary.BigEndian.AppendUint64(b, uint64(n))
	}
	f.Add(uint8(1), slices.Concat(loc(0, 0, 0, 100), loc(1, 0, 100, 100), loc(2, 1, 0, 50)))
	f.Add(uint8(0), loc(0, 0, 0, -1)) // a negative length once panicked Get
	f.Add(uint8(0), slices.Concat(loc(0, 0, 0, 16), loc(0, 1, 40, 16)))
	f.Fuzz(func(t *testing.T, split uint8, raw []byte) {
		var all []api.ObjectLocation
		for ; len(raw) >= 18; raw = raw[18:] {
			all = append(all, api.ObjectLocation{
				ID:     string(rune('a' + raw[0]%8)),
				PackID: string(rune('p' + raw[1]%3)),
				Off:    int64(binary.BigEndian.Uint64(raw[2:])),
				Len:    int64(binary.BigEndian.Uint64(raw[10:])),
			})
		}
		cut := int(split) % (len(all) + 1)
		s := &Source{locs: map[string]api.ObjectLocation{}, objSpan: map[string]packSpan{}, spans: map[string][]packSpan{}}
		// The same bookkeeping Locate does with a response, minus the transport.
		for _, located := range [][]api.ObjectLocation{all[:cut], all[cut:]} {
			if checkLocations(located) != nil {
				return
			}
			byPack := map[string][]api.ObjectLocation{}
			for _, l := range located {
				s.locs[l.ID] = l
				byPack[l.PackID] = append(byPack[l.PackID], l)
			}
			for _, objs := range byPack {
				s.assignSpans(objs)
			}
		}
		for id, l := range s.locs {
			sp := s.objSpan[id]
			if !slices.Contains(s.spans[l.PackID], sp) {
				t.Fatalf("object %s in pack %s was given a span of another pack", id, l.PackID)
			}
			// Get fetches [base,end) and slices [Off-base, Off-base+Len) out of it.
			inside := 0 <= sp.base && sp.base <= l.Off && l.Off < l.Off+l.Len && l.Off+l.Len <= sp.end && sp.end <= api.MaxPackBytes
			if !inside {
				t.Fatalf("object %s at offset %d length %d is not inside its span [%d,%d)", id, l.Off, l.Len, sp.base, sp.end)
			}
		}
	})
}

var errUnexpectedBytes = errors.New("unexpected object bytes")
