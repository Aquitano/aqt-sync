package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// LocateChunks must split a large id set into several bounded requests and merge
// their results. This reproduces issue #10: a clone that resolves every chunk id in
// one /v1/chunks/locate request overruns the server's 32 MiB body cap and 413s.
func TestLocateChunksBatchesLargeIDSet(t *testing.T) {
	const total = locateBatchSize*2 + 50 // three batches, last one partial

	var requests int
	var biggest int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.LocateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode locate request: %v", err)
		}
		requests++
		if len(req.IDs) > biggest {
			biggest = len(req.IDs)
		}
		if len(req.IDs) > locateBatchSize {
			t.Errorf("batch carried %d ids, exceeds locateBatchSize %d", len(req.IDs), locateBatchSize)
		}
		locs := make([]api.ObjectLocation, len(req.IDs))
		for i, id := range req.IDs {
			locs[i] = api.ObjectLocation{ID: id, PackID: "pack", Off: int64(i), Len: 1}
		}
		if err := json.NewEncoder(w).Encode(api.LocateResponse{Locations: locs}); err != nil {
			t.Errorf("encode locate response: %v", err)
		}
	}))
	defer srv.Close()

	ids := make([]string, total)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i)
	}

	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := cl.LocateChunks(ids)
	if err != nil {
		t.Fatalf("LocateChunks: %v", err)
	}
	if len(got) != total {
		t.Fatalf("merged %d locations, want %d", len(got), total)
	}
	wantRequests := (total + locateBatchSize - 1) / locateBatchSize
	if requests != wantRequests {
		t.Fatalf("made %d requests, want %d", requests, wantRequests)
	}
	if biggest != locateBatchSize {
		t.Fatalf("largest batch had %d ids, want %d", biggest, locateBatchSize)
	}
}

// GetResource must reject a response whose id differs from the requested one: the
// id-bound AAD checks downstream verify against the returned id, so a server that
// could substitute another record and echo that record's id would satisfy its own
// binding. This pin is what makes the returned id trustworthy.
func TestGetResourceRejectsMismatchedID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := api.EncodeResourceDownload(api.GetResourceResponse{ID: "other", Visibility: api.Private, Version: 1})
		if err != nil {
			t.Errorf("encode download: %v", err)
		}
		w.Write(body)
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cl.GetResource("requested"); err == nil {
		t.Fatal("a response for a different resource id must be rejected")
	}
}

// A snapshot listing filtered by resource must not carry rows the server attributes
// to another resource, for the same reason: the claimed ResourceID feeds the
// id-bound AAD checks.
func TestListSnapshotsRejectsForeignResource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := api.ListSnapshotsResponse{Snapshots: []api.SnapshotInfo{{ID: "s1", ResourceID: "other"}}}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cl.ListSnapshots("requested"); err == nil {
		t.Fatal("a filtered listing carrying another resource's snapshot must be rejected")
	}
	// Unfiltered listings have no expectation to enforce.
	if _, err := cl.ListSnapshots(""); err != nil {
		t.Fatalf("unfiltered listing must pass through: %v", err)
	}
}

// An empty id set must not hit the network at all, matching the old behavior the
// pull path relies on (callers already short-circuit, but a stray request would 400
// nothing useful).
func TestLocateChunksEmptyMakesNoRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request for empty id set: %s", r.URL.Path)
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := cl.LocateChunks(nil)
	if err != nil {
		t.Fatalf("LocateChunks(nil): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d locations for empty input, want 0", len(got))
	}
}
