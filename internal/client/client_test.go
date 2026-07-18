package client

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// writeFrame emits one length-prefixed object frame, the server side of the
// positional framing PublicObjects decodes.
func writeFrame(w http.ResponseWriter, b []byte) {
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(b)))
	w.Write(lenbuf[:])
	w.Write(b)
}

// PublicObjects must return one slice per requested id, in request order, decoded off
// the positional length-prefixed framing.
func TestPublicObjectsFramingRoundTrip(t *testing.T) {
	want := [][]byte{[]byte("alpha"), []byte("bravo bytes"), []byte("c")}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.PublicObjectsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(req.IDs) != len(want) {
			t.Errorf("server saw %d ids, want %d", len(req.IDs), len(want))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		for _, b := range want {
			writeFrame(w, b)
		}
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := cl.PublicObjects("res1", []string{"id0", "id1", "id2"})
	if err != nil {
		t.Fatalf("PublicObjects: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i]) != string(want[i]) {
			t.Fatalf("frame %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A frame whose declared length overruns the body is a truncated response and must
// error rather than return a short or panicking slice.
func TestPublicObjectsRejectsTruncatedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var lenbuf [4]byte
		binary.BigEndian.PutUint32(lenbuf[:], 100) // claims 100 bytes...
		w.Write(lenbuf[:])
		w.Write([]byte("only ten b")) // ...but sends 10
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cl.PublicObjects("res1", []string{"id0"}); err == nil {
		t.Fatal("a truncated frame must be rejected")
	}
}

// A 404 (private or unknown resource) maps to ErrNotFound, like the other reads.
func TestPublicObjectsMaps404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cl.PublicObjects("res1", []string{"id0"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

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

// Every request must advertise the build's read capability so the server can gate a
// format boundary with a 426 instead of serving bytes the client cannot open.
func TestRequestsCarryCapabilityHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(api.CapabilityHeader)
		if err := json.NewEncoder(w).Encode(api.ChunkCheckResponse{}); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cl.CheckChunks([]string{"a"}); err != nil {
		t.Fatalf("CheckChunks: %v", err)
	}
	if want := strconv.Itoa(api.ClientCapability); got != want {
		t.Fatalf("capability header = %q, want %q", got, want)
	}
}

// A 426 must map to ErrUpgradeRequired carrying the server's min_client, and the
// error text must be the server's message (printed verbatim to the user).
func TestUpgradeRequiredMaps426(t *testing.T) {
	const msg = "resource requires client capability 3 or newer (this client supports 2): upgrade aqt"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUpgradeRequired)
		if err := json.NewEncoder(w).Encode(api.ErrorResponse{
			Error: msg, Code: api.ErrCodeUpgradeRequired, MinClient: 3,
		}); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer srv.Close()

	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = cl.GetResource("id")
	if !errors.Is(err, ErrUpgradeRequired) {
		t.Fatalf("error = %v, want ErrUpgradeRequired", err)
	}
	var ue *UpgradeRequiredError
	if !errors.As(err, &ue) || ue.MinClient != 3 {
		t.Fatalf("min_client not surfaced: %v", err)
	}
	if !strings.Contains(err.Error(), "upgrade aqt") {
		t.Fatalf("error text = %q, want the server's message", err.Error())
	}
}

func TestCreateRetriesOnceWithSameIdempotencyKey(t *testing.T) {
	var keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if len(keys) == 1 {
			http.Error(w, "transient", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.PutResourceResponse{ID: "stable", Version: 1})
	}))
	defer srv.Close()
	cl, _ := New(srv.URL, "tok")
	got, err := cl.PutResource(api.PutResourceRequest{Visibility: api.Public})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "stable" || len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("response=%+v keys=%v", got, keys)
	}
}

func TestUnsafeMutationSurfacesUnknownOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "lost", http.StatusInternalServerError) }))
	defer srv.Close()
	cl, _ := New(srv.URL, "tok")
	_, err := cl.SetVisibility("id", api.SetVisibilityRequest{Visibility: api.Public, ExpectedVersion: 1})
	var unknown *UnknownOutcomeError
	if !errors.As(err, &unknown) {
		t.Fatalf("error = %v, want UnknownOutcomeError", err)
	}
}
