package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func TestEntriesBytes(t *testing.T) {
	got := entriesBytes([]syncengine.Entry{{Size: 100}, {Size: 250}, {Size: 0}})
	if got != 350 {
		t.Errorf("entriesBytes = %d, want 350", got)
	}
}

func TestUploadBytes(t *testing.T) {
	base := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "same", Size: 10, Hash: "h1"},
		{Path: "changed", Size: 20, Hash: "old"},
	}}
	local := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "same", Size: 10, Hash: "h1"},     // unchanged: not counted
		{Path: "changed", Size: 20, Hash: "new"}, // hash differs: counted
		{Path: "added", Size: 30, Hash: "h3"},    // absent from base: counted
	}}
	if got := uploadBytes(local, base); got != 50 {
		t.Errorf("uploadBytes = %d, want 50 (20 changed + 30 added)", got)
	}
}

func TestProgressBarLine(t *testing.T) {
	p := &progressBar{label: "uploading"}
	p.total.Store(1000)
	p.done.Store(250)
	line := p.line()
	for _, want := range []string{"uploading", "25%", "750 B left"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q missing %q", line, want)
		}
	}
}

func TestProgressBarNilSafe(t *testing.T) {
	var p *progressBar // progress off => newProgressBar returns nil
	p.add(10)
	p.finish()
}

// A symlink entry materializes without fetching or decrypting any pack, so it is a
// clean way to observe that the download loop credits each finished file's size.
func TestRunDownloadsCountsProgress(t *testing.T) {
	f := &fakePackServer{
		packs:   map[string][]byte{},
		locs:    map[string]api.ObjectLocation{},
		getHits: map[string]*int32{},
	}
	cl := newFakePackClient(t, f)
	entries := []syncengine.Entry{{Path: "link", Size: 42, Link: "target"}}

	prog := &progressBar{}
	prog.total.Store(42)
	if err := runDownloads(cl, t.TempDir(), entries, prog); err != nil {
		t.Fatalf("runDownloads: %v", err)
	}
	if got := prog.done.Load(); got != 42 {
		t.Errorf("download progress = %d, want 42", got)
	}
}

// TestPackUploaderCountsProgress drives the real upload pipeline against a fake that
// reports every chunk missing, and asserts the bar credits each pack's plaintext
// bytes once it is confirmed on the server.
func TestPackUploaderCountsProgress(t *testing.T) {
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

	prog := &progressBar{}
	prog.total.Store(300)
	up := newPackUploader(cl, prog)
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
