// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// listAll now serves every paginated listing, so a bug in its loop breaks all five at
// once rather than one. Nothing exercised multi-page behavior before.
func TestListAllFollowsEveryPage(t *testing.T) {
	pages := map[string]api.ListDevicesResponse{
		"":   {Devices: []api.Device{{ID: "d1"}}, NextCursor: "c1"},
		"c1": {Devices: []api.Device{{ID: "d2"}}, NextCursor: "c2"},
		"c2": {Devices: []api.Device{{ID: "d3"}}},
	}
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		seen = append(seen, cursor)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pages[cursor])
	}))
	defer srv.Close()

	got, err := newTestClient(t, srv.URL).ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(got) != 3 || got[0].ID != "d1" || got[1].ID != "d2" || got[2].ID != "d3" {
		t.Fatalf("got %+v, want d1,d2,d3 in page order", got)
	}
	if len(seen) != 3 || seen[0] != "" || seen[1] != "c1" || seen[2] != "c2" {
		t.Fatalf("cursors sent were %q, want \"\",c1,c2", seen)
	}
}

// A server that keeps handing back the same cursor must end the listing rather than
// pin the client in a loop forever.
func TestListAllRefusesAStuckCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ListDevicesResponse{
			Devices: []api.Device{{ID: "d"}}, NextCursor: "same",
		})
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).ListDevices()
	if !errors.Is(err, errTooManyPages) {
		t.Fatalf("got %v, want errTooManyPages", err)
	}
}

// A mid-listing failure must abort rather than return the pages gathered so far: a
// caller cannot tell a truncated slice from a complete one.
func TestListAllAbortsOnAFailedPage(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ListDevicesResponse{
			Devices: []api.Device{{ID: "d1"}}, NextCursor: "c1",
		})
	}))
	defer srv.Close()

	got, err := newTestClient(t, srv.URL).ListDevices()
	if err == nil {
		t.Fatal("expected the second page's failure to abort the listing")
	}
	if got != nil {
		t.Fatalf("a failed listing returned %+v; a partial slice reads as complete", got)
	}
}
