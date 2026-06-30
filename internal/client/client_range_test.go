package client

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// GetPackRange must return exactly the requested window whether the server answers a
// Range request with 206 (partial) or 200 (the whole body). The pack download path
// slices each object out by its absolute offset minus the fetched span's base, so a
// whole-body 200 that is not narrowed here would feed it the wrong bytes.
func TestGetPackRangeNormalizesWholeBodyResponse(t *testing.T) {
	full := []byte("0123456789abcdef")

	t.Run("206 partial", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Honor the Range like the real server (http.ServeContent) does.
			http.ServeContent(w, r, "pack", time.Time{}, bytes.NewReader(full))
		}))
		defer srv.Close()
		cl, err := New(srv.URL, "tok")
		if err != nil {
			t.Fatal(err)
		}
		got, err := cl.GetPackRange("pack", 4, 5)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "45678" {
			t.Fatalf("206 range = %q, want %q", got, "45678")
		}
	})

	t.Run("200 whole body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ignore the Range header entirely and return 200 with the whole pack.
			w.WriteHeader(http.StatusOK)
			w.Write(full)
		}))
		defer srv.Close()
		cl, err := New(srv.URL, "tok")
		if err != nil {
			t.Fatal(err)
		}
		got, err := cl.GetPackRange("pack", 4, 5)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "45678" {
			t.Fatalf("200 whole-body range = %q, want %q", got, "45678")
		}
	})
}
