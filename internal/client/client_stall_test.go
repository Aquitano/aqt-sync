// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The stall guard replaces the old whole-request timeout: it must kill a
// connection that stops moving data, while a transfer that is slow but making
// progress runs for longer than the stall window without being aborted.
func TestStallGuard(t *testing.T) {
	old := stallTimeout
	stallTimeout = 200 * time.Millisecond
	t.Cleanup(func() { stallTimeout = old })

	t.Run("hung before headers aborts", func(t *testing.T) {
		done := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-done
		}))
		defer srv.Close()
		defer close(done)

		cl, err := New(srv.URL, "tok")
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = cl.GetPackRange("pack", 0, 4)
		if err == nil || !strings.Contains(err.Error(), "transfer stalled") {
			t.Fatalf("err = %v, want transfer stalled", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("abort took %s, guard did not fire", elapsed)
		}
	})

	t.Run("hung mid-body aborts", func(t *testing.T) {
		done := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("part"))
			w.(http.Flusher).Flush()
			<-done
		}))
		defer srv.Close()
		defer close(done)

		cl, err := New(srv.URL, "tok")
		if err != nil {
			t.Fatal(err)
		}
		_, err = cl.GetPackRange("pack", 0, 16)
		if err == nil || !strings.Contains(err.Error(), "transfer stalled") {
			t.Fatalf("err = %v, want transfer stalled", err)
		}
	})

	t.Run("slow but moving transfer outlives the window", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			for i := 0; i < 8; i++ {
				w.Write([]byte("ab"))
				w.(http.Flusher).Flush()
				time.Sleep(80 * time.Millisecond)
			}
		}))
		defer srv.Close()

		cl, err := New(srv.URL, "tok")
		if err != nil {
			t.Fatal(err)
		}
		// 8 x 80ms = 640ms total, more than 3x the 200ms stall window; each
		// inter-chunk gap stays under it.
		got, err := cl.GetPackRange("pack", 0, 16)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != strings.Repeat("ab", 8) {
			t.Fatalf("got %q", got)
		}
	})
}
