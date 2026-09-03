// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"errors"
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
		if !errors.Is(err, ErrStalled) {
			t.Fatalf("err = %v, want ErrStalled", err)
		}
		// A stall is the guard's decision, not the user's; the two must never
		// read as each other (cancel maps to exit 130, stall to retryable 5).
		if errors.Is(err, context.Canceled) {
			t.Fatalf("a stall surfaced as a user cancel: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("abort took %s, guard did not fire", elapsed)
		}
	})

	t.Run("hung mid-body aborts", func(t *testing.T) {
		done := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("part"))
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
		if !errors.Is(err, ErrStalled) {
			t.Fatalf("err = %v, want ErrStalled", err)
		}
	})

	t.Run("slow but moving transfer outlives the window", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			for range 8 {
				_, _ = w.Write([]byte("ab"))
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
