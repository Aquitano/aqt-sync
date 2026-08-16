// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// boundClient builds a client bound to a cancellable context against srv, with
// the stall guard left at its long default so any prompt abort observed in these
// tests is attributable to the cancel, never the guard.
func boundClient(t *testing.T, srv *httptest.Server) (*Client, context.CancelFunc) {
	t.Helper()
	cl, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return cl.WithContext(ctx), cancel
}

// requireCanceled asserts the error is a user cancel — and specifically not a
// stall, which is the distinction the typed errors exist for.
func requireCanceled(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled in the chain", err)
	}
	if errors.Is(err, ErrStalled) {
		t.Fatalf("a user cancel surfaced as a stall: %v", err)
	}
}

// A ^C during an upload must abort promptly even though bytes were still
// flowing, which the stall guard alone would never do.
func TestCancelDuringUploadAborts(t *testing.T) {
	t.Parallel()
	uploading := make(chan struct{})
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read a little so the client is genuinely mid-upload, then stop draining.
		buf := make([]byte, 1024)
		r.Body.Read(buf)
		close(uploading)
		<-done
	}))
	defer srv.Close()
	defer close(done)

	cl, cancel := boundClient(t, srv)
	go func() {
		<-uploading
		cancel()
	}()
	start := time.Now()
	// Large enough that the transport cannot buffer it all before the server
	// stops reading.
	err := cl.PutPack("pack", make([]byte, 8<<20))
	if err == nil {
		t.Fatal("canceled upload reported success")
	}
	requireCanceled(t, err)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("abort took %s", elapsed)
	}
}

// A ^C while the response body is streaming must abort the read.
func TestCancelDuringResponseReadAborts(t *testing.T) {
	t.Parallel()
	reading := make(chan struct{})
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		close(reading)
		<-done
	}))
	defer srv.Close()
	defer close(done)

	cl, cancel := boundClient(t, srv)
	go func() {
		<-reading
		cancel()
	}()
	_, err := cl.GetPackRange("pack", 0, 64)
	if err == nil {
		t.Fatal("canceled download reported success")
	}
	requireCanceled(t, err)
}

// A ^C during a rate-limit cooldown park must abort the wait, not ride it out.
func TestCancelDuringCooldownAborts(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cl, cancel := boundClient(t, srv)
	// A cooldown some concurrent request established; the next request parks on it
	// before sending.
	cl.cooldown.enter(30 * time.Second)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := cl.Usage()
	if err == nil {
		t.Fatal("canceled cooldown wait reported success")
	}
	requireCanceled(t, err)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the cancel did not interrupt the park (took %s)", elapsed)
	}
}

// The idempotent-create loop retries transport failures — and a cancel reports
// as one (status 0). It must not send the second attempt of a command the user
// killed.
func TestCancelStopsIdempotentCreateRetry(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int64
	var cancelOnce func()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		// Cancel before answering with a retryable 500: whichever the client
		// observes first, the loop must stop at one attempt.
		cancelOnce()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cl, cancel := boundClient(t, srv)
	cancelOnce = cancel
	_, err := cl.PutResource(api.PutResourceRequest{
		Visibility: api.Private,
		Blob:       crypto.SealedBlob{Nonce: []byte{1}, Ciphertext: []byte{2}},
		WrappedKey: &crypto.WrappedKey{},
	})
	if err == nil {
		t.Fatal("canceled create reported success")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1 (the retry ignored the cancel)", got)
	}
}
