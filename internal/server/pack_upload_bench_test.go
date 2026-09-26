// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// BenchmarkPutPackConcurrentUploads drives one account's pack PUTs through the
// router from as many uploaders as a sync runs, so it measures what one pushing
// device gets from the server rather than the cost of a single pack. The same few
// packs are re-sent, which still verifies, writes, and commits each one, so the
// benchmark's disk use stays bounded by the pool.
func BenchmarkPutPackConcurrentUploads(b *testing.B) {
	const (
		uploaders = 4
		objects   = 64
		objSize   = 256 << 10
		pool      = 8
	)
	s := newStore(b)
	router := NewWithConfig(s, Config{AuthedRatePerSec: 1e6, AuthedBurst: 1e6}).Router()
	owner := s.mustAccount(b, "uploads@example.com")
	_, token, err := s.CreateDevice(owner, "bench", 1, 0)
	if err != nil {
		b.Fatal(err)
	}
	type pack struct {
		id   string
		data []byte
	}
	packs := make([]pack, pool)
	for i := range packs {
		payloads := make([]string, objects)
		for j := range payloads {
			obj := make([]byte, objSize)
			_, _ = rand.Read(obj)
			payloads[j] = string(obj)
		}
		id, data, _ := packOf(payloads...)
		packs[i] = pack{id, data}
	}
	b.SetBytes(int64(len(packs[0].data)))
	b.ResetTimer()
	var next atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, uploaders)
	for range uploaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := next.Add(1)
				if n > int64(b.N) {
					return
				}
				p := packs[n%pool]
				req := httptest.NewRequest(http.MethodPut, "/v1/packs/"+p.id, bytes.NewReader(p.data))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/octet-stream")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					errs <- fmt.Errorf("put pack: %d %s", rec.Code, rec.Body.String())
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		b.Fatal(err)
	}
}
