// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// sealJob carries one chunk's plaintext from the split goroutine to a sealer and
// the sealed result to the collector. piece is an owned copy — SplitStream reuses
// its emit buffer, so the bytes must be copied before they cross goroutines.
// done closes once ct/ch/err are set.
type sealJob struct {
	piece []byte
	ct    []byte
	ch    crypto.Chunk
	err   error
	done  chan struct{}
}

// errSealStopped aborts the split after the collector has recorded a real error;
// that error takes precedence, so this sentinel never escapes sealStream.
var errSealStopped = errors.New("syncengine: seal aborted")

// sealStream splits r and seals every chunk under conv, fanning crypto.SealChunk
// (XChaCha20-Poly1305 plus two SHA-256s — the CPU ceiling of a push on a fast
// network) across GOMAXPROCS workers. Order is preserved: the returned chunk
// records follow stream order, and sink.Add is called in that same order from a
// single collector goroutine, so callers observe exactly the serial loop's
// behavior. All sink.Add calls complete before sealStream returns.
func sealStream(r io.Reader, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) ([]crypto.Chunk, int64, error) {
	workers := runtime.GOMAXPROCS(0)
	if workers <= 1 {
		return sealSerial(r, conv, chunker, sink)
	}

	jobs := make(chan *sealJob)
	// order hands jobs to the collector in emit order. Its bound (plus the jobs in
	// workers' hands) caps buffered plaintext at O(workers * Max) per file.
	order := make(chan *sealJob, workers)
	// free recycles piece buffers from the collector back to the splitter, so a
	// steady state seals a large file with a fixed set of buffers.
	free := make(chan []byte, 2*workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				j.ct, j.ch, j.err = crypto.SealChunk(j.piece, conv)
				close(j.done)
			}
		}()
	}

	var (
		chunks     []crypto.Chunk
		failed     atomic.Bool
		collectErr = make(chan error, 1)
	)
	go func() {
		var err error
		for j := range order {
			<-j.done
			if err == nil {
				err = j.err
			}
			if err != nil {
				failed.Store(true)
				continue // drain so the splitter never blocks on a full channel
			}
			chunks = append(chunks, j.ch)
			if err = sink.Add(j.ch, j.ct); err != nil {
				failed.Store(true)
				continue
			}
			select {
			case free <- j.piece[:0]:
			default:
			}
		}
		collectErr <- err
	}()

	var size int64
	splitErr := chunker.SplitStream(r, func(piece []byte) error {
		if failed.Load() {
			return errSealStopped
		}
		size += int64(len(piece))
		var buf []byte
		select {
		case buf = <-free:
		default:
		}
		j := &sealJob{piece: append(buf, piece...), done: make(chan struct{})}
		jobs <- j
		order <- j
		return nil
	})
	close(jobs)
	close(order)
	err := <-collectErr
	wg.Wait()
	if err != nil {
		return nil, 0, err
	}
	if splitErr != nil {
		return nil, 0, splitErr
	}
	return chunks, size, nil
}

// sealSerial is the single-core path: no pool, no copies, chunks sealed inline on
// the split goroutine.
func sealSerial(r io.Reader, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) ([]crypto.Chunk, int64, error) {
	var chunks []crypto.Chunk
	var size int64
	err := chunker.SplitStream(r, func(piece []byte) error {
		ct, ch, err := crypto.SealChunk(piece, conv)
		if err != nil {
			return err
		}
		size += int64(len(piece))
		chunks = append(chunks, ch)
		return sink.Add(ch, ct)
	})
	if err != nil {
		return nil, 0, err
	}
	return chunks, size, nil
}
