// SPDX-License-Identifier: AGPL-3.0-or-later

// Package packio moves chunk objects between a tracked folder and the server's
// packs: a bounded uploader that batches sealed chunks into packs, and a source
// that range-fetches them back through a byte-bounded LRU.
package packio

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// Progress is credited the plaintext byte count of each batch a transfer confirms.
// A nil Progress disables the accounting.
type Progress interface {
	Add(n int64)
}

type noProgress struct{}

func (noProgress) Add(int64) {}

// Uploader is the syncengine.ChunkSink a push feeds. It buffers sealed chunks up to
// ~syncengine.DefaultPackTarget, then hands the batch to a bounded pool that asks the
// server which chunks it lacks, packs only those, and uploads the pack. Dispatching
// to the pool instead of uploading inline overlaps chunking with the two upload
// round-trips, so the CPU keeps sealing the next pack while earlier ones are in
// flight — the win over a WAN, where each pack otherwise cost two sequential RTTs of
// pure stall.
//
// The pool is bounded: group.Go blocks once limit packs are in flight, which is the
// backpressure that keeps push memory at O(limit packs) rather than O(tree). A
// per-run seen set dedups a chunk shared by several files within the same sync; it
// and the candidate buffer are touched only by the single producer goroutine
// (syncengine.Take calls Add sequentially), while workers touch only their own batch
// and the concurrency-safe client, so no further synchronization is needed.
type Uploader struct {
	cl       *client.Client
	target   int
	seen     map[string]bool
	cand     []candidate
	candSize int
	group    *errgroup.Group
	ctx      context.Context
	waitOnce sync.Once
	waitErr  error
	prog     Progress
}

type candidate struct {
	id   string
	ct   []byte
	size int // plaintext length, for progress accounting
}

// NewUploader returns an uploader running at most limit uploads at once. Parent ctx
// on the signal context so a ^C stops queued uploads from dispatching, not just the
// in-flight requests the bound client kills itself.
func NewUploader(ctx context.Context, cl *client.Client, prog Progress, limit int) *Uploader {
	if prog == nil {
		prog = noProgress{}
	}
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	return &Uploader{cl: cl, target: syncengine.DefaultPackTarget, seen: map[string]bool{}, group: g, ctx: ctx, prog: prog}
}

// Add buffers one sealed chunk, dispatching a pack once the buffer reaches the target.
func (u *Uploader) Add(ch crypto.Chunk, ciphertext []byte) error {
	if u.seen[ch.ID] {
		return nil
	}
	u.seen[ch.ID] = true
	// Dispatch-before-append when this object would push the assembled pack past
	// the wire cap (see syncengine.FitsInPack); the target flush below runs after
	// the append and cannot catch that case.
	if u.candSize > 0 && !syncengine.FitsInPack(u.candSize, len(u.cand), len(ciphertext)) {
		if err := u.dispatch(); err != nil {
			return err
		}
	}
	u.cand = append(u.cand, candidate{id: ch.ID, ct: ciphertext, size: ch.Len})
	u.candSize += len(ciphertext)
	if u.candSize >= u.target {
		return u.dispatch()
	}
	return nil
}

// Flush dispatches any buffered remainder, then waits for every in-flight upload;
// call once after the snapshot pass. The manifest PUT that roots these objects must
// not race ahead of them, so Flush is the barrier that guarantees they are all stored.
func (u *Uploader) Flush() error {
	if err := u.dispatch(); err != nil {
		return err
	}
	return u.Wait()
}

// Wait blocks until all dispatched uploads finish and returns the first error. It is
// idempotent — errgroup.Wait must not be called twice — so a caller can drain the
// pool on a snapshot error and still have Flush return the same result on success.
func (u *Uploader) Wait() error {
	u.waitOnce.Do(func() { u.waitErr = u.group.Wait() })
	return u.waitErr
}

// dispatch hands the buffered candidates to an upload worker and resets the buffer,
// transferring ownership of the batch. group.Go blocks when limit uploads are
// already running — the backpressure that bounds memory. If a prior upload already
// failed the group context is cancelled, so stop feeding work and surface that error.
func (u *Uploader) dispatch() error {
	if len(u.cand) == 0 {
		return nil
	}
	batch := u.cand
	u.cand = nil
	u.candSize = 0
	if u.ctx.Err() != nil {
		// The batch was just detached and is being dropped, so success must not
		// be reported. A worker failure surfaces through Wait; a root cancel
		// leaves the group error-free (the context is no longer only canceled by
		// failing workers, it parents on the caller's context), so the cancellation itself is
		// the error — returning nil here would let a ^C'd push keep sealing the
		// rest of the tree and report every dropped pack as uploaded.
		if err := u.Wait(); err != nil {
			return err
		}
		return context.Cause(u.ctx)
	}
	u.group.Go(func() error { return u.upload(batch) })
	return nil
}

// upload runs one pack's have/want gate and PutPack. It owns cand exclusively (each
// ciphertext is an independent SealChunk allocation), so it needs no locking.
func (u *Uploader) upload(cand []candidate) error {
	ids := make([]string, len(cand))
	var batchBytes int64
	for i, c := range cand {
		ids[i] = c.id
		batchBytes += int64(c.size)
	}
	missing, err := u.cl.CheckChunks(ids)
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(missing))
	for _, id := range missing {
		want[id] = true
	}
	pb := syncengine.NewPackBuilder()
	for _, c := range cand {
		if want[c.id] {
			pb.Add(c.id, c.ct)
		}
	}
	// Count the batch's plaintext bytes as done once it is confirmed on the server,
	// whether it was uploaded or already present (dedup) — so the bar reflects content
	// committed, not bytes on the wire, and still reaches the total on a re-sync.
	if pb.Empty() {
		u.prog.Add(batchBytes) // every candidate already on the server (a re-sync)
		return nil
	}
	packID, pack := pb.Finish()
	if err := u.cl.PutPack(packID, pack); err != nil {
		return err
	}
	u.prog.Add(batchBytes)
	return nil
}
