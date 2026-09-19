// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/packio"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// uploadConcurrency bounds how many packs are checked-and-uploaded at once. Uploads
// are IO-bound (two round-trips plus server ingest), so a small fixed fan-out hides
// latency without a per-core thread; it also caps peak push memory at roughly this
// many packs (each in-flight upload holds a candidate buffer plus its assembled pack,
// both ~DefaultPackTarget).
const uploadConcurrency = 4

// newUploader binds a pack uploader to the root signal context and this stage's
// transfer limit.
func (app *application) newUploader(cl *client.Client, prog *progressBar) *packio.Uploader {
	return packio.NewUploader(app.ctx, cl, prog, syncTransferLimit(uploadConcurrency))
}

// syncTransferLimit is the errgroup concurrency for a transfer stage, normally the
// given fan-out. AQT_SYNC_SERIAL=1 forces it to 1 so the multi-device sim's crash-fault
// injection is seed-deterministic: with a single request in flight per stage, which
// request the injector aborts no longer depends on goroutine scheduling.
func syncTransferLimit(n int) int {
	if os.Getenv("AQT_SYNC_SERIAL") == "1" {
		return 1
	}
	return n
}

// downloadConcurrency bounds how many files a pull materializes at once. Downloads
// are IO-bound (each file range-fetches its packs, then writes them out), so a small
// fixed fan-out overlaps the network latency of independent files without a
// per-core thread. The shared packio.Source is concurrency-safe, and every file lands
// at a distinct path, so the content-addressed model makes the parallelism trivially
// correct — no file's bytes depend on another's.
const downloadConcurrency = 6

// locateBatchChunks bounds how many chunk locations one download resolves at a time.
// The ciphertext a pull holds is O(one pack), but the location index is not: at the
// default fine profile (~8 KiB average chunk) each located object costs a few hundred
// bytes, so resolving a whole tree up front cost a gigabyte of index on a 20 GB clone
// before a single byte was written. Files are located and materialized in batches of
// about this many chunks and each batch's index is dropped once its files land, which
// caps that at tens of megabytes; the pack LRU carries across batches, so a pack two
// batches share is still fetched once.
const locateBatchChunks = 50_000

// runDownloads materializes each entry under root, streaming its chunks from the
// packs that hold them. A pack-backed chunk source range-fetches packs on demand
// and caches a few, so neither a whole file nor the whole tree is ever in memory.
// Files are materialized by a bounded worker pool; the first error wins and is
// returned, matching the upload pipeline's aggregation. The returned map gives each
// written file's resulting mtime, keyed by path, for the caller's base manifest.
func runDownloads(cl *client.Client, slices sliceFetch, root string, entries []syncengine.Entry, prog *progressBar) (map[string]int64, error) {
	src := packio.NewEmptySource(cl)
	cache := packio.NewCache(packio.DefaultCacheBytes)
	mtimes := make(map[string]int64, len(entries))
	for _, batch := range batchByChunks(entries, locateBatchChunks) {
		get := src.Get
		if slices != nil {
			get = newPublicEntrySource(slices, batch, cache)
		} else if err := src.Locate(distinctChunkIDs(batch)); err != nil {
			return nil, err
		}
		batchMTimes, err := runDownloadsFrom(get, root, batch, prog)
		if err != nil {
			return nil, err
		}
		for path, mtime := range batchMTimes {
			mtimes[path] = mtime
		}
		src.ForgetLocations()
	}
	return mtimes, nil
}

// batchByChunks splits entries into runs of at most maxChunks chunk records, never
// splitting a file: one file with more chunks than the bound is simply its own batch.
func batchByChunks(entries []syncengine.Entry, maxChunks int) [][]syncengine.Entry {
	var batches [][]syncengine.Entry
	start, count := 0, 0
	for i, e := range entries {
		if count > 0 && count+len(e.Chunks) > maxChunks {
			batches = append(batches, entries[start:i])
			start, count = i, 0
		}
		count += len(e.Chunks)
	}
	if start < len(entries) {
		batches = append(batches, entries[start:])
	}
	return batches
}

// runDownloadsFrom is runDownloads with the chunk source already chosen, so the
// link-holder paths can materialize entries through the public object endpoint
// with the same worker pool the authed pack path uses.
func runDownloadsFrom(get func(id string) ([]byte, error), root string, entries []syncengine.Entry, prog *progressBar) (map[string]int64, error) {
	// Landing these entries on a case-folding filesystem would silently collapse
	// case-twins into one file; refuse before the first write.
	if syncengine.CaseInsensitiveDir(root) {
		if err := refuseCaseCollisions(entries, nil); err != nil {
			return nil, err
		}
	}
	// One probe decides for all of this batch's symlinks. A skipped link is still
	// recorded in the caller's base, and the scan reads its absence as inability
	// rather than a delete (keepUnsupportedLinks), so the folder stays usable.
	skipLinks := false
	for _, e := range entries {
		if e.IsSymlink() {
			skipLinks = !syncengine.SymlinkSupport(root)
			break
		}
	}
	var g errgroup.Group
	g.SetLimit(syncTransferLimit(downloadConcurrency))
	var mu sync.Mutex
	mtimes := make(map[string]int64, len(entries))
	var skippedLinks []string
	for _, e := range entries {
		g.Go(func() error {
			if e.IsSymlink() {
				if skipLinks {
					mu.Lock()
					skippedLinks = append(skippedLinks, e.Path)
					mu.Unlock()
					prog.Add(e.Size)
					return nil
				}
				if err := syncengine.WriteSymlink(root, e); err != nil {
					return err
				}
			} else {
				mtime, err := syncengine.MaterializeFile(root, e, get)
				if err != nil {
					return err
				}
				mu.Lock()
				mtimes[e.Path] = mtime
				mu.Unlock()
			}
			prog.Add(e.Size)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	if len(skippedLinks) > 0 {
		sort.Strings(skippedLinks)
		const show = 3
		named := strings.Join(skippedLinks[:min(show, len(skippedLinks))], ", ")
		if rest := len(skippedLinks) - show; rest > 0 {
			named += fmt.Sprintf(" and %d more", rest)
		}
		fmt.Fprintf(os.Stderr, "warning: skipped %d symlink(s) this filesystem cannot create (on Windows, enable Developer Mode or use an elevated shell): %s\n",
			len(skippedLinks), named)
	}
	return mtimes, nil
}

// stampMTimes records each freshly written file's mtime on its entry in byPath (the
// map that becomes the new base). A remote entry has no mtime of its own, and a base
// entry without one never matches a stat, so skipping this leaves `status`, the TUI,
// and the next sync re-reading and re-hashing every file the pull just wrote.
func stampMTimes(byPath map[string]syncengine.Entry, mtimes map[string]int64) {
	for path, mtime := range mtimes {
		if e, ok := byPath[path]; ok {
			e.MTime = mtime
			byPath[path] = e
		}
	}
}

func distinctChunkIDs(entries []syncengine.Entry) []string {
	seen := map[string]bool{}
	var ids []string
	for _, e := range entries {
		for _, ch := range e.Chunks {
			if !seen[ch.ID] {
				seen[ch.ID] = true
				ids = append(ids, ch.ID)
			}
		}
	}
	return ids
}

// entriesBytes sums the plaintext size of a set of entries — the logical volume a
// transfer moves, used for the pre-transfer total and the summary.
func entriesBytes(entries []syncengine.Entry) int64 {
	var n int64
	for _, e := range entries {
		n += e.Size
	}
	return n
}
