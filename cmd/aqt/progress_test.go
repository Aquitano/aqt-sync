// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// packio.Uploader honors whatever context it is handed; what only this package can
// prove is that newUploader hands it the root signal context, so a ^C stops a push
// from sealing the rest of the tree. The client is deliberately left on its own
// context: if the adapter dropped rootCtx, the dispatched pack would reach the
// unroutable address and fail with a connection error instead of a cancellation.
func TestNewUploaderObservesRootCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	orig := rootCtx
	rootCtx = ctx
	t.Cleanup(func() { rootCtx = orig })

	cl, err := client.New("https://127.0.0.1:1/", "")
	if err != nil {
		t.Fatal(err)
	}
	up := newUploader(cl, nil)
	cancel()

	var failed error
	for i := 0; i < 64 && failed == nil; i++ {
		failed = up.Add(crypto.Chunk{ID: fmt.Sprintf("chunk-%03d", i), Len: 1 << 20}, make([]byte, 1<<20))
	}
	if failed == nil {
		failed = up.Flush()
	}
	if !errors.Is(failed, context.Canceled) {
		t.Fatalf("cancel surfaced as %v, want context.Canceled", failed)
	}
}

func TestEntriesBytes(t *testing.T) {
	got := entriesBytes([]syncengine.Entry{{Size: 100}, {Size: 250}, {Size: 0}})
	if got != 350 {
		t.Errorf("entriesBytes = %d, want 350", got)
	}
}

// An unsized bar has no total to divide by, so it reports what moved and how fast
// instead of a percentage.
func TestUnsizedBarLine(t *testing.T) {
	const moved = 100 << 20
	p := &progressBar{label: "uploading", unsized: true, start: time.Now().Add(-2 * time.Second)}
	p.done.Store(moved)
	line := p.line()
	for _, want := range []string{"uploading", "100.0 MB", "/s)"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "%") {
		t.Errorf("line %q shows a percentage, but the total is unknown", line)
	}
	// Rate is wall-clock derived, so assert the magnitude rather than an exact string.
	if got := p.rate(moved); got < 40<<20 || got > 60<<20 {
		t.Errorf("rate = %d B/s, want ~50 MiB/s for %d bytes over ~2s", got, moved)
	}
}

// A bar that has moved nothing has no elapsed time to divide by on its first redraw.
func TestUnsizedBarRateZeroBeforeClockAdvances(t *testing.T) {
	p := &progressBar{label: "uploading", unsized: true, start: time.Now().Add(time.Hour)}
	if got := p.rate(1000); got != 0 {
		t.Errorf("rate = %d, want 0 before any time has elapsed", got)
	}
}

// The bar draws nothing until the first byte lands, so a push with nothing to upload
// leaves no line behind — the state the deleted sizing pre-pass used to detect by
// walking the whole tree.
func TestUnsizedBarSilentUntilFirstByte(t *testing.T) {
	p := &progressBar{label: "uploading", unsized: true, start: time.Now(), stop: make(chan struct{})}
	if !p.silent() {
		t.Fatal("an unsized bar must stay silent before any byte moves")
	}
	p.Add(100)
	if p.silent() {
		t.Fatal("the bar must draw once bytes have moved")
	}
}

// finish(true) snaps a sized bar to its total; an unsized bar has none, so snapping
// would zero the count it just reported.
func TestUnsizedBarFinishKeepsCount(t *testing.T) {
	p := &progressBar{label: "uploading", unsized: true, start: time.Now(), stop: make(chan struct{})}
	p.done.Store(500)
	p.finish(true)
	if got := p.done.Load(); got != 500 {
		t.Errorf("finish(true) done = %d, want 500 (an unsized bar has no total to snap to)", got)
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
	p.Add(10)
	p.finish(true)
}

// finish(true) snaps the bar to its total so a completed transfer always reads 100%,
// hiding the undershoot that dedup and inlined files leave.
func TestProgressBarFinishSnapsWhenComplete(t *testing.T) {
	p := &progressBar{stop: make(chan struct{})}
	p.total.Store(1000)
	p.done.Store(400)
	p.finish(true)
	if got := p.done.Load(); got != 1000 {
		t.Errorf("finish(true) done = %d, want 1000 (snap to total)", got)
	}
}

// finish(false) leaves the bar at its last real position so an aborted transfer is not
// drawn as 100%.
func TestProgressBarFinishKeepsPositionOnError(t *testing.T) {
	p := &progressBar{stop: make(chan struct{})}
	p.total.Store(1000)
	p.done.Store(400)
	p.finish(false)
	if got := p.done.Load(); got != 400 {
		t.Errorf("finish(false) done = %d, want 400 (no snap on error)", got)
	}
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
	if _, err := runDownloads(cl, t.TempDir(), entries, prog); err != nil {
		t.Fatalf("runDownloads: %v", err)
	}
	if got := prog.done.Load(); got != 42 {
		t.Errorf("download progress = %d, want 42", got)
	}
}
