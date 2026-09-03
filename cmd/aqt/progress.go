// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/cliutil"
)

// progressBar renders a single-line transfer bar to stderr while bytes move. It is
// opt-in (--progress) and only draws on a terminal, so scripted/CI output is
// unchanged. Every method is nil-safe: when progress is off newProgressBar returns
// nil and all calls are no-ops, so call sites need no conditionals. Add() is called
// from the upload/download worker pools, so it must stay a lock-free atomic add.
type progressBar struct {
	label string
	total atomic.Int64
	done  atomic.Int64
	// unsized bars have no total: they report bytes moved and a rate. Set once before
	// the redraw goroutine starts, so it needs no synchronization.
	unsized bool
	start   time.Time
	stop    chan struct{}
	wg      sync.WaitGroup
}

// progressInterval is the redraw cadence: fast enough to feel live, slow enough not
// to flood a slow terminal.
const progressInterval = 100 * time.Millisecond

// progressActive reports whether a --progress bar would actually draw: the flag is set
// and stderr is a terminal.
func progressActive() bool {
	return flagProgress && term.IsTerminal(int(os.Stderr.Fd()))
}

// newProgressBar starts a bar labeled label. A positive total renders a percentage
// bar with bytes remaining; total <= 0 means "no bar" (there is nothing to size, or
// progress is off / stderr is not a terminal), returning a nil no-op bar.
func newProgressBar(label string, total int64) *progressBar {
	if total <= 0 || !progressActive() {
		return nil
	}
	p := &progressBar{label: label, start: time.Now(), stop: make(chan struct{})}
	p.total.Store(total)
	p.wg.Add(1)
	go p.run()
	return p
}

// newUnsizedBar starts a bar for a transfer whose total is not known up front, so it
// reports bytes moved and the rate instead of a percentage. A push is that transfer:
// it discovers what it will send only by walking the tree, and that walk is the
// upload. The bar stays silent until the first byte lands, so a sync with nothing to
// upload draws nothing at all.
func newUnsizedBar(label string) *progressBar {
	if !progressActive() {
		return nil
	}
	p := &progressBar{label: label, unsized: true, start: time.Now(), stop: make(chan struct{})}
	p.wg.Add(1)
	go p.run()
	return p
}

func (p *progressBar) Add(n int64) {
	if p == nil {
		return
	}
	p.done.Add(n)
}

// finish stops the redraw goroutine and draws a final line. On a completed transfer it
// snaps the bar to its total, hiding the undershoot that dedup and inlined files leave;
// on an error it leaves the bar at its last real position so a failed transfer is not
// drawn as 100%. Safe to call once on every path.
func (p *progressBar) finish(completed bool) {
	if p == nil {
		return
	}
	if completed && !p.unsized {
		p.done.Store(p.total.Load())
	}
	close(p.stop)
	p.wg.Wait()
	if p.silent() {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K"+p.line()+"\n")
}

func (p *progressBar) run() {
	defer p.wg.Done()
	t := time.NewTicker(progressInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			if p.silent() {
				continue
			}
			fmt.Fprint(os.Stderr, "\r\033[K"+p.line())
		}
	}
}

// silent reports whether the bar has nothing to show yet: an unsized bar before its
// first byte. Nothing is drawn then, so a transfer that moves no bytes leaves no line.
func (p *progressBar) silent() bool {
	return p.unsized && p.done.Load() == 0
}

// line formats the current bar: label, a filled bar, percent, bytes transferred over
// total, and bytes remaining. An unsized bar has no percentage to render, so it shows
// bytes moved and the rate they moved at.
func (p *progressBar) line() string {
	total := p.total.Load()
	done := p.done.Load()
	if p.unsized {
		return fmt.Sprintf("%s  %s  (%s/s)", p.label, cliutil.HumanBytes(done), cliutil.HumanBytes(p.rate(done)))
	}
	if done > total {
		done = total
	}
	pct := float64(done) / float64(total)
	const width = 24
	// Truncate both the fill and the percent (not round) so the number never reads 100%
	// while the bar still has an empty cell.
	filled := int(pct * width)
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
	return fmt.Sprintf("%s [%s] %3d%%  %s / %s  (%s left)",
		p.label, bar, int(pct*100), cliutil.HumanBytes(done), cliutil.HumanBytes(total), cliutil.HumanBytes(total-done))
}

// rate is the average bytes per second since the bar started, rounded down. It reads
// 0 until the clock has advanced, which keeps the first redraw from dividing by zero.
func (p *progressBar) rate(done int64) int64 {
	elapsed := time.Since(p.start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return int64(float64(done) / elapsed)
}
