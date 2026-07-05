package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

// progressBar renders a single-line transfer bar to stderr while bytes move. It is
// opt-in (--progress) and only draws on a terminal, so scripted/CI output is
// unchanged. Every method is nil-safe: when progress is off newProgressBar returns
// nil and all calls are no-ops, so call sites need no conditionals. add() is called
// from the upload/download worker pools, so it must stay a lock-free atomic add.
type progressBar struct {
	label string
	total atomic.Int64
	done  atomic.Int64
	stop  chan struct{}
	wg    sync.WaitGroup
}

// progressInterval is the redraw cadence: fast enough to feel live, slow enough not
// to flood a slow terminal.
const progressInterval = 100 * time.Millisecond

// newProgressBar starts a bar labeled label. A positive total renders a percentage
// bar with bytes remaining; total <= 0 means "no bar" (there is nothing to size, or
// progress is off / stderr is not a terminal), returning a nil no-op bar.
func newProgressBar(label string, total int64) *progressBar {
	if total <= 0 || !flagProgress || !term.IsTerminal(int(os.Stderr.Fd())) {
		return nil
	}
	p := &progressBar{label: label, stop: make(chan struct{})}
	p.total.Store(total)
	p.wg.Add(1)
	go p.run()
	return p
}

func (p *progressBar) add(n int64) {
	if p == nil {
		return
	}
	p.done.Add(n)
}

// finish snaps the bar to its total (hiding the undershoot that dedup leaves), draws
// a final line, and stops the redraw goroutine. Safe to call once on every path.
func (p *progressBar) finish() {
	if p == nil {
		return
	}
	p.done.Store(p.total.Load())
	close(p.stop)
	p.wg.Wait()
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
			fmt.Fprint(os.Stderr, "\r\033[K"+p.line())
		}
	}
}

// line formats the current bar: label, a filled bar, percent, bytes transferred over
// total, and bytes remaining.
func (p *progressBar) line() string {
	total := p.total.Load()
	done := p.done.Load()
	if done > total {
		done = total
	}
	pct := float64(done) / float64(total)
	const width = 24
	filled := int(pct * width)
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
	return fmt.Sprintf("%s [%s] %3.0f%%  %s / %s  (%s left)",
		p.label, bar, pct*100, humanBytes(done), humanBytes(total), humanBytes(total-done))
}
