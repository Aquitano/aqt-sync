// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// TreeWatcher turns kernel file events under a tracked root into a coalesced
// change signal, so the watch daemon can stop stat-walking the whole tree on a
// short poll interval. It honors the same .aqtignore rules as a scan, so churn in
// an ignored subtree (a .git directory, a build dir) never wakes the watcher.
//
// The signal is advisory, not authoritative: the daemon still fingerprints the
// tree before syncing, and keeps a slow periodic rescan, so a missed event (an
// unwatchable new directory, an event-queue overflow, stale ignore rules) delays
// a sync rather than losing it.
type TreeWatcher struct {
	root    string
	fw      *fsnotify.Watcher
	ig      *Ignore
	watched map[string]bool // rel dirs already added, so a re-walk never double-loads .aqtignore scopes
	events  chan struct{}
}

// WatchTree establishes a recursive watch over every non-ignored directory under
// root. Kernel watches are per-directory, so a tree that exceeds the OS watch
// budget (inotify limits) fails here and the caller falls back to polling.
func WatchTree(root string) (*TreeWatcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &TreeWatcher{
		root:    root,
		fw:      fw,
		ig:      newIgnore(),
		watched: map[string]bool{},
		events:  make(chan struct{}, 1),
	}
	if err := w.addTree(root, true); err != nil {
		_ = fw.Close()
		return nil, err
	}
	go w.pump()
	return w, nil
}

// Events yields one signal per burst of relevant file activity (coalesced: an
// undrained channel absorbs further signals). It is never closed; after Close the
// channel simply goes quiet.
func (w *TreeWatcher) Events() <-chan struct{} { return w.events }

func (w *TreeWatcher) Close() error { return w.fw.Close() }

// addTree walks the directories under dir (itself included), loading each level's
// .aqtignore and adding a watch per non-ignored directory. strict propagates Add
// errors — setup fails loud so the daemon can fall back to polling — while the
// runtime path (a directory created mid-watch) swallows them, leaving that subtree
// to the periodic rescan.
func (w *TreeWatcher) addTree(dir string, strict bool) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // churn during the walk: the dir is already gone
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(w.root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = ""
		} else if w.ig.Match(rel, true) {
			return filepath.SkipDir
		}
		if w.watched[rel] {
			return nil
		}
		w.ig.loadDir(path, rel)
		if err := w.fw.Add(path); err != nil {
			if strict {
				return err
			}
			return nil // over the watch budget mid-run: the rescan covers this subtree
		}
		w.watched[rel] = true
		return nil
	})
}

// pump translates raw fsnotify traffic into the coalesced signal. It exits when
// Close shuts the underlying watcher. Errors (including event-queue overflow) are
// signaled like changes: a scan reconciles whatever was missed.
func (w *TreeWatcher) pump() {
	for {
		select {
		case ev, ok := <-w.fw.Events:
			if !ok {
				return
			}
			w.handle(ev)
		case _, ok := <-w.fw.Errors:
			if !ok {
				return
			}
			w.signal()
		}
	}
}

func (w *TreeWatcher) handle(ev fsnotify.Event) {
	rel, err := filepath.Rel(w.root, ev.Name)
	if err != nil {
		return
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		w.signal()
		return
	}
	// An edited .aqtignore changes what is watched and filtered: rebuild the rule
	// set and re-walk for newly-unignored directories. Watches on newly-ignored
	// dirs stay behind but their events are filtered by the fresh rules.
	if filepath.Base(rel) == ignoreFile {
		w.ig = newIgnore()
		w.watched = map[string]bool{}
		_ = w.addTree(w.root, false)
		w.signal()
		return
	}
	info, statErr := os.Lstat(ev.Name)
	isDir := statErr == nil && info.IsDir()
	// For a removed path Lstat fails and isDir is a guess; a dirOnly ignore rule
	// then misses and we signal spuriously — one wasted scan, not a missed change.
	if w.ig.Match(rel, isDir) {
		return
	}
	if isDir && ev.Op.Has(fsnotify.Create) {
		// Watch a new subtree before its children churn. Files already inside
		// (created between mkdir and this walk) are caught by the walk itself.
		_ = w.addTree(ev.Name, false)
	}
	w.signal()
}

func (w *TreeWatcher) signal() {
	select {
	case w.events <- struct{}{}:
	default:
	}
}
