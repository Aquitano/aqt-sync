// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"fmt"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// dirMovesManifests builds a tree of leaves directories holding filesPer files each,
// and a copy with every fourth leaf renamed: many independent directory moves, the
// shape a bulk folder rename leaves for status and snapshot diff to explain.
func dirMovesManifests(leaves, filesPer int) (old, cur Manifest) {
	rng := benchRand()
	for l := range leaves {
		dir := fmt.Sprintf("p%02d/leaf%04d", l%16, l)
		moved := dir
		if l%4 == 0 {
			moved += "-renamed"
		}
		old.Dirs = append(old.Dirs, DirEntry{Path: dir, Mode: 0o755})
		cur.Dirs = append(cur.Dirs, DirEntry{Path: moved, Mode: 0o755})
		for f := range filesPer {
			e := benchEntry(rng, fmt.Sprintf("%s/f%02d.txt", dir, f), 512)
			old.Entries = append(old.Entries, e)
			e.Path = fmt.Sprintf("%s/f%02d.txt", moved, f)
			cur.Entries = append(cur.Entries, e)
		}
	}
	for p := range 16 {
		d := DirEntry{Path: fmt.Sprintf("p%02d", p), Mode: 0o755}
		old.Dirs, cur.Dirs = append(old.Dirs, d), append(cur.Dirs, d)
	}
	sortEntries(old.Entries)
	sortEntries(cur.Entries)
	sortDirs(old.Dirs)
	sortDirs(cur.Dirs)
	return old, cur
}

func BenchmarkDiffDirMoves(b *testing.B) {
	old, cur := dirMovesManifests(2000, 20)
	b.Run("manifest", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if d := Diff(old, cur); len(d.Renamed) != 500 {
				b.Fatalf("renamed = %d, want 500 directory moves", len(d.Renamed))
			}
		}
	})
	b.Run("tree", func(b *testing.B) {
		var conv crypto.ConvergenceKey
		copy(conv[:], "bench-convergence-key-3123123123")
		oldSink, curSink := mapSink{}, mapSink{}
		oldRoot, _, err := SealTree(old, conv, oldSink, nil)
		if err != nil {
			b.Fatal(err)
		}
		curRoot, _, err := SealTree(cur, conv, curSink, nil)
		if err != nil {
			b.Fatal(err)
		}
		f := newDiffFetcher(oldSink, curSink)
		b.ReportAllocs()
		for b.Loop() {
			d, err := DiffTreeRoots(oldRoot, curRoot, f.fetch)
			if err != nil {
				b.Fatal(err)
			}
			if len(d.Renamed) != 500 {
				b.Fatalf("renamed = %d, want 500 directory moves", len(d.Renamed))
			}
		}
	})
}
