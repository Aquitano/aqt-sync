// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDiffLocalRemoteSnapshotAndBinary(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes/a.txt", "one\ntwo\nthree\n")
	writeTree(t, origin, "skip.txt", "unchanged\n")
	chunkLines := make([]string, 700)
	for i := range chunkLines {
		chunkLines[i] = fmt.Sprintf("chunk line %04d", i)
	}
	writeTree(t, origin, "chunked.txt", strings.Join(chunkLines, "\n")+"\n")
	if err := os.WriteFile(filepath.Join(origin, "blob.bin"), []byte("old\x00binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cl.CreateSnapshot(h.folderID(origin), nil, false)
	if err != nil {
		t.Fatal(err)
	}

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	writeTree(t, replica, "notes/a.txt", "one\nTWO\nthree\n")
	writeTree(t, replica, "skip.txt", "local-only change\n")
	chunkLines[350] = "chunk line changed locally"
	writeTree(t, replica, "chunked.txt", strings.Join(chunkLines, "\n")+"\n")
	if err := os.WriteFile(filepath.Join(replica, "blob.bin"), []byte("new\x00binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	var runErr error
	localOut := captureStdout(t, func() {
		runErr = runDiff(replica, []string{"notes"}, diffOptions{})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	for _, want := range []string{"--- a/notes/a.txt", "+++ b/notes/a.txt", "-two", "+TWO"} {
		if !strings.Contains(localOut, want) {
			t.Fatalf("local diff missing %q:\n%s", want, localOut)
		}
	}
	if strings.Contains(localOut, "skip.txt") {
		t.Fatalf("path filter leaked skip.txt:\n%s", localOut)
	}
	chunkedOut := captureStdout(t, func() {
		runErr = runDiff(replica, []string{"chunked.txt"}, diffOptions{})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(chunkedOut, "-chunk line 0350\n+chunk line changed locally") {
		t.Fatalf("chunked diff did not materialize base content:\n%s", chunkedOut)
	}

	binaryOut := captureStdout(t, func() {
		runErr = runDiff(replica, []string{"blob.bin"}, diffOptions{})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(binaryOut, "Binary files a/blob.bin and b/blob.bin differ") {
		t.Fatalf("binary marker missing:\n%s", binaryOut)
	}

	writeTree(t, origin, "notes/a.txt", "ONE\ntwo\nthree\n")
	h.sync(origin)
	remoteOut := captureStdout(t, func() {
		runErr = runDiff(replica, nil, diffOptions{remote: true})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(remoteOut, "-one\n+ONE") || strings.Contains(remoteOut, "TWO") || strings.Contains(remoteOut, "skip.txt") {
		t.Fatalf("remote diff did not isolate incoming changes:\n%s", remoteOut)
	}

	if err := os.Remove(controlPath(replica, baseFile)); err != nil {
		t.Fatal(err)
	}
	snapshotOut := captureStdout(t, func() {
		runErr = runDiff(replica, []string{"notes/a.txt"}, diffOptions{against: snapshot.ID})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(snapshotOut, "-two\n+TWO") {
		t.Fatalf("snapshot diff missing local edit:\n%s", snapshotOut)
	}
}

func TestDiffInvocationUsesOnlyTrackedRootAsDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".aqt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if dir, paths := diffInvocation([]string{"notes", root}); dir != root || len(paths) != 1 || paths[0] != "notes" {
		t.Fatalf("tracked-root invocation = (%q, %v)", dir, paths)
	}
	if dir, paths := diffInvocation([]string{"notes"}); dir != "." || len(paths) != 1 {
		t.Fatalf("path-only invocation = (%q, %v)", dir, paths)
	}
}

func TestNormalizeDiffPathsRejectsEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := normalizeDiffPaths(root, root, []string{"../outside"}); err == nil {
		t.Fatal("expected escaping path to be rejected")
	}
}

// countingWriter tallies the response bytes a proxied request serves.
type countingWriter struct {
	http.ResponseWriter
	n *atomic.Int64
}

func (w *countingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.n.Add(int64(n))
	return n, err
}

// A classified path list is a metadata question. Answering it must not stream the
// snapshot's file content back, let alone reconstruct the tree on disk — a folder is
// arbitrarily larger than the answer, and the reconstruction lands in the shared temp
// directory in plaintext.
func TestDiffAgainstSnapshotPathLevelSkipsContent(t *testing.T) {
	var counting atomic.Bool
	var served atomic.Int64
	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if counting.Load() {
			pass(&countingWriter{ResponseWriter: w, n: &served}, r)
			return
		}
		pass(w, r)
	})
	origin := t.TempDir()
	h.init(origin)

	// Incompressible, so the transfer cost of the content is not optimized away and
	// the assertion below measures what it means to measure.
	rng := rand.New(rand.NewSource(1))
	bulk := make([]byte, 4<<20)
	if _, err := rng.Read(bulk); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origin, "bulk.bin"), bulk, 0o644); err != nil {
		t.Fatal(err)
	}
	writeTree(t, origin, "notes.txt", "one\n")
	h.sync(origin)

	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cl.CreateSnapshot(h.folderID(origin), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// Only the small file moves. The bulk file is identical on both sides, so nothing
	// about it needs to travel to classify the difference.
	writeTree(t, origin, "notes.txt", "two\n")

	counting.Store(true)
	var runErr error
	out := captureStdout(t, func() {
		runErr = runDiff(origin, nil, diffOptions{against: snapshot.ID, nameStatus: true})
	})
	counting.Store(false)
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(out, "M  notes.txt") {
		t.Fatalf("path-level snapshot comparison did not report the edit:\n%s", out)
	}
	if strings.Contains(out, "bulk.bin") {
		t.Fatalf("unchanged file reported as differing:\n%s", out)
	}
	if got := served.Load(); got > int64(len(bulk))/4 {
		t.Errorf("path-level comparison served %d bytes for a %d-byte folder; it is still transferring content", got, len(bulk))
	}
}
