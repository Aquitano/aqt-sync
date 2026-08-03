package syncengine

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aquitano/aqt-sync/internal/compress"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// memObjects is a fake object store: TarAndSeal writes segments into it, ExtractToTree
// reads them back. It stands in for the server's pack store in unit tests.
type memObjects map[string][]byte

func (m memObjects) Add(id string, object []byte) error {
	m[id] = append([]byte(nil), object...)
	return nil
}

func (m memObjects) get(id string) ([]byte, error) {
	b, ok := m[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func testContentKey(t *testing.T) crypto.ContentKey {
	t.Helper()
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	return ck
}

// TestPackRoundTrip seals a tree (small file, nested file, a file larger than a
// segment, and a symlink) and extracts it into a fresh dir byte-for-byte, with a
// manifest that matches a direct Scan of the source — the parity the LWW base
// detection depends on.
func TestPackRoundTrip(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte("hello"))
	writeFile(t, src, "nested/b.txt", []byte("nested body"))
	// Incompressible so the zstd stream stays larger than one segment.
	big := make([]byte, segTarget+1234)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	writeFile(t, src, "big.bin", big)
	if err := os.Symlink("a.txt", filepath.Join(src, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	ck := testContentKey(t)
	store := memObjects{}
	root, shipped, err := TarAndSeal(src, ck, store)
	if err != nil {
		t.Fatalf("TarAndSeal: %v", err)
	}
	// The manifest TarAndSeal reports must match a direct Scan, so pushPack can
	// record it as the base without a Scan/re-walk disagreement.
	if scan, err := Scan(src); err != nil {
		t.Fatal(err)
	} else {
		assertManifestHashesEqual(t, scan, shipped)
	}
	if len(root.Segments) < 2 {
		t.Fatalf("expected the big file to span multiple segments, got %d", len(root.Segments))
	}
	if got := len(root.SegmentIDs()); got != len(root.Segments) {
		t.Fatalf("SegmentIDs count %d != segments %d", got, len(root.Segments))
	}

	dst := t.TempDir()
	manifest, err := ExtractToTree(dst, root, ck, store.get, nil)
	if err != nil {
		t.Fatalf("ExtractToTree: %v", err)
	}

	// Content round-trips exactly.
	for _, f := range []string{"a.txt", "nested/b.txt", "big.bin"} {
		want, _ := os.ReadFile(filepath.Join(src, f))
		got, err := os.ReadFile(filepath.Join(dst, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s did not round-trip", f)
		}
	}
	if target, err := os.Readlink(filepath.Join(dst, "link")); err != nil || target != "a.txt" {
		t.Fatalf("symlink did not round-trip: target=%q err=%v", target, err)
	}

	// The extracted manifest equals a direct scan of the source, so a sync that just
	// pulled would see no local change on the next pass.
	scan, err := Scan(src)
	if err != nil {
		t.Fatal(err)
	}
	assertManifestHashesEqual(t, scan, manifest)
}

// TestPackNonConvergent verifies pack-and-seal keeps no dedup: re-sealing the same
// tree yields entirely different segment ids (fresh nonces), which is what makes
// every change re-ship the whole folder and lets a new sync supersede the last.
func TestPackNonConvergent(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte("stable content"))
	ck := testContentKey(t)

	first, _, err := TarAndSeal(src, ck, memObjects{})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := TarAndSeal(src, ck, memObjects{})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range first.SegmentIDs() {
		for _, other := range second.SegmentIDs() {
			if id == other {
				t.Fatalf("segment id %s repeated across seals; pack-and-seal must not dedup", id)
			}
		}
	}
}

// TestPackSegmentTamperRejected ensures a flipped byte in a stored segment fails the
// content-address/AEAD check on extract rather than landing corrupt bytes on disk.
func TestPackSegmentTamperRejected(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte("trust but verify"))
	ck := testContentKey(t)
	store := memObjects{}
	root, _, err := TarAndSeal(src, ck, store)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the first segment's stored bytes.
	id := root.Segments[0].ID
	store[id][0] ^= 0xff
	if _, err := ExtractToTree(t.TempDir(), root, ck, store.get, nil); err == nil {
		t.Fatal("extract accepted a tampered segment")
	}
}

// TestPackWrongKeyRejected ensures a different content key cannot open the segments.
func TestPackWrongKeyRejected(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte("secret"))
	store := memObjects{}
	root, _, err := TarAndSeal(src, testContentKey(t), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractToTree(t.TempDir(), root, testContentKey(t), store.get, nil); err == nil {
		t.Fatal("extract accepted the wrong content key")
	}
}

// TestExtractRefusesSymlinkTraversal builds a hostile tar by hand — a symlink entry
// pointing out of the tree, then a regular file written through it — seals it as
// pack-and-seal segments, and asserts extraction refuses it rather than landing the
// file at the symlink's target. safeJoin alone would pass both entries (neither path
// contains ".."); refuseSymlinkParents is what stops the escape.
func TestExtractRefusesSymlinkTraversal(t *testing.T) {
	outside := t.TempDir() // stands in for an out-of-tree location the symlink targets

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "evil", Linkname: outside, Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "evil/payload", Mode: 0o644, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("pwned")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	// Seal the hostile tar into segments exactly as TarAndSeal would (compressed,
	// current version), so it travels the real ExtractToTree path.
	ck := testContentKey(t)
	ss := &segmentSink{ck: ck, sink: memObjects{}}
	store := ss.sink.(memObjects)
	zw, err := compress.NewWriter(ss)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ss.finish(); err != nil {
		t.Fatal(err)
	}
	root := PackRoot{Version: PackRootVersion, Size: ss.size, Segments: ss.segments}

	if _, err := ExtractToTree(t.TempDir(), root, ck, store.get, nil); err == nil {
		t.Fatal("extract accepted a symlink-traversal archive")
	}
	if _, err := os.Stat(filepath.Join(outside, "payload")); err == nil {
		t.Fatal("hostile archive escaped the tracked root: payload written outside")
	}
}

// TestExtractLegacyRawTarRoot verifies a version-1 root — raw tar segments sealed
// before compression existed — still extracts, and that a root newer than this
// client is refused instead of misread.
func TestExtractLegacyRawTarRoot(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	body := []byte("legacy body")
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "old.txt", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	ck := testContentKey(t)
	ss := &segmentSink{ck: ck, sink: memObjects{}}
	store := ss.sink.(memObjects)
	if _, err := ss.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := ss.finish(); err != nil {
		t.Fatal(err)
	}
	root := PackRoot{Version: 1, Size: int64(tarBuf.Len()), Segments: ss.segments}

	dst := t.TempDir()
	if _, err := ExtractToTree(dst, root, ck, store.get, nil); err != nil {
		t.Fatalf("extract v1 root: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "old.txt"))
	if err != nil || string(got) != string(body) {
		t.Fatalf("legacy content did not round-trip: got=%q err=%v", got, err)
	}

	root.Version = PackRootVersion + 1
	if _, err := ExtractToTree(t.TempDir(), root, ck, store.get, nil); err == nil {
		t.Fatal("a root newer than this client must be refused")
	}
}

// TestPackRootDoesNotCrossOpenAsTree guards the silent data-loss path: a sealed
// PackRoot and a chunked folder's TreeRoot are byte-compatible JSON under the same
// content key, so without distinct AADs routing a packed folder through the chunked
// path would read it as an empty tree and could wipe the working tree or clone
// nothing. The distinct AADs must make the cross-open fail while each root still
// opens as itself.
func TestPackRootDoesNotCrossOpenAsTree(t *testing.T) {
	ck := testContentKey(t)

	packBlob, err := SealPackRoot(PackRoot{Version: PackRootVersion, Size: 123, Segments: []Segment{{ID: "abc", Len: 10}}}, ck, "res1")
	if err != nil {
		t.Fatal(err)
	}
	treeBlob, err := SealTreeRoot(TreeRoot{Version: TreeManifestVersion, Root: crypto.Chunk{ID: "abc", Key: make([]byte, crypto.KeySize), Len: 4}}, ck, "res1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenTreeRoot(packBlob, ck, "res1"); err == nil {
		t.Fatal("a sealed pack root opened as a tree root; AAD domain separation missing")
	}
	if _, err := OpenPackRoot(treeBlob, ck, "res1"); err == nil {
		t.Fatal("a sealed tree root opened as a pack root; AAD domain separation missing")
	}
	if _, err := OpenPackRoot(packBlob, ck, "res1"); err != nil {
		t.Fatalf("pack root did not open as itself: %v", err)
	}
	if _, err := OpenTreeRoot(treeBlob, ck, "res1"); err != nil {
		t.Fatalf("tree root did not open as itself: %v", err)
	}
}

// TestPackTreeManifestMatchesScan verifies the in-memory compare path: hashing a
// sealed tree straight from its segments yields the same manifest a direct Scan of the
// source does, so remoteEqualsLocal can decide tree equality without materializing the
// remote to disk and deleting it.
func TestPackTreeManifestMatchesScan(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte("hello"))
	writeFile(t, src, "nested/b.txt", []byte("nested body"))
	// Incompressible so the zstd stream stays larger than one segment.
	big := make([]byte, segTarget+777)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	writeFile(t, src, "big.bin", big)
	if err := os.Symlink("a.txt", filepath.Join(src, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	ck := testContentKey(t)
	store := memObjects{}
	root, _, err := TarAndSeal(src, ck, store)
	if err != nil {
		t.Fatal(err)
	}

	hashed, err := PackTreeManifest(root, ck, store.get)
	if err != nil {
		t.Fatalf("PackTreeManifest: %v", err)
	}
	scan, err := Scan(src)
	if err != nil {
		t.Fatal(err)
	}
	assertManifestHashesEqual(t, scan, hashed)
}

// TestExtractReplacesStaleParent covers a remote type change: a path that was a
// regular file or a symlink locally is now a directory. The stale local entry must be
// cleared so extraction can create the directory, instead of aborting on MkdirAll
// (ENOTDIR for a file) or refuseSymlinkParents (for a symlink).
func TestExtractReplacesStaleParent(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "data/inner.txt", []byte("hello"))
	ck := testContentKey(t)
	store := memObjects{}
	root, _, err := TarAndSeal(src, ck, store)
	if err != nil {
		t.Fatal(err)
	}

	for _, stale := range []string{"file", "symlink"} {
		t.Run(stale, func(t *testing.T) {
			dst := t.TempDir()
			switch stale {
			case "file":
				writeFile(t, dst, "data", []byte("stale file where a dir must go"))
			case "symlink":
				if err := os.Symlink("somewhere", filepath.Join(dst, "data")); err != nil {
					t.Skipf("symlinks unsupported: %v", err)
				}
			}
			if _, err := ExtractToTree(dst, root, ck, store.get, nil); err != nil {
				t.Fatalf("extract over stale %s: %v", stale, err)
			}
			got, err := os.ReadFile(filepath.Join(dst, "data", "inner.txt"))
			if err != nil || string(got) != "hello" {
				t.Fatalf("inner.txt not extracted over stale %s: got=%q err=%v", stale, got, err)
			}
		})
	}
}

// TestExtractAppliesDirModesAfterContents covers the ordering the archive forces: the
// walk lists a directory ahead of everything under it, so a mode that denies write must
// not land until the whole stream has been extracted, or the directory locks out its
// own children.
func TestExtractAppliesDirModesAfterContents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows Chmod carries only the write bit, so a non-writable directory is not representable")
	}
	src, dst := t.TempDir(), t.TempDir()
	writeFile(t, src, "locked/inner.txt", []byte("body"))
	if err := os.Mkdir(filepath.Join(src, "locked", "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	// RemoveAll cannot unlink out of a directory it cannot write, so restore the modes
	// before the temp dirs are torn down.
	for _, root := range []string{src, dst} {
		t.Cleanup(func() {
			os.Chmod(filepath.Join(root, "locked", "empty"), 0o700)
			os.Chmod(filepath.Join(root, "locked"), 0o700)
		})
	}
	for _, rel := range []string{"locked/empty", "locked"} {
		if err := os.Chmod(filepath.Join(src, filepath.FromSlash(rel)), 0o500); err != nil {
			t.Fatal(err)
		}
	}

	ck := testContentKey(t)
	store := memObjects{}
	root, _, err := TarAndSeal(src, ck, store)
	if err != nil {
		t.Fatalf("TarAndSeal: %v", err)
	}
	if _, err := ExtractToTree(dst, root, ck, store.get, nil); err != nil {
		t.Fatalf("ExtractToTree: %v", err)
	}

	if got, err := os.ReadFile(filepath.Join(dst, "locked", "inner.txt")); err != nil || string(got) != "body" {
		t.Fatalf("child of a non-writable directory: got=%q err=%v", got, err)
	}
	for _, rel := range []string{"locked", "locked/empty"} {
		fi, err := os.Stat(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o500 {
			t.Errorf("%s mode = %#o, want 0500", rel, got)
		}
	}
}

// TestExtractSafeSkipsVetoedEntry is the drift-guard mechanism the pack pull relies
// on: an entry the safe callback rejects is not written to disk (its local bytes
// survive), but is still hashed from the archive and recorded in the returned
// manifest, so the caller's base always describes the full remote tree.
func TestExtractSafeSkipsVetoedEntry(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "keep.txt", []byte("remote keep"))
	writeFile(t, src, "guarded.txt", []byte("remote body"))

	ck := testContentKey(t)
	store := memObjects{}
	root, _, err := TarAndSeal(src, ck, store)
	if err != nil {
		t.Fatalf("TarAndSeal: %v", err)
	}

	dst := t.TempDir()
	writeFile(t, dst, "guarded.txt", []byte("local edit")) // drifted bytes the guard must keep

	var seen []string
	safe := func(path string) (bool, error) {
		seen = append(seen, path)
		return path != "guarded.txt", nil
	}
	m, err := ExtractToTree(dst, root, ck, store.get, safe)
	if err != nil {
		t.Fatalf("ExtractToTree: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("safe consulted %d times, want 2 (both regular files)", len(seen))
	}

	// The vetoed file keeps its local bytes; the accepted one is written from the archive.
	if got, _ := os.ReadFile(filepath.Join(dst, "guarded.txt")); string(got) != "local edit" {
		t.Fatalf("guarded.txt = %q, want the local bytes preserved", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "keep.txt")); string(got) != "remote keep" {
		t.Fatalf("keep.txt = %q, want the remote bytes written", got)
	}

	// The returned manifest still describes the whole remote tree, including the entry
	// that was not written, carrying the remote hash.
	scan, err := Scan(src)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m.ByPath()["guarded.txt"]
	if !ok {
		t.Fatal("vetoed entry missing from the returned manifest")
	}
	if e.Hash != scan.ByPath()["guarded.txt"].Hash {
		t.Fatalf("recorded hash %q != remote hash %q", e.Hash, scan.ByPath()["guarded.txt"].Hash)
	}
}

func assertManifestHashesEqual(t *testing.T, want, got Manifest) {
	t.Helper()
	wp, gp := want.byPath(), got.byPath()
	if len(wp) != len(gp) {
		t.Fatalf("entry count: scan=%d extract=%d", len(wp), len(gp))
	}
	for path, we := range wp {
		ge, ok := gp[path]
		if !ok {
			t.Fatalf("extract missing %s", path)
		}
		if we.Hash != ge.Hash {
			t.Fatalf("%s hash mismatch: scan=%s extract=%s", path, we.Hash, ge.Hash)
		}
		if we.Link != ge.Link {
			t.Fatalf("%s link mismatch: scan=%q extract=%q", path, we.Link, ge.Link)
		}
		if we.Mode != ge.Mode {
			t.Fatalf("%s mode mismatch: scan=%o extract=%o", path, we.Mode, ge.Mode)
		}
	}
}
