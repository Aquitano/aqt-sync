package syncengine

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

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
	big := make([]byte, segTarget+1234) // spans more than one segment
	for i := range big {
		big[i] = byte(i)
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
	manifest, err := ExtractToTree(dst, root, ck, store.get)
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
	if _, err := ExtractToTree(t.TempDir(), root, ck, store.get); err == nil {
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
	if _, err := ExtractToTree(t.TempDir(), root, testContentKey(t), store.get); err == nil {
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

	// Seal the hostile tar into segments exactly as TarAndSeal would, so it travels
	// the real ExtractToTree path.
	ck := testContentKey(t)
	ss := &segmentSink{ck: ck, sink: memObjects{}}
	store := ss.sink.(memObjects)
	if _, err := ss.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := ss.finish(); err != nil {
		t.Fatal(err)
	}
	root := PackRoot{Version: PackRootVersion, Size: int64(tarBuf.Len()), Segments: ss.segments}

	if _, err := ExtractToTree(t.TempDir(), root, ck, store.get); err == nil {
		t.Fatal("extract accepted a symlink-traversal archive")
	}
	if _, err := os.Stat(filepath.Join(outside, "payload")); err == nil {
		t.Fatal("hostile archive escaped the tracked root: payload written outside")
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
