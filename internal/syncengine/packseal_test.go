package syncengine

import (
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
	root, err := TarAndSeal(src, ck, store)
	if err != nil {
		t.Fatalf("TarAndSeal: %v", err)
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

	first, err := TarAndSeal(src, ck, memObjects{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := TarAndSeal(src, ck, memObjects{})
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
	root, err := TarAndSeal(src, ck, store)
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
	root, err := TarAndSeal(src, testContentKey(t), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractToTree(t.TempDir(), root, testContentKey(t), store.get); err == nil {
		t.Fatal("extract accepted the wrong content key")
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
