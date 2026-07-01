package syncengine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

func scanEntry(t *testing.T, m Manifest, path string) Entry {
	t.Helper()
	e, ok := m.ByPath()[path]
	if !ok {
		t.Fatalf("entry %q missing from manifest", path)
	}
	return e
}

// A file whose size, mode, and mtime match its base entry must reuse the base
// entry verbatim — hash and content refs included — without being read. The
// sentinel hash proves no re-hash happened: a content read would replace it.
func TestScanReusingStatFastPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	base, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	realHash := scanEntry(t, base, "a.txt").Hash

	sentinel := "sentinel-not-a-real-hash"
	chunks := []crypto.Chunk{{ID: "deadbeef", Key: []byte("k"), Len: 5}}
	for i := range base.Entries {
		base.Entries[i].Hash = sentinel
		base.Entries[i].Chunks = chunks
	}

	got, err := ScanReusing(dir, &base, false)
	if err != nil {
		t.Fatal(err)
	}
	e := scanEntry(t, got, "a.txt")
	if e.Hash != sentinel {
		t.Fatalf("stat fast-path re-hashed the file: hash=%q", e.Hash)
	}
	if len(e.Chunks) != 1 || e.Chunks[0].ID != "deadbeef" {
		t.Fatal("stat fast-path must carry the base entry's content refs")
	}

	// rehash forces the content hash even when the stat matches.
	got, err = ScanReusing(dir, &base, true)
	if err != nil {
		t.Fatal(err)
	}
	if scanEntry(t, got, "a.txt").Hash != realHash {
		t.Fatal("rehash must compute the real content hash")
	}
}

// A touched file (new mtime, same content) is re-hashed once, then keeps its base
// entry with the fresh mtime so the next scan stat-fast-paths it again. A real
// edit gets a new hash and drops the stale refs.
func TestScanReusingRehashOnStatMiss(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	chunks := []crypto.Chunk{{ID: "deadbeef", Key: []byte("k"), Len: 5}}
	for i := range base.Entries {
		base.Entries[i].Chunks = chunks
	}

	newTime := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	got, err := ScanReusing(dir, &base, false)
	if err != nil {
		t.Fatal(err)
	}
	e := scanEntry(t, got, "a.txt")
	if e.Hash != scanEntry(t, base, "a.txt").Hash {
		t.Fatal("unchanged content must keep the base hash")
	}
	if len(e.Chunks) != 1 {
		t.Fatal("unchanged content must keep the base entry's content refs")
	}
	if e.MTime != newTime.UnixNano() {
		t.Fatal("reused entry must adopt the new mtime")
	}

	if err := os.WriteFile(path, []byte("edited content"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = ScanReusing(dir, &base, false)
	if err != nil {
		t.Fatal(err)
	}
	e = scanEntry(t, got, "a.txt")
	if e.Hash == scanEntry(t, base, "a.txt").Hash {
		t.Fatal("an edited file must get a new hash")
	}
	if len(e.Chunks) != 0 {
		t.Fatal("an edited file must not carry stale content refs")
	}
}

// A zero base mtime (an entry recorded before mtimes existed) never stat-matches,
// so the content is hashed rather than blindly trusted.
func TestScanReusingZeroMTimeForcesHash(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	realHash := scanEntry(t, base, "a.txt").Hash
	for i := range base.Entries {
		base.Entries[i].MTime = 0
		base.Entries[i].Hash = "sentinel"
	}
	got, err := ScanReusing(dir, &base, false)
	if err != nil {
		t.Fatal(err)
	}
	if scanEntry(t, got, "a.txt").Hash != realHash {
		t.Fatal("a zero base mtime must force a content hash")
	}
}
