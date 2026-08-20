// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/compress"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func tempSealMemo(t *testing.T) *sealMemo {
	t.Helper()
	dir := t.TempDir()
	c := &nodeCache{dir: dir, budget: nodeCacheBytes}
	return &sealMemo{cache: c, dir: filepath.Join(dir, "seal", "test-codec")}
}

func TestSealMemoRoundTrip(t *testing.T) {
	t.Parallel()
	memo := tempSealMemo(t)
	var conv crypto.ConvergenceKey
	conv[0] = 9
	plain := bytes.Repeat([]byte("node plaintext "), 100)

	coldCT, coldCh, err := crypto.SealNode(plain, conv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := crypto.SealNodeMemo(plain, conv, memo); err != nil {
		t.Fatal(err)
	}
	ct, ch, err := crypto.SealNodeMemo(plain, conv, memo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, coldCT) || ch.ID != coldCh.ID || ch.Alg != coldCh.Alg {
		t.Fatal("disk memo round trip diverged from a cold seal")
	}
}

// Bad on-disk states must read as misses: a mangled index entry (which is also
// dropped so the next seal heals it), and an index whose ciphertext was evicted
// from the id-keyed store.
func TestSealMemoBadEntriesMiss(t *testing.T) {
	t.Parallel()
	memo := tempSealMemo(t)
	digest := bytes.Repeat([]byte("ab"), 32)

	ct := []byte("ciphertext")
	sum := sha256.Sum256(ct)
	memo.PutNodeSeal(string(digest), hex.EncodeToString(sum[:]), "", ct)
	if _, _, _, ok := memo.GetNodeSeal(string(digest)); !ok {
		t.Fatal("healthy entry missed")
	}

	p := memo.path(string(digest))
	if err := os.WriteFile(p, []byte("not an entry"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := memo.GetNodeSeal(string(digest)); ok {
		t.Fatal("mangled index entry hit")
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("mangled index entry was not dropped")
	}
}

// An entry that reads fine but fails SealNodeMemo's verification — here another
// node's valid seal sitting in this digest's slot — must be replaced by the cold
// seal's put, not skipped: left in place it would pin the node to a cold seal on
// every future push.
func TestSealMemoHealsMismatchedEntry(t *testing.T) {
	t.Parallel()
	memo := tempSealMemo(t)
	var conv crypto.ConvergenceKey
	conv[0] = 9
	plainA := bytes.Repeat([]byte("node A plaintext "), 100)
	plainB := bytes.Repeat([]byte("node B plaintext "), 100)

	// Warm the memo for A, then splice B's (perfectly valid) seal into A's slot.
	if _, _, err := crypto.SealNodeMemo(plainA, conv, memo); err != nil {
		t.Fatal(err)
	}
	entries, err := filepath.Glob(filepath.Join(memo.dir, "*", "*"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one index entry, got %v (err %v)", entries, err)
	}
	ctB, chB, err := crypto.SealNode(plainB, conv)
	if err != nil {
		t.Fatal(err)
	}
	memo.cache.put(chB.ID, ctB)
	if err := os.WriteFile(entries[0], []byte(chB.ID+"\n"+chB.Alg+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	coldCT, coldCh, err := crypto.SealNode(plainA, conv)
	if err != nil {
		t.Fatal(err)
	}
	ct, ch, err := crypto.SealNodeMemo(plainA, conv, memo)
	if err != nil || !bytes.Equal(ct, coldCT) || ch.ID != coldCh.ID {
		t.Fatalf("mismatched entry did not degrade to a cold seal (err %v)", err)
	}
	if b, err := os.ReadFile(entries[0]); err != nil || string(b) != coldCh.ID+"\n"+coldCh.Alg+"\n" {
		t.Fatalf("mismatched entry was not healed: %q (err %v)", b, err)
	}
}

func TestSealMemoEvictedCiphertextMisses(t *testing.T) {
	t.Parallel()
	memo := tempSealMemo(t)
	digest := bytes.Repeat([]byte("ef"), 32)
	id := bytes.Repeat([]byte("01"), 32)
	memo.PutNodeSeal(string(digest), string(id), "", []byte("ciphertext"))

	// Evict the ciphertext out from under the index, as the LRU prune may.
	if err := os.Remove(memo.cache.path(string(id))); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := memo.GetNodeSeal(string(digest)); ok {
		t.Fatal("entry with evicted ciphertext hit")
	}
}

func TestSealMemoRejectsBadNames(t *testing.T) {
	t.Parallel()
	memo := tempSealMemo(t)
	memo.PutNodeSeal("../escape", "0123", "", []byte("x"))
	if _, _, _, ok := memo.GetNodeSeal("../escape"); ok {
		t.Fatal("non-digest name hit")
	}
	if entries, err := os.ReadDir(memo.dir); err == nil && len(entries) != 0 {
		t.Fatal("non-digest name created entries")
	}
}

// The issue's prune gate, end to end: push a folder, change one file, push again
// (the second seal reuses the first push's memo entries), then prune. Prune
// re-seals the downloaded manifest and refuses unless the recomputed root matches
// the stored one, so it passing proves a reused push wrote the same root and refs
// a cold seal would — and the clone proves no live object was collected.
func TestSealMemoReuseAcrossSyncAndPrune(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	writeTree(t, dir, "a/keep.txt", "keep me around")
	writeTree(t, dir, "a/b/nested.txt", "nested content")
	writeTree(t, dir, "c/other.txt", "other content")
	h.sync(dir)

	memoDir := filepath.Join(os.Getenv("AQT_NODE_CACHE_DIR"), "seal", compress.CodecID())
	if entries, err := os.ReadDir(memoDir); err != nil || len(entries) == 0 {
		t.Fatalf("first sync recorded no seal-memo entries in %s (err %v)", memoDir, err)
	}

	writeTree(t, dir, "a/keep.txt", "keep me around, edited")
	h.sync(dir)

	if err := runPrune(false, false); err != nil {
		t.Fatalf("prune after a reused push: %v", err)
	}

	st, err := loadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	clone := t.TempDir()
	h.clone(st.ID, clone)
	for rel, want := range map[string]string{
		"a/keep.txt":     "keep me around, edited",
		"a/b/nested.txt": "nested content",
		"c/other.txt":    "other content",
	} {
		got, err := os.ReadFile(filepath.Join(clone, filepath.FromSlash(rel)))
		if err != nil || string(got) != want {
			t.Fatalf("%s after prune: err=%v, got %q", rel, err, got)
		}
	}
}
