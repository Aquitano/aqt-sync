// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// countingMemo is an in-memory crypto.NodeSealMemo that records hit traffic, so a
// test can assert reuse actually happened (and not just that outputs agree).
type countingMemo struct {
	entries map[string]countingEntry
	hits    int
}

type countingEntry struct {
	id, alg string
	ct      []byte
}

func newCountingMemo() *countingMemo { return &countingMemo{entries: map[string]countingEntry{}} }

func (m *countingMemo) GetNodeSeal(digest string) (string, string, []byte, bool) {
	e, ok := m.entries[digest]
	if !ok {
		return "", "", nil, false
	}
	m.hits++
	return e.id, e.alg, append([]byte(nil), e.ct...), true
}

func (m *countingMemo) PutNodeSeal(digest, id, alg string, ct []byte) {
	m.entries[digest] = countingEntry{id: id, alg: alg, ct: append([]byte(nil), ct...)}
}

// lyingMemo claims a hit for every digest, always returning the same bogus entry.
type lyingMemo struct{ puts int }

func (m *lyingMemo) GetNodeSeal(string) (string, string, []byte, bool) {
	return "deadbeef", "", bytes.Repeat([]byte{0xaa}, 64), true
}

func (m *lyingMemo) PutNodeSeal(string, string, string, []byte) { m.puts++ }

func memoBaseManifest() Manifest {
	key := make([]byte, crypto.KeySize)
	return Manifest{
		Version: TreeManifestVersion,
		Entries: []Entry{
			{Path: "a.txt", Mode: 0o644, Size: 3, Hash: "ha", Inline: []byte("abc")},
			{Path: "keep/deep/d.txt", Mode: 0o644, Size: 2, Hash: "hd", Inline: []byte("dd")},
			{Path: "moved/b.bin", Mode: 0o600, Size: 5, Hash: "hb", Chunks: []crypto.Chunk{{ID: "c1", Key: key, Len: 5}}},
			{Path: "moved/sub/c.txt", Mode: 0o644, Size: 1, Hash: "hc", Inline: []byte("x")},
		},
		Dirs: []DirEntry{
			{Path: "keep", Mode: 0o755},
			{Path: "keep/deep", Mode: 0o755},
			{Path: "moved", Mode: 0o700},
			{Path: "moved/sub", Mode: 0o755},
		},
	}
}

// A memo-backed seal must be observably indistinguishable from a cold seal —
// identical root, ref set, and sink contents — for the unchanged tree and across
// each mutation shape reuse could get wrong: a rename, a delete, and a whole
// subtree moved to a new parent. Each mutated seal runs against the memo warmed
// by the base push, exactly the state a second `aqt sync` sees.
func TestSealTreeWithMemoMatchesColdSeal(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	base := memoBaseManifest()

	mutate := map[string]func(Manifest) Manifest{
		"unchanged": func(m Manifest) Manifest { return m },
		"rename": func(m Manifest) Manifest {
			m.Entries[0].Path = "renamed.txt"
			return m
		},
		"delete": func(m Manifest) Manifest {
			m.Entries = m.Entries[1:]
			return m
		},
		"subtree move": func(m Manifest) Manifest {
			m.Entries[2].Path = "keep/moved/b.bin"
			m.Entries[3].Path = "keep/moved/sub/c.txt"
			m.Dirs[2].Path = "keep/moved"
			m.Dirs[3].Path = "keep/moved/sub"
			return m
		},
	}
	for name, f := range mutate {
		memo := newCountingMemo()
		if _, _, err := SealTree(base, conv, nil, memo); err != nil {
			t.Fatalf("%s: warm base seal: %v", name, err)
		}
		edited := f(memoBaseManifest())

		coldSink := mapSink{}
		coldRoot, coldRefs, err := SealTree(edited, conv, coldSink, nil)
		if err != nil {
			t.Fatalf("%s: cold seal: %v", name, err)
		}
		memoSink := mapSink{}
		memoRoot, memoRefs, err := SealTree(edited, conv, memoSink, memo)
		if err != nil {
			t.Fatalf("%s: memo seal: %v", name, err)
		}

		if memoRoot.Root.ID != coldRoot.Root.ID {
			t.Fatalf("%s: memo root %s != cold root %s", name, memoRoot.Root.ID, coldRoot.Root.ID)
		}
		if !reflect.DeepEqual(memoRefs, coldRefs) {
			t.Fatalf("%s: memo refs diverge from cold refs (prune would delete live objects)", name)
		}
		if !reflect.DeepEqual(map[string][]byte(memoSink), map[string][]byte(coldSink)) {
			t.Fatalf("%s: memo sink contents diverge from cold seal", name)
		}
		if memo.hits == 0 {
			t.Fatalf("%s: seal never hit the warmed memo — reuse is not happening", name)
		}
	}
}

// A memo that lies about every node must not change anything: the seal falls
// back to cold output for the whole tree and re-records each node.
func TestSealTreePoisonedMemoDegradesToCold(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	m := memoBaseManifest()
	coldRoot, coldRefs, err := SealTree(m, conv, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	memo := &lyingMemo{}
	root, refs, err := SealTree(m, conv, nil, memo)
	if err != nil {
		t.Fatalf("poisoned memo must degrade, not fail: %v", err)
	}
	if root.Root.ID != coldRoot.Root.ID || !reflect.DeepEqual(refs, coldRefs) {
		t.Fatal("poisoned memo changed the seal output")
	}
	if memo.puts == 0 {
		t.Fatal("rejected entries were not re-recorded")
	}
}
