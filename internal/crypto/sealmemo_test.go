// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"testing"
)

// mapMemo is an in-memory NodeSealMemo that counts traffic and can be poisoned.
type mapMemo struct {
	entries    map[string]memoEntry
	gets, puts int
}

type memoEntry struct {
	id, alg string
	ct      []byte
}

func newMapMemo() *mapMemo { return &mapMemo{entries: map[string]memoEntry{}} }

func (m *mapMemo) GetNodeSeal(digest string) (string, string, []byte, bool) {
	m.gets++
	e, ok := m.entries[digest]
	if !ok {
		return "", "", nil, false
	}
	return e.id, e.alg, append([]byte(nil), e.ct...), true
}

func (m *mapMemo) PutNodeSeal(digest, id, alg string, ct []byte) {
	m.puts++
	m.entries[digest] = memoEntry{id: id, alg: alg, ct: append([]byte(nil), ct...)}
}

func testConvKey(fill byte) ConvergenceKey {
	var conv ConvergenceKey
	for i := range conv {
		conv[i] = fill
	}
	return conv
}

// Reuse rests on node sealing being deterministic and resource-independent: the
// same plaintext under the same convergence key must produce byte-identical
// ciphertext (and thus the same id) on every call — nodes, unlike tree roots,
// bind no resource id. This pins that property.
func TestSealNodeDeterministic(t *testing.T) {
	t.Parallel()
	conv := testConvKey(7)
	plain := bytes.Repeat([]byte(`{"version":2,"children":[{"name":"a"}]}`), 100)
	ct1, ch1, err := SealNode(plain, conv)
	if err != nil {
		t.Fatal(err)
	}
	ct2, ch2, err := SealNode(plain, conv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct1, ct2) || ch1.ID != ch2.ID || !bytes.Equal(ch1.Key, ch2.Key) || ch1.Alg != ch2.Alg || ch1.Len != ch2.Len {
		t.Fatalf("SealNode is not deterministic: %+v vs %+v", ch1, ch2)
	}
}

// A verified hit must be indistinguishable from a cold seal: same ciphertext,
// same Chunk record, and no re-recording.
func TestSealNodeMemoHitMatchesCold(t *testing.T) {
	t.Parallel()
	conv := testConvKey(7)
	plain := bytes.Repeat([]byte("directory node plaintext "), 200)
	coldCT, coldCh, err := SealNode(plain, conv)
	if err != nil {
		t.Fatal(err)
	}

	memo := newMapMemo()
	firstCT, firstCh, err := SealNodeMemo(plain, conv, memo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstCT, coldCT) || firstCh.ID != coldCh.ID {
		t.Fatal("miss path diverged from a cold seal")
	}
	if memo.puts != 1 {
		t.Fatalf("puts after miss = %d, want 1", memo.puts)
	}

	hitCT, hitCh, err := SealNodeMemo(plain, conv, memo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hitCT, coldCT) || hitCh.ID != coldCh.ID || !bytes.Equal(hitCh.Key, coldCh.Key) || hitCh.Alg != coldCh.Alg || hitCh.Len != coldCh.Len {
		t.Fatal("hit path diverged from a cold seal")
	}
	if memo.puts != 1 {
		t.Fatalf("puts after hit = %d, want 1 (a verified hit must not re-record)", memo.puts)
	}
	if plain2, err := OpenNode(hitCT, hitCh); err != nil || !bytes.Equal(plain2, plain) {
		t.Fatalf("reused seal does not open: %v", err)
	}
}

// Every flavor of bad entry — swapped with another node's, garbage ciphertext,
// truncated, wrong alg — must degrade to a cold seal with the correct output,
// never an error and never a wrong node.
func TestSealNodeMemoRejectsPoisonedEntries(t *testing.T) {
	t.Parallel()
	conv := testConvKey(7)
	plainA := bytes.Repeat([]byte("node A plaintext "), 200)
	plainB := bytes.Repeat([]byte("node B plaintext "), 200)
	coldCT, coldCh, err := SealNode(plainA, conv)
	if err != nil {
		t.Fatal(err)
	}
	digestA := nodeSealDigest(conv, plainA)

	poison := map[string]func(m *mapMemo){
		"other node's entry": func(m *mapMemo) {
			ctB, chB, err := SealNode(plainB, conv)
			if err != nil {
				t.Fatal(err)
			}
			m.entries[digestA] = memoEntry{id: chB.ID, alg: chB.Alg, ct: ctB}
		},
		"garbage ciphertext": func(m *mapMemo) {
			m.entries[digestA] = memoEntry{id: coldCh.ID, alg: coldCh.Alg, ct: bytes.Repeat([]byte{0xaa}, len(coldCT))}
		},
		"truncated ciphertext": func(m *mapMemo) {
			m.entries[digestA] = memoEntry{id: coldCh.ID, alg: coldCh.Alg, ct: coldCT[:len(coldCT)/2]}
		},
		"wrong alg": func(m *mapMemo) {
			alg := ""
			if coldCh.Alg == "" {
				alg = "zstd"
			}
			m.entries[digestA] = memoEntry{id: coldCh.ID, alg: alg, ct: coldCT}
		},
	}
	for name, inject := range poison {
		memo := newMapMemo()
		inject(memo)
		ct, ch, err := SealNodeMemo(plainA, conv, memo)
		if err != nil {
			t.Fatalf("%s: seal failed: %v (a bad entry must degrade, not fail)", name, err)
		}
		if !bytes.Equal(ct, coldCT) || ch.ID != coldCh.ID {
			t.Fatalf("%s: output diverged from a cold seal", name)
		}
		if memo.puts != 1 {
			t.Fatalf("%s: puts = %d, want 1 (the rejected entry should be healed)", name, memo.puts)
		}
	}
}

// Different convergence keys must never share memo slots: account B looking up
// the digest space misses whatever account A recorded.
func TestSealNodeMemoDigestIsAccountScoped(t *testing.T) {
	t.Parallel()
	plain := []byte("identical plaintext on two accounts")
	if nodeSealDigest(testConvKey(1), plain) == nodeSealDigest(testConvKey(2), plain) {
		t.Fatal("memo digest does not depend on the convergence key")
	}
}

func TestSealNodeMemoNilIsSealNode(t *testing.T) {
	t.Parallel()
	conv := testConvKey(7)
	plain := []byte("plain")
	coldCT, coldCh, err := SealNode(plain, conv)
	if err != nil {
		t.Fatal(err)
	}
	ct, ch, err := SealNodeMemo(plain, conv, nil)
	if err != nil || !bytes.Equal(ct, coldCT) || ch.ID != coldCh.ID {
		t.Fatalf("nil memo diverged from SealNode: %v", err)
	}
}
