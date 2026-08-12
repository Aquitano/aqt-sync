package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aquitano/aqt-sync/internal/compress"
)

func convKey(t *testing.T, pass string) ConvergenceKey {
	t.Helper()
	params := cheapKdf(t)
	mk, err := DeriveMasterKey(pass, params)
	if err != nil {
		t.Fatal(err)
	}
	return DeriveConvergenceKey(mk)
}

func TestSealChunkRoundTrip(t *testing.T) {
	conv := convKey(t, "an account passphrase")
	plaintext := bytes.Repeat([]byte("chunk payload "), 100)

	ct, ch, err := SealChunk(plaintext, conv)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := OpenChunk(ct, ch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("chunk round trip mismatch")
	}
}

func TestSealChunkDeterministicPerAccount(t *testing.T) {
	conv := convKey(t, "deterministic account")
	plaintext := []byte("the same bytes encrypt the same way for one account")

	ct1, ch1, err := SealChunk(plaintext, conv)
	if err != nil {
		t.Fatal(err)
	}
	ct2, ch2, err := SealChunk(plaintext, conv)
	if err != nil {
		t.Fatal(err)
	}
	// Determinism is what makes server-side dedup possible.
	if !bytes.Equal(ct1, ct2) || ch1.ID != ch2.ID {
		t.Fatal("same account + same plaintext must produce identical ciphertext and id")
	}
}

func TestSealChunkDiffersAcrossAccounts(t *testing.T) {
	a := convKey(t, "account A")
	b := convKey(t, "account B")
	plaintext := []byte("a shared secret value that both accounts happen to hold")

	_, chA, err := SealChunk(plaintext, a)
	if err != nil {
		t.Fatal(err)
	}
	_, chB, err := SealChunk(plaintext, b)
	if err != nil {
		t.Fatal(err)
	}
	// No cross-account equality oracle: identical plaintext, different addresses.
	if chA.ID == chB.ID {
		t.Fatal("different accounts must not produce the same chunk id for the same plaintext")
	}
}

func TestOpenChunkRejectsTamperedCiphertext(t *testing.T) {
	conv := convKey(t, "tamper account")
	ct, ch, err := SealChunk([]byte("important bytes"), conv)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	// The address check fires before the AEAD even runs.
	if _, err := OpenChunk(ct, ch); err == nil {
		t.Fatal("tampered ciphertext must be rejected")
	}
}

func TestOpenChunkRejectsWrongKey(t *testing.T) {
	conv := convKey(t, "key account")
	ct, ch, err := SealChunk([]byte("important bytes"), conv)
	if err != nil {
		t.Fatal(err)
	}
	other := convKey(t, "other account")
	_, wrong, err := SealChunk([]byte("important bytes"), other)
	if err != nil {
		t.Fatal(err)
	}
	ch.Key = wrong.Key // valid-length key, wrong value
	if _, err := OpenChunk(ct, ch); err == nil {
		t.Fatal("wrong key must fail the AEAD tag check")
	}
}

// OpenChunk must reject a ciphertext sealed under the same key+nonce but without the
// chunk AAD, proving the domain-separation tag is actually bound (a chunk's bytes
// cannot be reinterpreted as another sealed role).
func TestOpenChunkRejectsMissingAAD(t *testing.T) {
	conv := convKey(t, "aad account")
	plaintext := []byte("bytes sealed without the chunk aad")

	// Re-derive the exact chunk key SealChunk would use, then seal with nil AAD.
	_, ch, err := SealChunk(plaintext, conv)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(ch.Key)
	if err != nil {
		t.Fatal(err)
	}
	noAAD := aead.Seal(nil, chunkNonce[:], plaintext, nil)

	// Address the crafted ciphertext so it passes the id check and the AEAD tag is the
	// only thing left to reject it.
	sum := sha256.Sum256(noAAD)
	id := hex.EncodeToString(sum[:])
	if _, err := OpenChunk(noAAD, Chunk{ID: id, Key: ch.Key, Len: len(plaintext)}); err == nil {
		t.Fatal("a chunk sealed without the domain-separation AAD must not open")
	}
}

func TestSealChunkCompressesCompressibleData(t *testing.T) {
	conv := convKey(t, "compress account")
	plaintext := bytes.Repeat([]byte("very compressible line\n"), 500)

	ct, ch, err := SealChunk(plaintext, conv)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Alg != compress.Zstd {
		t.Fatalf("compressible chunk sealed with alg %q, want %q", ch.Alg, compress.Zstd)
	}
	if len(ct) >= len(plaintext) {
		t.Fatalf("ciphertext (%d) not smaller than plaintext (%d)", len(ct), len(plaintext))
	}
	got, err := OpenChunk(ct, ch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("compressed chunk round trip mismatch")
	}
}

func TestSealChunkSkipsIncompressibleData(t *testing.T) {
	conv := convKey(t, "incompressible account")
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ct, ch, err := SealChunk(plaintext, conv)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Alg != "" {
		t.Fatalf("incompressible chunk sealed with alg %q, want raw", ch.Alg)
	}
	got, err := OpenChunk(ct, ch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("raw chunk round trip mismatch")
	}
}

// TestOpenChunkLegacyRawChunk seals a chunk exactly as pre-compression clients did
// (raw plaintext, no alg marker) and opens it with the current code: absence of Alg
// must mean raw, so old stored chunks stay readable.
func TestOpenChunkLegacyRawChunk(t *testing.T) {
	conv := convKey(t, "legacy account")
	plaintext := bytes.Repeat([]byte("legacy chunk sealed before compression existed\n"), 50)

	_, ch, err := SealChunk(plaintext, conv)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(ch.Key)
	if err != nil {
		t.Fatal(err)
	}
	legacy := aead.Seal(nil, chunkNonce[:], plaintext, aadChunk)
	sum := sha256.Sum256(legacy)

	got, err := OpenChunk(legacy, Chunk{ID: hex.EncodeToString(sum[:]), Key: ch.Key, Len: len(plaintext)})
	if err != nil {
		t.Fatalf("legacy raw chunk must still open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("legacy chunk content mismatch")
	}
}
