package syncengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

func TestPackBuilderSelfDescribing(t *testing.T) {
	t.Parallel()
	pb := NewPackBuilder()
	objs := map[string][]byte{}
	for _, s := range []string{"alpha", "bravo-bravo", "charlie chunk data"} {
		ct := []byte(s)
		sum := sha256.Sum256(ct)
		id := hex.EncodeToString(sum[:])
		objs[id] = ct
		pb.Add(id, ct)
	}
	if pb.Empty() {
		t.Fatal("builder should not be empty after adds")
	}
	packID, pack := pb.Finish()

	// Pack id is sha256 of the whole serialized pack.
	sum := sha256.Sum256(pack)
	if hex.EncodeToString(sum[:]) != packID {
		t.Fatal("pack id is not sha256 of the pack bytes")
	}

	// Trailing 4 bytes are the index length; the index parses and every slice
	// hashes to its id at the recorded offset.
	indexLen := int(binary.BigEndian.Uint32(pack[len(pack)-4:]))
	indexStart := len(pack) - 4 - indexLen
	var index []api.PackIndexEntry
	if err := json.Unmarshal(pack[indexStart:len(pack)-4], &index); err != nil {
		t.Fatalf("parse index: %v", err)
	}
	if len(index) != len(objs) {
		t.Fatalf("index has %d entries, want %d", len(index), len(objs))
	}
	for _, e := range index {
		slice := pack[e.Off : e.Off+e.Len]
		s := sha256.Sum256(slice)
		if hex.EncodeToString(s[:]) != e.ID {
			t.Fatalf("object %s slice does not hash to its id", e.ID)
		}
		if !bytes.Equal(slice, objs[e.ID]) {
			t.Fatalf("object %s bytes mismatch", e.ID)
		}
	}
}
