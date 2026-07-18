package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// publicResource creates a public streamed-file resource rooting the given object
// ids, so the unauthenticated object-read endpoint will serve them.
func (s *Store) publicResource(t *testing.T, owner string, refs []string) string {
	t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("sealed root"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"big.bin","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, ChunkRefs: refs,
	})
	if err != nil {
		t.Fatalf("public resource: %v", err)
	}
	return id
}

// postPublicObjects issues the unauthenticated object-read request and returns the
// recorder for the caller to inspect status and raw framed body.
func postPublicObjects(t *testing.T, router http.Handler, resourceID string, ids []string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(api.PublicObjectsRequest{IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/public/resources/"+resourceID+"/objects", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeFrames splits a positional length-prefixed response into exactly want
// frames and asserts the body carries no trailing bytes.
func decodeFrames(t *testing.T, body []byte, want int) [][]byte {
	t.Helper()
	out := make([][]byte, 0, want)
	for i := 0; i < want; i++ {
		if len(body) < 4 {
			t.Fatalf("frame %d: body ended before length prefix", i)
		}
		n := binary.BigEndian.Uint32(body[:4])
		body = body[4:]
		if uint32(len(body)) < n {
			t.Fatalf("frame %d: declared %d bytes, only %d left", i, n, len(body))
		}
		out = append(out, body[:n])
		body = body[n:]
	}
	if len(body) != 0 {
		t.Fatalf("response carried %d trailing bytes past %d frames", len(body), want)
	}
	return out
}

// A public streamed resource's objects are served unauthenticated, exact bytes in
// request order, with duplicate ids honored positionally.
func TestPublicObjectsServesExactSlicesInOrder(t *testing.T) {
	s := newStore(t)
	router := New(s).Router()
	owner := s.mustAccount(t, "share@example.com")

	packID, data, ids := packOf("first object bytes", "second object bytes longer")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	resID := s.publicResource(t, owner, ids)

	// Duplicate the first id to prove the framing is positional, not deduped.
	req := []string{ids[0], ids[1], ids[0]}
	rec := postPublicObjects(t, router, resID, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != api.ObjectFramesMediaType {
		t.Fatalf("content-type = %q, want versioned object frames", ct)
	}
	frames := decodeFrames(t, rec.Body.Bytes(), len(req))
	want := []string{"first object bytes", "second object bytes longer", "first object bytes"}
	for i, w := range want {
		if string(frames[i]) != w {
			t.Fatalf("frame %d = %q, want %q", i, frames[i], w)
		}
	}
}

// A private resource must not confirm its own existence: the same 404 as an unknown
// id, so the endpoint is no oracle.
func TestPublicObjectsRejectsPrivateAndUnknownResource(t *testing.T) {
	s := newStore(t)
	router := New(s).Router()
	owner := s.mustAccount(t, "private@example.com")

	packID, data, ids := packOf("private object")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	privID := s.rootResource(t, owner, ids) // rootResource is private

	if rec := postPublicObjects(t, router, privID, ids); rec.Code != http.StatusNotFound {
		t.Fatalf("private resource status = %d, want 404", rec.Code)
	}
	if rec := postPublicObjects(t, router, "deadbeef", ids); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown resource status = %d, want 404", rec.Code)
	}
}

// Security-critical: a public resource must not be an oracle for the owner's objects
// it does not reference. An id the owner stores but this resource does not root fails
// the whole request with 404, and it does not leak which id failed.
func TestPublicObjectsRejectsUnreferencedObject(t *testing.T) {
	s := newStore(t)
	router := New(s).Router()
	owner := s.mustAccount(t, "oracle@example.com")

	// Two packs: one object is referenced by the public resource, the other is a
	// private object the owner stores but never shares.
	sharedPack, sharedData, sharedIDs := packOf("shared object")
	secretPack, secretData, secretIDs := packOf("secret object")
	if _, err := s.PutPack(owner, sharedPack, sharedData, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPack(owner, secretPack, secretData, 0); err != nil {
		t.Fatal(err)
	}
	resID := s.publicResource(t, owner, sharedIDs)

	// The shared object alone succeeds.
	if rec := postPublicObjects(t, router, resID, sharedIDs); rec.Code != http.StatusOK {
		t.Fatalf("shared object status = %d, want 200", rec.Code)
	}
	// The unreferenced (secret) object is not served through this resource.
	if rec := postPublicObjects(t, router, resID, secretIDs); rec.Code != http.StatusNotFound {
		t.Fatalf("unreferenced object status = %d, want 404", rec.Code)
	}
	// Mixing a valid id with an unreferenced one fails the whole request, so a
	// referenced id cannot be used to smuggle out an unreferenced one.
	mixed := []string{sharedIDs[0], secretIDs[0]}
	if rec := postPublicObjects(t, router, resID, mixed); rec.Code != http.StatusNotFound {
		t.Fatalf("mixed request status = %d, want 404", rec.Code)
	}
}

// More than maxPublicObjectIDs ids in one request is rejected before any store work,
// so a single response can never fan out to an unbounded read set.
func TestPublicObjectsRejectsOverLimitIDCount(t *testing.T) {
	s := newStore(t)
	router := New(s).Router()
	owner := s.mustAccount(t, "toomany@example.com")
	resID := s.publicResource(t, owner, nil)

	ids := make([]string, maxPublicObjectIDs+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i)
	}
	if rec := postPublicObjects(t, router, resID, ids); rec.Code != http.StatusBadRequest {
		t.Fatalf("over-limit status = %d, want 400", rec.Code)
	}
}

// PublicObjectSlices resolves locations in request order and re-arms the GC age guard
// on every pack it touches, so an in-flight public download cannot be reaped.
func TestPublicObjectSlicesOrderingAndTouch(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "slices@example.com")
	packID, data, ids := packOf("obj a", "obj b")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	resID := s.publicResource(t, owner, ids)

	// Age the pack past the guard; a successful resolve must bump it back.
	aged := time.Now().Add(-2 * time.Hour).Unix()
	if _, err := s.db.Exec(
		`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`, aged, owner, packID,
	); err != nil {
		t.Fatal(err)
	}

	// Reversed request order must be reflected in the returned locations.
	gotOwner, locs, err := s.PublicObjectSlices(resID, []string{ids[1], ids[0]})
	if err != nil {
		t.Fatalf("PublicObjectSlices: %v", err)
	}
	if gotOwner != owner {
		t.Fatalf("owner = %q, want %q", gotOwner, owner)
	}
	if len(locs) != 2 || locs[0].ID != ids[1] || locs[1].ID != ids[0] {
		t.Fatalf("locations out of request order: %+v", locs)
	}

	var touched int64
	if err := s.db.QueryRow(
		`SELECT created_at FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, packID,
	).Scan(&touched); err != nil {
		t.Fatal(err)
	}
	if touched <= aged {
		t.Fatalf("pack created_at = %d, want re-armed above %d", touched, aged)
	}
}
