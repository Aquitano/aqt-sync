// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// doAt issues a JSON request declaring the given client capability.
func (h *harness) doAt(capability int, method, path, token string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.raw(method, path, token, map[string]string{
		"Content-Type":       "application/json",
		api.CapabilityHeader: strconv.Itoa(capability),
	}, raw)
}

func (h *harness) handleOf(email string) string {
	h.t.Helper()
	keys, err := h.store.AccountKeysByEmail(email)
	if err != nil {
		h.t.Fatalf("handle of %s: %v", email, err)
	}
	return keys.Handle
}

// An account still on a pre-X-Wing key is served as a decoy, not as a grant target,
// until it upgrades; the upgrade swaps its key and every incoming wrap in one step,
// and only for the complete set, signed by the account's own identity, at X-Wing
// sizes.
func TestUpgradeEncKeyMovesKeyAndGrantsTogether(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("alice@example.com", "alice passphrase here")
	bobToken, bobMK := h.signup("bob@example.com", "bob passphrase here")
	res, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("create resource = %d", code)
	}
	alice, bob := h.handleOf("alice@example.com"), h.handleOf("bob@example.com")

	// Bob as a server upgraded under him holds him: an X25519 key and X25519 wraps,
	// one of them on a resource since reclaimed, which no re-wrap set names.
	gone, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("create resource = %d", code)
	}
	if _, err := h.store.db.Exec(`UPDATE accounts SET enc_public_key = ? WHERE owner_handle = ?`, make([]byte, 32), bob); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{res.ID, gone.ID} {
		if err := h.store.PutGrant(alice, id, bob, make([]byte, 80), nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.store.db.Exec(`UPDATE resources SET reclaimed = 1 WHERE id = ?`, gone.ID); err != nil {
		t.Fatal(err)
	}
	lookup := func() api.AccountKeysResponse {
		t.Helper()
		rec := h.doAt(api.ClientCapability, http.MethodGet, "/v1/account/keys?email=bob@example.com", aliceToken, nil)
		var keys api.AccountKeysResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &keys) != nil {
			t.Fatalf("lookup = %d %s", rec.Code, rec.Body)
		}
		return keys
	}
	if lookup().Handle == bob {
		t.Fatal("a pre-X-Wing account was served as a grant target instead of a decoy")
	}

	enc := crypto.DeriveEncKey(bobMK).Public()
	sig := crypto.SignEncKey(crypto.DeriveSigningKey(bobMK), enc)
	wrap := bytes.Repeat([]byte{7}, crypto.GrantWrapSize)
	grants := []api.GrantKeyMigration{{ResourceID: res.ID, OwnerHandle: alice, WrappedKey: wrap}}
	refused := []struct {
		name string
		req  api.EncKeyUpgradeRequest
		want int
	}{
		{"incomplete grant set", api.EncKeyUpgradeRequest{EncPublicKey: enc, EncKeySig: sig}, http.StatusConflict},
		{"signed by another identity", api.EncKeyUpgradeRequest{EncPublicKey: enc, EncKeySig: crypto.SignEncKey(crypto.DeriveSigningKey(aliceMK), enc), IncomingGrants: grants}, http.StatusBadRequest},
		{"X25519-sized wrap", api.EncKeyUpgradeRequest{EncPublicKey: enc, EncKeySig: sig, IncomingGrants: []api.GrantKeyMigration{{ResourceID: res.ID, OwnerHandle: alice, WrappedKey: make([]byte, 80)}}}, http.StatusBadRequest},
	}
	for _, c := range refused {
		if rec := h.doAt(api.ClientCapability, http.MethodPut, "/v1/account/enc-key", bobToken, c.req); rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
	}
	if lookup().Handle == bob {
		t.Fatal("a refused upgrade still published the key")
	}

	if rec := h.doAt(api.ClientCapability, http.MethodPut, "/v1/account/enc-key", bobToken,
		api.EncKeyUpgradeRequest{EncPublicKey: enc, EncKeySig: sig, IncomingGrants: grants}); rec.Code != http.StatusNoContent {
		t.Fatalf("upgrade = %d %s", rec.Code, rec.Body)
	}
	if got := lookup(); got.Handle != bob || !bytes.Equal(got.EncPublicKey, enc) {
		t.Fatal("the upgraded account is not served with its X-Wing key")
	}
	stored, ok, err := h.store.grantWrappedKey(res.ID, bob)
	if err != nil || !ok || !bytes.Equal(stored, wrap) {
		t.Fatalf("incoming grant not re-wrapped with the key: ok=%v err=%v", ok, err)
	}
	var leftover int
	if err := h.store.db.QueryRow(`SELECT count(*) FROM grants WHERE resource_id = ?`, gone.ID).Scan(&leftover); err != nil || leftover != 0 {
		t.Fatalf("an X25519 wrap on a reclaimed resource outlived the upgrade: %d rows (%v)", leftover, err)
	}

	// Once upgraded, a replay — here by anyone holding bob's token, who can read the
	// public binding — must not touch his grants.
	garbage := []api.GrantKeyMigration{{ResourceID: res.ID, OwnerHandle: alice, WrappedKey: make([]byte, crypto.GrantWrapSize)}}
	if rec := h.doAt(api.ClientCapability, http.MethodPut, "/v1/account/enc-key", bobToken,
		api.EncKeyUpgradeRequest{EncPublicKey: enc, EncKeySig: sig, IncomingGrants: garbage}); rec.Code != http.StatusNoContent {
		t.Fatalf("repeated upgrade = %d, want a 204 no-op", rec.Code)
	}
	if stored, _, _ := h.store.grantWrappedKey(res.ID, bob); !bytes.Equal(stored, wrap) {
		t.Fatal("a repeated upgrade rewrote an upgraded account's grant")
	}
}

// A client from before X-Wing grants gets a 426 on every route that would hand it
// a key it rejects or a wrap it cannot open, and no client can store an X25519-sized
// wrap.
func TestGrantSurfaceRefusesPreXWingClients(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("alice@example.com", "alice passphrase here")
	bobToken, _ := h.signup("bob@example.com", "bob passphrase here")
	res, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("create resource = %d", code)
	}
	if err := h.store.PutGrant(h.handleOf("alice@example.com"), res.ID, h.handleOf("bob@example.com"), make([]byte, crypto.GrantWrapSize), nil); err != nil {
		t.Fatal(err)
	}

	const old = api.CapabilityGitRemote
	for _, r := range []struct{ method, path, token string }{
		{http.MethodPost, "/v1/account", ""},
		{http.MethodGet, "/v1/account/keys?email=bob@example.com", aliceToken},
		{http.MethodPost, "/v1/resources/" + res.ID + "/grants", aliceToken},
		{http.MethodPut, "/v1/account/root-key", aliceToken},
		{http.MethodPut, "/v1/account/enc-key", bobToken},
		{http.MethodGet, "/v1/shares", bobToken},
		{http.MethodGet, "/v1/resources/" + res.ID, bobToken},
	} {
		if rec := h.doAt(old, r.method, r.path, r.token, nil); rec.Code != http.StatusUpgradeRequired {
			t.Errorf("%s %s at capability %d = %d, want 426", r.method, r.path, old, rec.Code)
		}
	}
	if rec := h.getCap(res.ID, aliceToken, strconv.Itoa(old)); rec.Code != http.StatusOK {
		t.Errorf("the owner's own read at capability %d = %d, want 200: only grant wraps moved", old, rec.Code)
	}

	legacy := api.CreateGrantRequest{GranteeHandle: h.handleOf("bob@example.com"), WrappedKey: make([]byte, 80)}
	if rec := h.doAt(api.ClientCapability, http.MethodPost, "/v1/resources/"+res.ID+"/grants", aliceToken, legacy); rec.Code != http.StatusBadRequest {
		t.Errorf("X25519-sized grant wrap = %d, want 400", rec.Code)
	}
}
