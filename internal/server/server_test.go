// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
)

// harness wires a real store (temp dir) to the Gin router for a full HTTP cycle.
type harness struct {
	t      *testing.T
	router *gin.Engine
	store  *Store
	srv    *Server
}

// Set once here rather than per-harness: gin.SetMode writes package state, which
// the parallel tests would otherwise race on.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	srv := New(store)
	return &harness{t: t, router: srv.Router(), store: store, srv: srv}
}

// do issues a request and decodes the JSON response into out (if non-nil).
func (h *harness) do(method, path, token string, body, out any) int {
	h.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			h.t.Fatalf("decode response (%d): %v; body=%s", rec.Code, err, rec.Body.String())
		}
	}
	return rec.Code
}

// TestHealthzIsPublic covers the liveness probe: it answers 200 without a token so
// load balancers and container healthchecks can reach it before any device exists.
func TestHealthzIsPublic(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	var body struct {
		Status string `json:"status"`
	}
	if code := h.do(http.MethodGet, "/healthz", "", nil, &body); code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", code)
	}
	if body.Status != "ok" {
		t.Fatalf("healthz body status = %q, want \"ok\"", body.Status)
	}
}

// get issues an unauthenticated GET and returns the raw recorder (for non-JSON
// responses like the HTML share view).
func (h *harness) get(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// signup creates an account and returns its first device token plus the random
// root (master) key. The root key wraps content keys; the passphrase only wraps the
// root key (wrappedRoot) and derives the attach verifier.
func (h *harness) signup(email, passphrase string) (token string, mk crypto.MasterKey) {
	h.t.Helper()
	kdf := cryptotest.KdfParams(h.t)
	var err error
	mk, err = crypto.GenerateMasterKey()
	if err != nil {
		h.t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey(passphrase, kdf)
	if err != nil {
		h.t.Fatal(err)
	}
	wrappedRoot, err := crypto.WrapRoot(mk, uk)
	if err != nil {
		h.t.Fatal(err)
	}
	var resp api.AuthResponse
	code := h.do(http.MethodPost, "/v1/account", "", api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   "test-device",
	}, &resp)
	if code != http.StatusCreated {
		h.t.Fatalf("signup: got status %d", code)
	}
	return resp.Token, mk
}

// bootstrap fetches the new-device bootstrap (KDF params + wrapped root) for an email.
func (h *harness) bootstrap(email string) api.SaltResponse {
	h.t.Helper()
	var boot api.SaltResponse
	if code := h.do(http.MethodGet, "/v1/account/salt?email="+email, "", nil, &boot); code != http.StatusOK {
		h.t.Fatalf("bootstrap: status %d", code)
	}
	return boot
}

func TestPrivatePushPullRoundTrip(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("dev@example.com", "correct horse battery staple")

	plaintext := []byte("DATABASE_URL=postgres://localhost/app\nAPI_KEY=sk-live-123\n")

	// Client-side seal: content key seals the body and the metadata; the content
	// key itself is wrapped under the master key for a private resource.
	ck, _ := crypto.GenerateContentKey()
	blob, err := crypto.Seal(plaintext, ck, crypto.AADBlob)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, _ := json.Marshal(api.Metadata{Name: ".env", Size: int64(len(plaintext))})
	metaBlob, err := crypto.Seal(metaJSON, ck, crypto.AADMeta)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}

	var put api.PutResourceResponse
	code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility:    api.Private,
		Blob:          blob,
		EncryptedMeta: metaBlob,
		WrappedKey:    &wrapped,
	}, &put)
	if code != http.StatusCreated {
		t.Fatalf("put: status %d", code)
	}

	// Owner fetches and decrypts.
	var got api.GetResourceResponse
	code = h.do(http.MethodGet, "/v1/resources/"+put.ID, token, nil, &got)
	if code != http.StatusOK {
		t.Fatalf("get: status %d", code)
	}
	if got.WrappedKey == nil {
		t.Fatal("expected a wrapped key on a private resource")
	}
	unwrapped, err := crypto.UnwrapKey(*got.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	decrypted, err := crypto.Open(got.Blob, unwrapped, crypto.AADBlob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}

	// A request without the owner's token must not reveal a private resource.
	code = h.do(http.MethodGet, "/v1/resources/"+put.ID, "", nil, nil)
	if code != http.StatusNotFound {
		t.Fatalf("anonymous read of private resource: got %d, want 404", code)
	}
}

func TestPublicResourceReadableWithoutAuth(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("pub@example.com", "another passphrase here")

	plaintext := []byte("public snippet")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal(plaintext, ck, crypto.AADBlob)
	metaBlob, _ := crypto.Seal([]byte(`{"name":"note.txt","size":14}`), ck, crypto.AADMeta)

	var put api.PutResourceResponse
	code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility:    api.Public,
		Blob:          blob,
		EncryptedMeta: metaBlob,
	}, &put)
	if code != http.StatusCreated {
		t.Fatalf("put public: status %d", code)
	}

	// Anonymous fetch succeeds; decryption uses the content key that would have
	// arrived in the URL fragment.
	var got api.GetResourceResponse
	code = h.do(http.MethodGet, "/v1/resources/"+put.ID, "", nil, &got)
	if code != http.StatusOK {
		t.Fatalf("anonymous read of public resource: got %d", code)
	}
	decrypted, err := crypto.Open(got.Blob, ck, crypto.AADBlob)
	if err != nil {
		t.Fatalf("open public blob: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("public round trip mismatch: %q", decrypted)
	}
}

// attachRaw fetches a challenge and posts a device attach with caller-supplied
// signature and verifier, so a test can drive both the honest path and the rejection
// paths. Returns the HTTP status.
func (h *harness) attachRaw(email string, sign func(nonce []byte) []byte, verifier []byte, out *api.AuthResponse) int {
	h.t.Helper()
	var ch api.ChallengeResponse
	if code := h.do(http.MethodPost, "/v1/auth/challenge", "", api.ChallengeRequest{Email: email}, &ch); code != http.StatusOK {
		h.t.Fatalf("challenge: status %d", code)
	}
	var target any // avoid handing do() a typed-nil *AuthResponse to decode into
	if out != nil {
		target = out
	}
	return h.do(http.MethodPost, "/v1/devices", "", api.AttachDeviceRequest{
		Email:        email,
		ChallengeID:  ch.ChallengeID,
		Signature:    sign(ch.Nonce),
		AuthVerifier: verifier,
		DeviceName:   "device-2",
	}, target)
}

// attachWith runs the honest new-device flow: fetch the bootstrap, recover the root
// key with the passphrase, and present both the challenge signature and the verifier.
func (h *harness) attachWith(email, passphrase string, out *api.AuthResponse) int {
	h.t.Helper()
	boot := h.bootstrap(email)
	uk, err := crypto.DeriveUnlockKey(passphrase, boot.Kdf)
	if err != nil {
		h.t.Fatal(err)
	}
	rk, err := crypto.UnwrapRoot(boot.WrappedRoot, uk)
	if err != nil {
		h.t.Fatalf("unwrap root: %v", err)
	}
	signing := crypto.DeriveSigningKey(rk)
	return h.attachRaw(email, func(n []byte) []byte { return ed25519.Sign(signing, n) }, crypto.DeriveAuthVerifier(uk), out)
}

func TestDeviceAttachRequiresSignatureAndVerifier(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	const email, pass = "multi@example.com", "shared passphrase"
	h.signup(email, pass)

	boot := h.bootstrap(email)
	uk, _ := crypto.DeriveUnlockKey(pass, boot.Kdf)
	rk, err := crypto.UnwrapRoot(boot.WrappedRoot, uk)
	if err != nil {
		t.Fatal(err)
	}
	goodSign := func(n []byte) []byte { return ed25519.Sign(crypto.DeriveSigningKey(rk), n) }
	goodVerifier := crypto.DeriveAuthVerifier(uk)

	// Both factors present: attaches.
	var resp api.AuthResponse
	if code := h.attachRaw(email, goodSign, goodVerifier, &resp); code != http.StatusCreated || resp.Token == "" {
		t.Fatalf("attach with both factors: status %d, token=%q", code, resp.Token)
	}
	// Correct signature but a verifier from a different passphrase: rejected. Holding
	// the root key alone (without the current passphrase) cannot attach.
	otherUK, _ := crypto.DeriveUnlockKey("a different passphrase", boot.Kdf)
	if code := h.attachRaw(email, goodSign, crypto.DeriveAuthVerifier(otherUK), nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong verifier: got %d, want 401", code)
	}
	// Correct verifier but a signature from the wrong key: rejected.
	wrongKey, _ := crypto.GenerateMasterKey()
	badSign := func(n []byte) []byte { return ed25519.Sign(crypto.DeriveSigningKey(wrongKey), n) }
	if code := h.attachRaw(email, badSign, goodVerifier, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong signature: got %d, want 401", code)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	const email, pass = "replay@example.com", "a passphrase"
	h.signup(email, pass)
	boot := h.bootstrap(email)
	uk, _ := crypto.DeriveUnlockKey(pass, boot.Kdf)
	rk, err := crypto.UnwrapRoot(boot.WrappedRoot, uk)
	if err != nil {
		t.Fatal(err)
	}

	var ch api.ChallengeResponse
	if code := h.do(http.MethodPost, "/v1/auth/challenge", "", api.ChallengeRequest{Email: email}, &ch); code != http.StatusOK {
		t.Fatalf("challenge: status %d", code)
	}
	sig := ed25519.Sign(crypto.DeriveSigningKey(rk), ch.Nonce)
	verifier := crypto.DeriveAuthVerifier(uk)
	attach := func(out any) int {
		return h.do(http.MethodPost, "/v1/devices", "", api.AttachDeviceRequest{
			Email: email, ChallengeID: ch.ChallengeID, Signature: sig, AuthVerifier: verifier, DeviceName: "d",
		}, out)
	}
	var resp api.AuthResponse
	if code := attach(&resp); code != http.StatusCreated {
		t.Fatalf("first attach: status %d", code)
	}
	// Replaying the same challenge + signature must be rejected.
	if code := attach(nil); code != http.StatusUnauthorized {
		t.Fatalf("challenge replay: got %d, want 401", code)
	}
}

func TestBootstrapDecoyForUnknownEmail(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.signup("real@example.com", "the real passphrase")

	// An unknown email returns 200 with a decoy (not 404), so registered and
	// unregistered emails are indistinguishable on the wire.
	a := h.bootstrap("ghost@example.com")
	if len(a.WrappedRoot.Ciphertext) == 0 || len(a.Kdf.Salt) == 0 {
		t.Fatal("decoy bootstrap must look like a real one (non-empty salt + wrapped root)")
	}
	// The decoy is deterministic per email, so probing twice cannot reveal it.
	b := h.bootstrap("ghost@example.com")
	if !bytes.Equal(a.WrappedRoot.Ciphertext, b.WrappedRoot.Ciphertext) || !bytes.Equal(a.Kdf.Salt, b.Kdf.Salt) {
		t.Fatal("decoy must be stable across probes")
	}
	// A different unknown email yields a different decoy.
	c := h.bootstrap("other-ghost@example.com")
	if bytes.Equal(a.WrappedRoot.Ciphertext, c.WrappedRoot.Ciphertext) {
		t.Fatal("decoy must vary by email")
	}
	// And the decoy never unwraps (it wraps no real key).
	uk, _ := crypto.DeriveUnlockKey("any passphrase at all", a.Kdf)
	if _, err := crypto.UnwrapRoot(a.WrappedRoot, uk); err == nil {
		t.Fatal("a decoy wrapped root must not unwrap")
	}
}

func TestPassphraseChangeInvalidatesOtherDevices(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	const email, oldPass, newPass = "rotate@example.com", "old passphrase here", "new passphrase here"
	token1, rk := h.signup(email, oldPass)

	// A second device attaches under the old passphrase.
	var dev2 api.AuthResponse
	if code := h.attachWith(email, oldPass, &dev2); code != http.StatusCreated {
		t.Fatalf("attach device 2: %d", code)
	}

	// Device 1 changes the passphrase: the root key is unchanged, only re-wrapped.
	boot := h.bootstrap(email)
	oldUK, _ := crypto.DeriveUnlockKey(oldPass, boot.Kdf)
	newKdf := cryptotest.KdfParams(t)
	newUK, _ := crypto.DeriveUnlockKey(newPass, newKdf)
	newWrapped, _ := crypto.WrapRoot(rk, newUK)
	var chResp api.AuthResponse
	if code := h.do(http.MethodPut, "/v1/account/passphrase", token1, api.PassphraseChangeRequest{
		Kdf:             newKdf,
		WrappedRoot:     newWrapped,
		OldAuthVerifier: crypto.DeriveAuthVerifier(oldUK),
		NewAuthVerifier: crypto.DeriveAuthVerifier(newUK),
		ExpectedEpoch:   1,
	}, &chResp); code != http.StatusOK {
		t.Fatalf("passphrase change: %d", code)
	}
	if chResp.Epoch != 2 {
		t.Fatalf("epoch after change = %d, want 2", chResp.Epoch)
	}

	// The initiating device keeps working; every other device's token is invalidated.
	if code := h.do(http.MethodGet, "/v1/devices", token1, nil, nil); code != http.StatusOK {
		t.Fatalf("initiator token after change: got %d, want 200", code)
	}
	if code := h.do(http.MethodGet, "/v1/devices", dev2.Token, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("other device token after change: got %d, want 401", code)
	}

	// Re-attach now needs the new passphrase.
	if code := h.attachWith(email, newPass, nil); code != http.StatusCreated {
		t.Fatalf("re-attach with new passphrase: %d", code)
	}
	// The old passphrase's verifier no longer attaches, even with the real root key.
	sign := func(n []byte) []byte { return ed25519.Sign(crypto.DeriveSigningKey(rk), n) }
	if code := h.attachRaw(email, sign, crypto.DeriveAuthVerifier(oldUK), nil); code != http.StatusUnauthorized {
		t.Fatalf("attach with old passphrase verifier: got %d, want 401", code)
	}
}

func TestUpdateResourceReplacesInPlace(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("upd@example.com", "passphrase for updates")

	put := func(id string, body []byte) api.PutResourceResponse {
		ck, _ := crypto.GenerateContentKey()
		blob, _ := crypto.Seal(body, ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
		var resp api.PutResourceResponse
		code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		}, &resp)
		if id == "" && code != http.StatusCreated {
			t.Fatalf("create: status %d", code)
		}
		if id != "" && code != http.StatusOK {
			t.Fatalf("update: status %d", code)
		}
		return resp
	}

	created := put("", []byte("v1"))
	if created.Version != 1 {
		t.Fatalf("create version = %d, want 1", created.Version)
	}
	updated := put(created.ID, []byte("v2-bigger-content"))
	if updated.ID != created.ID || updated.Version != 2 {
		t.Fatalf("update id/version = %s/%d, want %s/2", updated.ID, updated.Version, created.ID)
	}

	// A different owner cannot update this resource.
	otherToken, _ := h.signup("other@example.com", "another passphrase")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("hijack"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	code := h.do(http.MethodPut, "/v1/resources", otherToken, api.PutResourceRequest{
		ID: created.ID, Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, nil)
	if code != http.StatusNotFound {
		t.Fatalf("cross-owner update: got %d, want 404", code)
	}
}

func TestSetVisibilityStripsWrappedKeyForNonOwner(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("share@example.com", "passphrase here")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("shared body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	var put api.PutResourceResponse
	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, &put); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}

	if code := h.do(http.MethodPost, "/v1/resources/"+put.ID+"/visibility", token,
		api.SetVisibilityRequest{Visibility: api.Public}, nil); code != http.StatusOK {
		t.Fatalf("set visibility: %d", code)
	}

	// Anonymous read: public and decryptable via the content key, but no wrapped key.
	var anon api.GetResourceResponse
	if code := h.do(http.MethodGet, "/v1/resources/"+put.ID, "", nil, &anon); code != http.StatusOK {
		t.Fatalf("anon get: %d", code)
	}
	if anon.Visibility != api.Public {
		t.Fatalf("visibility = %s, want public", anon.Visibility)
	}
	if anon.WrappedKey != nil {
		t.Fatal("anonymous reader must not receive the wrapped key")
	}
	if got, err := crypto.Open(anon.Blob, ck, crypto.AADBlob); err != nil || string(got) != "shared body" {
		t.Fatalf("anon decrypt: %q err=%v", got, err)
	}

	// The owner still gets the wrapped key (their recovery path for `private`).
	var owner api.GetResourceResponse
	if code := h.do(http.MethodGet, "/v1/resources/"+put.ID, token, nil, &owner); code != http.StatusOK {
		t.Fatalf("owner get: %d", code)
	}
	if owner.WrappedKey == nil {
		t.Fatal("owner must still receive the wrapped key")
	}
}

func TestPublicPutKeepsOwnerWrappedKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("pubowner@example.com", "a passphrase")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("public with owner key"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	var put api.PutResourceResponse
	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, &put); code != http.StatusCreated {
		t.Fatalf("public put with wrapped key: %d", code)
	}

	// The owner keeps the wrapped key (so they can later share/private it)...
	var owner api.GetResourceResponse
	h.do(http.MethodGet, "/v1/resources/"+put.ID, token, nil, &owner)
	if owner.WrappedKey == nil {
		t.Fatal("owner should receive the wrapped key")
	}
	// ...but an anonymous reader never does.
	var anon api.GetResourceResponse
	h.do(http.MethodGet, "/v1/resources/"+put.ID, "", nil, &anon)
	if anon.WrappedKey != nil {
		t.Fatal("anonymous reader must not receive the wrapped key")
	}
}

func TestShareViewLandingPage(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("web@example.com", "a passphrase for the web view")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	put := func(vis api.Visibility) string {
		var resp api.PutResourceResponse
		if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
			Visibility: vis, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		}, &resp); code != http.StatusCreated {
			t.Fatalf("put %s: status %d", vis, code)
		}
		return resp.ID
	}

	// A public resource gets a human landing page that names it and shows pull.
	rec := h.get("/x/" + put(api.Public))
	if rec.Code != http.StatusOK {
		t.Fatalf("public share view: got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "aqt pull") {
		t.Fatal("landing page should show the pull command")
	}

	// A private id 404s: the page must never confirm a private resource exists.
	if rec := h.get("/x/" + put(api.Private)); rec.Code != http.StatusNotFound {
		t.Fatalf("private /x: got %d, want 404", rec.Code)
	}

	// An unknown id 404s too.
	if rec := h.get("/x/does-not-exist"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown /x: got %d, want 404", rec.Code)
	}
}

func TestPutResourceVersionConflictReturns409(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("occ-http@example.com", "passphrase for occ http")
	ck, _ := crypto.GenerateContentKey()

	put := func(id string, expected int, body string) (api.PutResourceResponse, int) {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
		var resp api.PutResourceResponse
		code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ExpectedVersion: expected,
		}, &resp)
		return resp, code
	}

	created, code := put("", 0, "v1")
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if _, code := put(created.ID, 1, "v2"); code != http.StatusOK {
		t.Fatalf("update@1: %d", code)
	}
	// Second writer still based on version 1 must be told to re-sync.
	if _, code := put(created.ID, 1, "v3"); code != http.StatusConflict {
		t.Fatalf("stale update: got %d, want 409", code)
	}
}

// raw issues a request with an opaque body and returns the recorder, for the pack
// transport (octet-stream PUT, range GET) the JSON do() helper cannot model.
func (h *harness) raw(method, path, token string, header map[string]string, body []byte) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func TestPackEndpointsRoundTrip(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("packapi@example.com", "passphrase for pack api")
	packID, pack, ids := packOf("hello pack world", "second object here")

	var check api.ChunkCheckResponse
	if code := h.do(http.MethodPost, "/v1/chunks/check", token,
		api.ChunkCheckRequest{IDs: ids}, &check); code != http.StatusOK {
		t.Fatalf("check: %d", code)
	}
	if len(check.Missing) != 2 {
		t.Fatalf("expected 2 missing before upload, got %d", len(check.Missing))
	}

	if rec := h.raw(http.MethodPut, "/v1/packs/"+packID, token,
		map[string]string{"Content-Type": "application/octet-stream"}, pack); rec.Code != http.StatusOK {
		t.Fatalf("put pack: %d (%s)", rec.Code, rec.Body.String())
	}

	if code := h.do(http.MethodPost, "/v1/chunks/check", token,
		api.ChunkCheckRequest{IDs: ids}, &check); code != http.StatusOK || len(check.Missing) != 0 {
		t.Fatalf("check after upload: code=%d missing=%d", code, len(check.Missing))
	}

	// Locate resolves an object to its pack byte range.
	var loc api.LocateResponse
	if code := h.do(http.MethodPost, "/v1/chunks/locate", token,
		api.LocateRequest{IDs: []string{ids[1]}}, &loc); code != http.StatusOK || len(loc.Locations) != 1 {
		t.Fatalf("locate: code=%d locations=%d", code, len(loc.Locations))
	}
	got := loc.Locations[0]
	if got.PackID != packID {
		t.Fatalf("located in pack %s, want %s", got.PackID, packID)
	}

	// Whole-pack GET returns the bytes verbatim.
	rec := h.raw(http.MethodGet, "/v1/packs/"+packID, token, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get pack: %d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), pack) {
		t.Fatal("whole-pack GET did not round-trip the bytes")
	}

	// A Range GET returns just the requested object slice (206 Partial Content).
	rng := fmt.Sprintf("bytes=%d-%d", got.Off, got.Off+got.Len-1)
	rec = h.raw(http.MethodGet, "/v1/packs/"+packID, token, map[string]string{"Range": rng}, nil)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("range get: %d, want 206", rec.Code)
	}
	if rec.Body.String() != "second object here" {
		t.Fatalf("range get body = %q, want the second object", rec.Body.String())
	}

	// A pack whose bytes do not match the id in the path is rejected.
	if rec := h.raw(http.MethodPut, "/v1/packs/"+packID, token,
		map[string]string{"Content-Type": "application/octet-stream"}, append([]byte("x"), pack...)); rec.Code != http.StatusBadRequest {
		t.Fatalf("mislabeled pack: got %d, want 400", rec.Code)
	}

	// The pack store requires auth.
	if code := h.do(http.MethodPost, "/v1/chunks/check", "",
		api.ChunkCheckRequest{IDs: ids}, nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated check: got %d, want 401", code)
	}
	if rec := h.raw(http.MethodGet, "/v1/packs/"+packID, "", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated pack get: got %d, want 401", rec.Code)
	}
}

func TestResourceBodyAllowsBlobAboveControlCap(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("bigblob@example.com", "passphrase for a big blob")

	// 1 MiB is far above the control-route cap; the resource route must still
	// accept it, since a folder's whole sealed manifest lives in this blob (A2).
	big := bytes.Repeat([]byte("x"), 1<<20)
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal(big, ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	var resp api.PutResourceResponse
	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, &resp); code != http.StatusCreated {
		t.Fatalf("1 MiB resource PUT: got %d, want 201", code)
	}
}

func TestControlRouteRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// A control body padded past the tight control cap is rejected by the size
	// limit (the same payload would be well within the resource route's cap).
	req := api.CreateAccountRequest{
		Email:      "x@example.com",
		PublicKey:  make([]byte, ed25519.PublicKeySize),
		DeviceName: strings.Repeat("a", maxControlBody+1),
	}
	if code := h.do(http.MethodPost, "/v1/account", "", req, nil); code < 400 {
		t.Fatalf("oversized control body: got %d, want a 4xx rejection", code)
	}
}

func TestDeviceListAndRevoke(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	const email, pass = "devices@example.com", "a passphrase for devices"
	token1, _ := h.signup(email, pass)

	// Attach a second device to the same account.
	var second api.AuthResponse
	if code := h.attachWith(email, pass, &second); code != http.StatusCreated {
		t.Fatalf("attach second device: %d", code)
	}

	// The owner sees both devices.
	var list api.ListDevicesResponse
	if code := h.do(http.MethodGet, "/v1/devices", token1, nil, &list); code != http.StatusOK {
		t.Fatalf("list devices: %d", code)
	}
	if len(list.Devices) != 2 {
		t.Fatalf("device count = %d, want 2", len(list.Devices))
	}

	// Listing requires auth.
	if code := h.do(http.MethodGet, "/v1/devices", "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list: got %d, want 401", code)
	}

	// A different account cannot revoke this account's device (ownership scoping).
	intruder, _ := h.signup("intruder@example.com", "another passphrase entirely")
	if code := h.do(http.MethodDelete, "/v1/devices/"+second.DeviceID, intruder, nil, nil); code != http.StatusNotFound {
		t.Fatalf("cross-owner revoke: got %d, want 404", code)
	}

	// The owner revokes the second device; its token stops working.
	if code := h.do(http.MethodDelete, "/v1/devices/"+second.DeviceID, token1, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke device: %d", code)
	}
	if code := h.do(http.MethodGet, "/v1/devices", second.Token, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked token still works: got %d, want 401", code)
	}

	// Only the first device remains.
	var after api.ListDevicesResponse
	if code := h.do(http.MethodGet, "/v1/devices", token1, nil, &after); code != http.StatusOK {
		t.Fatalf("post-revoke list: %d", code)
	}
	if len(after.Devices) != 1 {
		t.Fatalf("post-revoke device count = %d, want 1", len(after.Devices))
	}
}

func TestListResourcesReturnsWrappedKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("listkey@example.com", "passphrase for list key")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	metaJSON, _ := json.Marshal(api.Metadata{Name: "secret.env", Size: 4, Kind: api.KindFile})
	meta, _ := crypto.Seal(metaJSON, ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, nil); code != http.StatusCreated {
		t.Fatalf("put: %d", code)
	}

	var list api.ListResourcesResponse
	if code := h.do(http.MethodGet, "/v1/resources", token, nil, &list); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if len(list.Resources) != 1 {
		t.Fatalf("resource count = %d, want 1", len(list.Resources))
	}
	item := list.Resources[0]
	if item.WrappedKey == nil {
		t.Fatal("list item must carry the owner's wrapped key so ls can decrypt the name")
	}
	// The wrapped key + master key recover the name the client sealed.
	unwrapped, err := crypto.UnwrapKey(*item.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	plain, err := crypto.Open(item.EncryptedMeta, unwrapped, crypto.AADMeta)
	if err != nil {
		t.Fatalf("open meta: %v", err)
	}
	var got api.Metadata
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if got.Name != "secret.env" || got.Kind != api.KindFile {
		t.Fatalf("decrypted meta = %+v, want name=secret.env kind=file", got)
	}
}

// --- capability negotiation (issue #69) ---

// putCap PUTs a resource as a JSON body with an explicit X-Aqt-Capability header
// (empty capHdr omits it), so a test can act as a client of any capability. It
// returns the recorder; the caller asserts the status.
func (h *harness) putCap(token, capHdr string, req api.PutResourceRequest) *httptest.ResponseRecorder {
	h.t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		h.t.Fatal(err)
	}
	header := map[string]string{"Content-Type": "application/json"}
	if capHdr != "" {
		header[api.CapabilityHeader] = capHdr
	}
	return h.raw(http.MethodPut, "/v1/resources", token, header, body)
}

// getCap GETs a resource with an explicit capability header.
func (h *harness) getCap(id, token, capHdr string) *httptest.ResponseRecorder {
	h.t.Helper()
	header := map[string]string{}
	if capHdr != "" {
		header[api.CapabilityHeader] = capHdr
	}
	return h.raw(http.MethodGet, "/v1/resources/"+id, token, header, nil)
}

// sealResource builds a sealed private resource body declaring minClient.
func sealResource(t *testing.T, minClient int) (api.PutResourceRequest, crypto.ContentKey) {
	t.Helper()
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	return api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, MinClient: minClient,
	}, ck
}

func mustPutID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("put: status %d (%s)", rec.Code, rec.Body.String())
	}
	var out api.PutResourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	return out.ID
}

// TestCapabilityReadBelowMinClientIs426 covers the core gate: a read whose declared
// capability is below the resource's stored min_client is refused with 426 and a
// structured upgrade error, before any payload is served.
func TestCapabilityReadBelowMinClientIs426(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("cap-read@example.com", "a good long passphrase here")

	req, _ := sealResource(t, api.CapabilityIDBinding)
	id := mustPutID(t, h.putCap(token, "2", req))

	// A capability-1 client cannot read a capability-2 resource.
	rec := h.getCap(id, token, "1")
	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("read below min_client: got %d, want 426", rec.Code)
	}
	var e api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != api.ErrCodeUpgradeRequired {
		t.Fatalf("error code = %q, want %q", e.Code, api.ErrCodeUpgradeRequired)
	}
	if e.MinClient != api.CapabilityIDBinding {
		t.Fatalf("error min_client = %d, want %d", e.MinClient, api.CapabilityIDBinding)
	}

	// The same client at capability 2 reads it fine.
	if rec := h.getCap(id, token, "2"); rec.Code != http.StatusOK {
		t.Fatalf("read at min_client: got %d, want 200", rec.Code)
	}
}

// TestCapabilityMissingHeaderFailsClosed ensures a header-less legacy client never
// receives an id-bound encrypted resource.
func TestCapabilityMissingHeaderFailsClosed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("cap-missing.com", "a good long passphrase here")
	req, _ := sealResource(t, api.CapabilityIDBinding)
	id := mustPutID(t, h.putCap(token, "2", req))
	if rec := h.getCap(id, token, ""); rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("header-less read of min_client=2: got %d, want 426", rec.Code)
	}
}

// TestCapabilityWriteDeclaration covers the write-side rules: a declared min_client is
// stored, a declaration above the writer's own capability is rejected, and an omitted
// declaration stores the baseline.
func TestCapabilityWriteDeclaration(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("cap-write@example.com", "a good long passphrase here")

	// Declaring above the writer's own capability is a client bug: 400.
	req, _ := sealResource(t, 3)
	if rec := h.putCap(token, "2", req); rec.Code != http.StatusBadRequest {
		t.Fatalf("declare min_client 3 as a cap-2 client: got %d, want 400", rec.Code)
	}

	// An omitted declaration stores the baseline (1), readable by a cap-1 client.
	base, _ := sealResource(t, 0)
	idBase := mustPutID(t, h.putCap(token, "2", base))
	if rec := h.getCap(idBase, token, "1"); rec.Code != http.StatusOK {
		t.Fatalf("cap-1 read of an undeclared (baseline) resource: got %d, want 200", rec.Code)
	}
}

// TestCapabilityUpdateGate covers update enforcement: a client that cannot read the
// current state cannot overwrite it, but a capable client may lower min_client.
func TestCapabilityUpdateGate(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("cap-update@example.com", "a good long passphrase here")

	req, _ := sealResource(t, api.CapabilityIDBinding)
	id := mustPutID(t, h.putCap(token, "2", req))

	// A capability-1 client must not overwrite a capability-2 resource.
	upd, _ := sealResource(t, api.CapabilityBaseline)
	upd.ID = id
	if rec := h.putCap(token, "1", upd); rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("update by cap-1 client: got %d, want 426", rec.Code)
	}

	// A capable client may rewrite it in the baseline format, lowering min_client so
	// older clients can read it again.
	if rec := h.putCap(token, "2", upd); rec.Code != http.StatusOK {
		t.Fatalf("cap-2 client lowering min_client: got %d, want 200", rec.Code)
	}
	if rec := h.getCap(id, token, "1"); rec.Code != http.StatusOK {
		t.Fatalf("cap-1 read after min_client lowered: got %d, want 200", rec.Code)
	}
}

// TestCapabilityPublicReadEnforced covers the unauthenticated (public) read path,
// which is served by its own handler outside the authed group.
func TestCapabilityPublicReadEnforced(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("cap-public@example.com", "a good long passphrase here")

	req, _ := sealResource(t, api.CapabilityIDBinding)
	req.Visibility = api.Public
	id := mustPutID(t, h.putCap(token, "2", req))

	// Unauthenticated cap-1 read is gated the same as an owner read.
	if rec := h.getCap(id, "", "1"); rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("public cap-1 read: got %d, want 426", rec.Code)
	}
	if rec := h.getCap(id, "", "2"); rec.Code != http.StatusOK {
		t.Fatalf("public cap-2 read: got %d, want 200", rec.Code)
	}
}

func TestLivenessAndReadinessTransitions(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if rec := h.get("/livez"); rec.Code != http.StatusOK {
		t.Fatalf("livez = %d", rec.Code)
	}
	if rec := h.get("/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("readyz = %d", rec.Code)
	}
	h.srv.BeginShutdown()
	if rec := h.get("/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz during shutdown = %d", rec.Code)
	}
	if rec := h.get("/livez"); rec.Code != http.StatusOK {
		t.Fatalf("livez during shutdown = %d", rec.Code)
	}
}

func TestBackgroundWorkersDrainAfterStop(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	stop := make(chan struct{})
	h.srv.StartAutoSnapshot(time.Millisecond, 1, stop)
	h.srv.StartGC(time.Millisecond, stop)
	time.Sleep(5 * time.Millisecond)
	h.srv.BeginShutdown()
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.srv.WaitWorkers(ctx); err != nil {
		t.Fatalf("workers did not drain: %v", err)
	}
}
