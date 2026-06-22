package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// harness wires a real store (temp dir) to the Gin router for a full HTTP cycle.
type harness struct {
	t      *testing.T
	router *gin.Engine
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &harness{t: t, router: New(store).Router()}
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

// signup creates an account from a passphrase and returns its token + master key.
func (h *harness) signup(email, passphrase string) (token string, mk crypto.MasterKey) {
	h.t.Helper()
	kdf, err := crypto.NewKdfParams()
	if err != nil {
		h.t.Fatal(err)
	}
	mk, err = crypto.DeriveMasterKey(passphrase, kdf)
	if err != nil {
		h.t.Fatal(err)
	}
	var resp api.AuthResponse
	code := h.do(http.MethodPost, "/v1/account", "", api.CreateAccountRequest{
		Email:      email,
		Kdf:        kdf,
		PublicKey:  crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey),
		DeviceName: "test-device",
	}, &resp)
	if code != http.StatusCreated {
		h.t.Fatalf("signup: got status %d", code)
	}
	return resp.Token, mk
}

func TestPrivatePushPullRoundTrip(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("dev@example.com", "correct horse battery staple")

	plaintext := []byte("DATABASE_URL=postgres://localhost/app\nAPI_KEY=sk-live-123\n")

	// Client-side seal: content key seals the body and the metadata; the content
	// key itself is wrapped under the master key for a private resource.
	ck, _ := crypto.GenerateContentKey()
	blob, err := crypto.Seal(plaintext, ck)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, _ := json.Marshal(api.Metadata{Name: ".env", Size: int64(len(plaintext))})
	metaBlob, err := crypto.Seal(metaJSON, ck)
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
	decrypted, err := crypto.Open(got.Blob, unwrapped)
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
	h := newHarness(t)
	token, _ := h.signup("pub@example.com", "another passphrase here")

	plaintext := []byte("public snippet")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal(plaintext, ck)
	metaBlob, _ := crypto.Seal([]byte(`{"name":"note.txt","size":14}`), ck)

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
	decrypted, err := crypto.Open(got.Blob, ck)
	if err != nil {
		t.Fatalf("open public blob: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("public round trip mismatch: %q", decrypted)
	}
}

// attachWith fetches a challenge and attaches a device by signing the nonce with
// the signing key derived from passphrase. Returns the HTTP status.
func (h *harness) attachWith(email, passphrase string, kdf crypto.KdfParams, out *api.AuthResponse) int {
	h.t.Helper()
	mk, err := crypto.DeriveMasterKey(passphrase, kdf)
	if err != nil {
		h.t.Fatal(err)
	}
	var ch api.ChallengeResponse
	if code := h.do(http.MethodPost, "/v1/auth/challenge", "", api.ChallengeRequest{Email: email}, &ch); code != http.StatusOK {
		h.t.Fatalf("challenge: status %d", code)
	}
	var target any // avoid handing do() a typed-nil *AuthResponse to decode into
	if out != nil {
		target = out
	}
	return h.do(http.MethodPost, "/v1/devices", "", api.AttachDeviceRequest{
		Email:       email,
		ChallengeID: ch.ChallengeID,
		Signature:   ed25519.Sign(crypto.DeriveSigningKey(mk), ch.Nonce),
		DeviceName:  "device-2",
	}, target)
}

func TestDeviceAttachVerifiesSignature(t *testing.T) {
	h := newHarness(t)
	const email, pass = "multi@example.com", "shared passphrase"
	h.signup(email, pass)

	var salt api.SaltResponse
	if code := h.do(http.MethodGet, "/v1/account/salt?email="+email, "", nil, &salt); code != http.StatusOK {
		t.Fatalf("salt: status %d", code)
	}

	var resp api.AuthResponse
	if code := h.attachWith(email, pass, salt.Kdf, &resp); code != http.StatusCreated || resp.Token == "" {
		t.Fatalf("attach with correct passphrase: status %d, token=%q", code, resp.Token)
	}

	// Wrong passphrase derives a different signing key, so the signature fails.
	if code := h.attachWith(email, "not the passphrase", salt.Kdf, nil); code != http.StatusUnauthorized {
		t.Fatalf("attach with wrong passphrase: got %d, want 401", code)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	const email, pass = "replay@example.com", "a passphrase"
	h.signup(email, pass)
	mk, _ := crypto.DeriveMasterKey(pass, mustSalt(h, email))

	var ch api.ChallengeResponse
	if code := h.do(http.MethodPost, "/v1/auth/challenge", "", api.ChallengeRequest{Email: email}, &ch); code != http.StatusOK {
		t.Fatalf("challenge: status %d", code)
	}
	sig := ed25519.Sign(crypto.DeriveSigningKey(mk), ch.Nonce)
	attach := func(out any) int {
		return h.do(http.MethodPost, "/v1/devices", "", api.AttachDeviceRequest{
			Email: email, ChallengeID: ch.ChallengeID, Signature: sig, DeviceName: "d",
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

func TestUpdateResourceReplacesInPlace(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("upd@example.com", "passphrase for updates")

	put := func(id string, body []byte) api.PutResourceResponse {
		ck, _ := crypto.GenerateContentKey()
		blob, _ := crypto.Seal(body, ck)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck)
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
	blob, _ := crypto.Seal([]byte("hijack"), ck)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	code := h.do(http.MethodPut, "/v1/resources", otherToken, api.PutResourceRequest{
		ID: created.ID, Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, nil)
	if code != http.StatusNotFound {
		t.Fatalf("cross-owner update: got %d, want 404", code)
	}
}

func mustSalt(h *harness, email string) crypto.KdfParams {
	h.t.Helper()
	var salt api.SaltResponse
	if code := h.do(http.MethodGet, "/v1/account/salt?email="+email, "", nil, &salt); code != http.StatusOK {
		h.t.Fatalf("salt: status %d", code)
	}
	return salt.Kdf
}
