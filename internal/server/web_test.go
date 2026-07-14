package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// The share landing page carries the in-browser decryptor: it must name the
// resource, ship the client-side state machine, and pin a CSP that keeps the
// fragment key from ever leaving the page.
func TestShareViewServesDecryptorPage(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("decryptor@example.com", "a passphrase for the decryptor page")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	var resp api.PutResourceResponse
	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, &resp); code != http.StatusCreated {
		t.Fatalf("put: status %d", code)
	}

	rec := h.get("/x/" + resp.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("share view: got %d, want 200", rec.Code)
	}

	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "'wasm-unsafe-eval'", "connect-src 'self'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing %q (got %q)", directive, csp)
		}
	}

	body := rec.Body.String()
	for _, want := range []string{
		resp.ID,                          // page is bound to the resource
		"state-locked",                   // consent-before-fetch state exists
		"Decrypt in browser",             // primary action
		"aqt pull",                       // CLI fallback stays available
		`name="robots" content="noindex`, // share pages stay out of indexes
		`src="/x-assets/libsodium-0.7.10.js"`,
		`src="/x-assets/hash-wasm-argon2-4.9.0.js"`,
		"crypto_aead_xchacha20poly1305_ietf_decrypt",
		"hashwasm.argon2id",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q", want)
		}
	}

	// The error pages keep the same guarantees they had before the redesign.
	if rec := h.get("/x/does-not-exist"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown /x: got %d, want 404", rec.Code)
	}
}

func TestShareCryptoAssetsAreSelfHostedAndAllowlisted(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{
		"libsodium-0.7.10.js",
		"libsodium-wrappers-0.7.10.js",
		"hash-wasm-argon2-4.9.0.js",
	} {
		rec := h.get("/x-assets/" + name)
		if rec.Code != http.StatusOK {
			t.Fatalf("asset %s: got %d, want 200", name, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/javascript") {
			t.Errorf("asset %s content type = %q", name, got)
		}
		if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
			t.Errorf("asset %s CORP = %q", name, got)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("asset %s is empty", name)
		}
	}

	if rec := h.get("/x-assets/share.html"); rec.Code != http.StatusNotFound {
		t.Fatalf("non-allowlisted embedded file: got %d, want 404", rec.Code)
	}
}
