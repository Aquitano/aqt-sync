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
	// blob: documents (Raw/Download) inherit this CSP; unsafe-inline scripts
	// would let a hostile shared SVG run in this origin.
	if strings.Contains(strings.SplitAfter(csp, "style-src")[0], "'unsafe-inline'") {
		t.Errorf("script-src must not allow 'unsafe-inline' (got %q)", csp)
	}

	body := rec.Body.String()
	for _, want := range []string{
		resp.ID,                          // page is bound to the resource
		"state-locked",                   // consent-before-fetch state exists
		"is-decrypted",                   // successful state expands into the file workspace
		"line-numbers",                   // text previews include an accessible, non-selectable gutter
		"Decrypt in browser",             // primary action
		"aqt pull",                       // CLI fallback stays available
		`name="robots" content="noindex`, // share pages stay out of indexes
		`src="/x-assets/libsodium-0.7.10.js"`,
		`src="/x-assets/hash-wasm-argon2-4.9.0.js"`,
		`src="/x-assets/fzstd-0.1.1.js"`, // zstd decoder for folder/streamed downloads
		`src="/x-assets/share.js"`,
		`id="state-folder"`,            // the in-browser folder browser state
		`id="folder-list"`,             // its listing container
		"Files, folders, and streamed", // copy now advertises folder/streamed support
		`for="password-input"`,         // password field has a visible accessible label
		`role="alert"`,                 // failures are announced
		`aria-live="polite"`,           // progress is announced without stealing semantics
		`id="policy-note"`,             // expiry/read policy is shown before consent
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q", want)
		}
	}
	if strings.Contains(body, "AqtCrypto") {
		t.Error("page script must be served as an asset, not inlined (CSP has no script-src 'unsafe-inline')")
	}
	if strings.Contains(body, "single inline files only") {
		t.Error("share page still claims browser decryption is inline-only after folder support landed")
	}
	if strings.Contains(body, "#…") {
		t.Error("page must not present a truncated fragment as a runnable CLI command")
	}

	// The decryptor logic ships in the external page script, including the folder
	// walk over content-addressed objects.
	script := h.get("/x-assets/share.js")
	if script.Code != http.StatusOK {
		t.Fatalf("share.js: got %d, want 200", script.Code)
	}
	for _, want := range []string{
		"crypto_aead_xchacha20poly1305_ietf_decrypt",
		"hashwasm.argon2id",
		"aqt-treenode-v1",         // directory-node AAD, mirrors crypto.aadTreeNode
		"/v1/public/resources/",   // the exact-slice objects endpoint
		"fzstd.decompress",        // zstd path for compressed objects/nodes
		"/preflight",              // uncounted metadata/policy inspection
		`"X-Aqt-Capability": "3"`, // browser advertises sealed-format support
		"INSPECTING ENCRYPTED METADATA",
		"no read was consumed",
	} {
		if !strings.Contains(script.Body.String(), want) {
			t.Errorf("share.js missing %q", want)
		}
	}
	if strings.Contains(body, "The server stores only ciphertext") {
		t.Error("share page still contains the removed explanatory lede")
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
		"fzstd-0.1.1.js",
		"share.js",
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
