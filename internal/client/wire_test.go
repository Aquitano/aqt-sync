package client_test

import (
	"bytes"
	"crypto/ed25519"
	"net/http/httptest"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/server"
)

// TestResourceRawWireRoundTrip drives the real Client against the real router: the
// blob makes a full PUT/GET round trip over the raw octet-stream wire (byte
// identical), and a compressible JSON reply comes back through net/http's
// transparent gzip without any client-side decompression code.
func TestResourceRawWireRoundTrip(t *testing.T) {
	store, err := server.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	srv := httptest.NewServer(server.New(store).Router())
	t.Cleanup(srv.Close)

	token, mk := signup(t, srv.URL, "wire@example.com", "correct horse battery staple")
	cl, err := client.New(srv.URL, token)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	plaintext := []byte("SECRET=super-secret-value\nAPI_KEY=sk-live-987654321\n")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal(plaintext, ck, crypto.AADBlob)
	metaBlob, _ := crypto.Seal([]byte(`{"name":".env","size":52}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	put, err := cl.PutResource(api.PutResourceRequest{
		Visibility:    api.Private,
		Blob:          blob,
		EncryptedMeta: metaBlob,
		WrappedKey:    &wrapped,
	})
	if err != nil {
		t.Fatalf("PutResource: %v", err)
	}

	got, err := cl.GetResource(put.ID)
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	if !bytes.Equal(got.Blob.Ciphertext, blob.Ciphertext) || !bytes.Equal(got.Blob.Nonce, blob.Nonce) {
		t.Fatal("blob did not round-trip byte-identical over the raw wire")
	}
	if got.WrappedKey == nil {
		t.Fatal("missing wrapped key")
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
		t.Fatalf("plaintext mismatch: %q", decrypted)
	}

	// A large check reply is gzip-compressed on the wire and transparently
	// decompressed by net/http; CheckChunks returns plain ids either way.
	ids := make([]string, 400)
	for i := range ids {
		ids[i] = idHex(i)
	}
	missing, err := cl.CheckChunks(ids)
	if err != nil {
		t.Fatalf("CheckChunks: %v", err)
	}
	if len(missing) != len(ids) {
		t.Fatalf("missing = %d, want %d", len(missing), len(ids))
	}
}

func idHex(i int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 64)
	for j := range b {
		b[j] = '0'
	}
	for j := 63; i > 0 && j >= 0; j-- {
		b[j] = hex[i&0xf]
		i >>= 4
	}
	return string(b)
}

// signup creates an account through the HTTP API and returns its device token and
// master key, mirroring the server package's test harness.
func signup(t *testing.T, baseURL, email, passphrase string) (string, crypto.MasterKey) {
	t.Helper()
	kdf, err := crypto.NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey(passphrase, kdf)
	if err != nil {
		t.Fatal(err)
	}
	wrappedRoot, err := crypto.WrapRoot(mk, uk)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := client.New(baseURL, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.CreateAccount(api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   "wire-test",
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	return resp.Token, mk
}
