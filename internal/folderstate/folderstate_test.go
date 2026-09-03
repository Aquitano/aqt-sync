// SPDX-License-Identifier: AGPL-3.0-or-later

package folderstate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// noKeychain seals under the deterministic machine-bound key, so a base round-trips
// within the process and a locked CI keychain is never reached.
func noKeychain(t *testing.T) {
	t.Helper()
	t.Setenv("AQT_NO_KEYCHAIN", "1")
}

func sampleBase() syncengine.Manifest {
	return syncengine.Manifest{
		Version: 7,
		Entries: []syncengine.Entry{
			{Path: "secret.env", Mode: 0o600, Size: 12, Hash: "hash-secret-env", Inline: []byte("API_KEY=1234")},
			{Path: "big.bin", Mode: 0o644, Size: 4096, Hash: "hash-big-bin",
				Chunks: []crypto.Chunk{{ID: "obj1", Key: []byte("chunk-decryption-key"), Len: 4096}}},
		},
	}
}

func mkControlDir(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, syncengine.ControlDir), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestSaveStateRoundTripAtomic(t *testing.T) {
	root := t.TempDir()
	ctl := filepath.Join(root, syncengine.ControlDir)
	if err := os.MkdirAll(ctl, 0o700); err != nil {
		t.Fatal(err)
	}

	first := State{ID: "res-1", Server: "https://one.example", Profile: "default", Account: "acct-1", RemoteVersion: 1}
	if err := SaveState(root, first); err != nil {
		t.Fatal(err)
	}
	// Overwrite with new content; the file must end up holding the new state.
	second := first
	second.ID, second.Server = "res-2", "https://two.example"
	if err := SaveState(root, second); err != nil {
		t.Fatal(err)
	}

	st, err := LoadState(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != "res-2" || st.Server != "https://two.example" {
		t.Fatalf("round-trip mismatch: %+v", st)
	}

	// File mode bits are a Unix concept; Windows reports 0666 for a writable file.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(StatePath(root)); err != nil {
			t.Fatal(err)
		} else if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("state perms = %o, want 600", perm)
		}
	}

	ents, err := os.ReadDir(ctl)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".aqt-tmp-") {
			t.Fatalf("leftover temp file after SaveState: %s", e.Name())
		}
	}
}

func TestSaveBaseSealsSecretsAtRest(t *testing.T) {
	noKeychain(t)
	root := t.TempDir()
	mkControlDir(t, root)
	if err := SaveBase(root, "", sampleBase()); err != nil {
		t.Fatalf("SaveBase: %v", err)
	}
	b, err := os.ReadFile(BasePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, baseMagic) {
		t.Errorf("base.json is not the sealed binary envelope: %s", b)
	}
	// Paths, chunk keys, hashes, and the entries array must not survive in the clear.
	for _, leak := range []string{"secret.env", "big.bin", "chunk-decryption-key", "entries", "hash-secret-env"} {
		if bytes.Contains(b, []byte(leak)) {
			t.Errorf("base.json leaks %q in cleartext: %s", leak, b)
		}
	}
}

func TestBaseSealRoundTrip(t *testing.T) {
	noKeychain(t)
	root := t.TempDir()
	mkControlDir(t, root)
	want := sampleBase()
	if err := SaveBase(root, "", want); err != nil {
		t.Fatalf("SaveBase: %v", err)
	}
	got, err := LoadBase(root, "")
	if err != nil {
		t.Fatalf("LoadBase: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	forSync, exists, err := LoadBaseForSync(root, "")
	if err != nil || !exists {
		t.Fatalf("LoadBaseForSync: exists=%v err=%v", exists, err)
	}
	if !reflect.DeepEqual(forSync, want) {
		t.Errorf("LoadBaseForSync mismatch:\n got %+v\nwant %+v", forSync, want)
	}
}

// A bare manifest is not a base: reading one would trust chunk keys and inline
// plaintext that nothing sealed. The sync degrades to --reconcile instead.
func TestLoadBaseRefusesUnsealedManifest(t *testing.T) {
	noKeychain(t)
	root := t.TempDir()
	mkControlDir(t, root)

	plain, err := json.Marshal(sampleBase())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(BasePath(root), plain, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadBase(root, ""); err == nil {
		t.Fatal("LoadBase read an unsealed manifest, want a refusal")
	}
	m, exists, err := LoadBaseForSync(root, "")
	if err != nil {
		t.Fatalf("LoadBaseForSync: %v", err)
	}
	if exists || len(m.Entries) != 0 {
		t.Errorf("unsealed base reported usable: exists=%v entries=%d", exists, len(m.Entries))
	}
}

func TestLoadBaseForSyncTreatsCorruptAsAbsent(t *testing.T) {
	noKeychain(t)
	root := t.TempDir()
	mkControlDir(t, root)
	if err := os.WriteFile(BasePath(root), []byte("}{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, exists, err := LoadBaseForSync(root, "")
	if err != nil {
		t.Fatalf("corrupt base should not error, got %v", err)
	}
	if exists {
		t.Error("corrupt base should report exists=false")
	}
	if len(m.Entries) != 0 {
		t.Error("corrupt base should yield an empty manifest")
	}
}

// A base written by a build predating the binary envelope (a base64 JSON
// {"sealed": ...} wrapper) must keep loading, or every upgraded folder would be
// forced through --reconcile.
func TestLoadBaseReadsLegacyJSONEnvelope(t *testing.T) {
	noKeychain(t)
	root := t.TempDir()
	mkControlDir(t, root)
	want := sampleBase()

	plain, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := identity.SealBase("", plain)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(sealedBase{Sealed: &sealed})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(BasePath(root), env, 0o600); err != nil {
		t.Fatal(err)
	}

	got, exists, err := LoadBaseForSync(root, "")
	if err != nil || !exists {
		t.Fatalf("legacy envelope: exists=%v err=%v", exists, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("legacy round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

// FuzzDecodeBase feeds arbitrary bytes to the base.json decoder, which reads a control
// file that a hostile actor with local access could tamper with. The invariant is that
// no byte sequence panics: anything but an openable sealed envelope is an error.
// Keychain access is disabled so the sealed branch resolves deterministically to a
// decrypt failure rather than reaching the host keyring.
func FuzzDecodeBase(f *testing.F) {
	f.Add([]byte(`{"entries":[{"path":"a","hash":"x"}]}`))
	f.Add([]byte(`{"sealed":{"nonce":"AAAA","ciphertext":"AAAA"}}`))
	f.Add([]byte("not json"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		t.Setenv("AQT_NO_KEYCHAIN", "1")
		var m syncengine.Manifest
		_ = decodeBase(b, "", &m)
	})
}
