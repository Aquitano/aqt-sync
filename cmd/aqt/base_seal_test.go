// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// TestMain (main_test.go) forces AQT_NO_KEYCHAIN, so these seal under the
// deterministic machine-bound key and round-trip within the process.

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

func TestSaveBaseSealsSecretsAtRest(t *testing.T) {
	root := t.TempDir()
	mkControlDir(t, root)
	if err := saveBase(root, sampleBase()); err != nil {
		t.Fatalf("saveBase: %v", err)
	}
	b, err := os.ReadFile(controlPath(root, baseFile))
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
	root := t.TempDir()
	mkControlDir(t, root)
	want := sampleBase()
	if err := saveBase(root, want); err != nil {
		t.Fatalf("saveBase: %v", err)
	}
	got, err := loadBase(root)
	if err != nil {
		t.Fatalf("loadBase: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	forSync, exists, err := loadBaseForSync(root)
	if err != nil || !exists {
		t.Fatalf("loadBaseForSync: exists=%v err=%v", exists, err)
	}
	if !reflect.DeepEqual(forSync, want) {
		t.Errorf("loadBaseForSync mismatch:\n got %+v\nwant %+v", forSync, want)
	}
}

// A bare manifest is not a base: reading one would trust chunk keys and inline
// plaintext that nothing sealed. The sync degrades to --reconcile instead.
func TestLoadBaseRefusesUnsealedManifest(t *testing.T) {
	root := t.TempDir()
	mkControlDir(t, root)

	plain, err := json.Marshal(sampleBase())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controlPath(root, baseFile), plain, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadBase(root); err == nil {
		t.Fatal("loadBase read an unsealed manifest, want a refusal")
	}
	m, exists, err := loadBaseForSync(root)
	if err != nil {
		t.Fatalf("loadBaseForSync: %v", err)
	}
	if exists || len(m.Entries) != 0 {
		t.Errorf("unsealed base reported usable: exists=%v entries=%d", exists, len(m.Entries))
	}
}

func TestLoadBaseForSyncTreatsCorruptAsAbsent(t *testing.T) {
	root := t.TempDir()
	mkControlDir(t, root)
	if err := os.WriteFile(controlPath(root, baseFile), []byte("}{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, exists, err := loadBaseForSync(root)
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
	if err := os.WriteFile(controlPath(root, baseFile), env, 0o600); err != nil {
		t.Fatal(err)
	}

	got, exists, err := loadBaseForSync(root)
	if err != nil || !exists {
		t.Fatalf("legacy envelope: exists=%v err=%v", exists, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("legacy round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}
