// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// Every create seals its body and metadata before the server has assigned an id, then
// re-seals both bound to it. Reads open bound-only, so a create path that skipped the
// bind would leave content nothing can open — assert the stored form per create path.
func TestCreatesSealIDBound(t *testing.T) {
	h := newE2E(t)

	inline := filepath.Join(t.TempDir(), "note.txt")
	body := []byte("inline body")
	if err := os.WriteFile(inline, body, 0o644); err != nil {
		t.Fatal(err)
	}
	printed := strings.TrimSpace(captureStdout(t, func() {
		if err := pushQuiet(inline, pushOptions{}); err != nil {
			t.Fatalf("push: %v", err)
		}
	}))
	inlineID, _, _ := parseRef(printed)
	if inlineID == "" {
		t.Fatalf("could not parse id from push output %q", printed)
	}

	streamID, _, _ := pushRandomStreamedFile(t, 9<<20, pushOptions{})

	dir := t.TempDir()
	h.init(dir)

	if err := runRepoCreate("bound", 64); err != nil {
		t.Fatalf("repo create: %v", err)
	}

	for _, tc := range []struct {
		what string
		id   string
		role []byte
	}{
		{"inline push", inlineID, crypto.AADBlob},
		{"streamed push", streamID, crypto.AADBlob},
		{"folder init", h.folderID(dir), crypto.AADTreeRoot},
		{"git remote create", gitRemoteIDForTest(t, "bound"), crypto.AADGitRefsRoot},
	} {
		assertSealedIDBound(t, tc.what, tc.id, tc.role)
	}

	// A create followed by a read, end to end on the bound-only path.
	out := filepath.Join(t.TempDir(), "note.txt")
	if err := runPull(inlineID, out, "", false, false); err != nil {
		t.Fatalf("pull: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("pulled %q, want %q", got, body)
	}
}

// assertSealedIDBound fails unless the resource's body and metadata open under the
// id-bound (v2) AAD and no longer open under the unbound (v1) role tag.
func assertSealedIDBound(t *testing.T, what, id string, role []byte) {
	t.Helper()
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("no cached session")
	}
	res, err := cl.GetResource(id)
	if err != nil {
		t.Fatalf("%s: get resource %s: %v", what, id, err)
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	for _, sealed := range []struct {
		name string
		blob crypto.SealedBlob
		role []byte
	}{
		{"body", res.Blob, role},
		{"metadata", res.EncryptedMeta, crypto.AADMeta},
	} {
		if _, err := crypto.Open(sealed.blob, ck, crypto.BoundAAD(sealed.role, id)); err != nil {
			t.Errorf("%s: %s is not sealed to the resource id: %v", what, sealed.name, err)
		}
		if _, err := crypto.Open(sealed.blob, ck, sealed.role); err == nil {
			t.Errorf("%s: %s is still stored in the unbound v1 form", what, sealed.name)
		}
	}
}

func gitRemoteIDForTest(t *testing.T, name string) string {
	t.Helper()
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("no cached session")
	}
	items, err := cl.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range gitRemoteItems(items) {
		if meta, ok := openMetadata(it, mk); ok && meta.Name == name {
			return it.ID
		}
	}
	t.Fatalf("git remote %q not found in the listing", name)
	return ""
}
