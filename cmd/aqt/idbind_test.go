// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
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

// A bind write can commit and still lose its response. Cleanup must not read that as
// a failed write: the resource is bound and readable, and deleting it would take the
// share link a public push has already issued with it.
func TestBindSurvivesLostResponse(t *testing.T) {
	var dropped atomic.Bool
	newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		// The create is a POST; the PUT that follows is the id-binding write. Let it
		// reach the server, then throw its answer away as a dropped connection would.
		if r.Method == http.MethodPut && r.URL.Path == "/v1/resources" && dropped.CompareAndSwap(false, true) {
			pass(httptest.NewRecorder(), r)
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server connection is not hijackable")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		pass(w, r)
	})

	src := filepath.Join(t.TempDir(), "note.txt")
	body := []byte("bound before the answer was lost")
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatal(err)
	}
	printed := strings.TrimSpace(captureStdout(t, func() {
		if err := pushQuiet(src, pushOptions{public: true}); err != nil {
			t.Fatalf("push: %v", err)
		}
	}))
	if !dropped.Load() {
		t.Fatal("the id-binding write was never intercepted")
	}
	id, fragment, _ := parseRef(printed)
	if id == "" || fragment == "" {
		t.Fatalf("public push printed no usable share link: %q", printed)
	}
	assertSealedIDBound(t, "inline push whose bind response was lost", id, crypto.AADBlob)

	out := filepath.Join(t.TempDir(), "note.txt")
	if err := runPull(id, out, "", false, false); err != nil {
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

// A bind that definitively fails still takes the first version with it: that version
// is sealed unbound, so it opens for nobody and would only strand an orphan.
func TestBindFailureDeletesUnboundResource(t *testing.T) {
	var refused atomic.Bool
	newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/resources" && refused.CompareAndSwap(false, true) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(api.ErrorResponse{Error: "injected version conflict", Code: api.ErrCodeVersionConflict})
			return
		}
		pass(w, r)
	})

	src := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(src, []byte("never becomes readable"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := pushQuiet(src, pushOptions{})
	if err == nil {
		t.Fatal("push must fail when the id-binding write cannot land")
	}
	if !strings.Contains(err.Error(), "bind resource") {
		t.Fatalf("error does not name the failed bind: %v", err)
	}
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	items, err := cl.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("the unbound first version was left behind: %+v", items)
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
