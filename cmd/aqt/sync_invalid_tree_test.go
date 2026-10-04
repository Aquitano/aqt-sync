// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func TestSyncRejectsAbsoluteRemotePath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &application{ctx: ctx}
	h := app.newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	h.sync(dir)
	cl, prof, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := app.unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	res, err := cl.GetResource(h.folderID(dir))
	if err != nil {
		t.Fatal(err)
	}
	owned, err := openOwnedResource(res, mk)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.ck.Wipe()
	node := syncengine.TreeNode{Version: syncengine.TreeManifestVersion, Children: []syncengine.TreeChild{{Name: "/evil", Type: syncengine.ChildFile, Hash: "crafted", Inline: []byte("x"), Size: 1, Mode: 0600}}}
	plain, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	ct, chunk, err := crypto.SealNode(plain, crypto.DeriveConvergenceKey(mk))
	if err != nil {
		t.Fatal(err)
	}
	up := app.newUploader(cl, nil)
	if err := up.Add(chunk, ct); err != nil {
		t.Fatal(err)
	}
	if err := up.Flush(); err != nil {
		t.Fatal(err)
	}
	blob, err := syncengine.SealTreeRoot(syncengine.TreeRoot{Version: syncengine.TreeManifestVersion, Root: chunk}, owned.ck, res.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.PutResource(api.PutResourceRequest{ID: res.ID, ExpectedVersion: res.Version, Visibility: res.Visibility, Blob: blob, EncryptedMeta: res.EncryptedMeta, WrappedKey: res.WrappedKey, MinClient: res.MinClient})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- app.runSync(dir, syncOptions{dryRun: true}) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "invalid child name") {
			t.Fatalf("sync returned %v, want an invalid child name error", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("sync --dry-run did not reject an absolute remote path")
	}
}
