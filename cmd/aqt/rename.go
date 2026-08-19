// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func renameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "mv <name-or-id|tracked-path> <new-name>",
		Aliases: []string{"rename"},
		Short:   "Rename a resource without re-uploading its content",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRename(args[0], args[1])
		},
	}
	markJSONSupported(cmd)
	return cmd
}

func runRename(ref, newName string) error {
	if strings.TrimSpace(newName) == "" {
		return errors.New("new name must not be empty")
	}
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	id, err := resolveOwnedResourceID(cl, mk, ref)
	if err != nil {
		return err
	}
	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found (or not yours)", id)
	}
	if err != nil {
		return err
	}
	if res.WrappedKey == nil {
		return errors.New("resource has no owner key; cannot decrypt and re-seal its metadata")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return fmt.Errorf("unwrap key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	oldName := meta.Name
	warnOnNameCollision(cl, mk, id, newName)
	meta.Name = newName
	plain, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	sealed, err := crypto.SealBound(plain, ck, crypto.AADMeta, id)
	if err != nil {
		return err
	}
	resp, err := cl.UpdateResourceMetadata(id, api.UpdateResourceMetadataRequest{
		EncryptedMeta: sealed, ExpectedVersion: res.Version,
	})
	if errors.Is(err, client.ErrConflict) {
		return errors.New("resource changed while renaming it; retry the command")
	}
	if errors.Is(err, client.ErrNotFound) {
		// GetResource for this id succeeded moments ago, so the resource was deleted in
		// between — by another device, or by its link's lifecycle policy firing.
		return fmt.Errorf("resource %s was deleted while renaming it", id)
	}
	if err != nil {
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"id": id, "oldName": oldName, "name": newName, "version": resp.Version})
	}
	fmt.Printf("renamed %s to %q\n", id, newName)
	return nil
}

// warnOnNameCollision alerts (to stderr) when newName already decrypts to another
// resource's name. The rename still proceeds — names are not unique keys — but later
// name-based refs to newName would resolve as "ambiguous", so the user is told why.
// A listing failure is non-fatal here: it must never block the rename itself.
func warnOnNameCollision(cl *client.Client, mk crypto.MasterKey, id, newName string) {
	items, err := cl.ListResources()
	if err != nil {
		return
	}
	for _, it := range items {
		if it.ID == id {
			continue
		}
		if meta, ok := openMetadata(it, mk); ok && meta.Name == newName {
			fmt.Fprintf(os.Stderr, "warning: %q already names resource %s; refer to either by id, not name\n", newName, it.ID)
			return
		}
	}
}
