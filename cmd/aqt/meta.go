// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// openMetadata unwraps a list item's content key with the master key and decrypts
// its sealed metadata. ok is false when the item carries no owner-wrapped key or
// the metadata cannot be decrypted, so callers can show a placeholder instead of
// failing the whole listing.
func openMetadata(it api.ResourceListItem, mk crypto.MasterKey) (m api.Metadata, ok bool) {
	if it.WrappedKey == nil {
		return api.Metadata{}, false
	}
	ck, err := crypto.UnwrapKey(*it.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.Metadata{}, false
	}
	defer ck.Wipe()
	plain, err := crypto.OpenBound(it.EncryptedMeta, ck, crypto.AADMeta, it.ID)
	if err != nil {
		return api.Metadata{}, false
	}
	if err := json.Unmarshal(plain, &m); err != nil {
		return api.Metadata{}, false
	}
	return m, true
}

func printJSON(v any) error { return printJSONTo(os.Stdout, v) }

// printJSONTo is printJSON against an explicit sink, so a command whose output a
// test needs to read does not have to redirect os.Stdout to get it.
func printJSONTo(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
