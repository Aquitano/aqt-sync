package main

import (
	"encoding/json"
	"fmt"
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
	plain, err := crypto.Open(it.EncryptedMeta, ck, crypto.AADMeta)
	if err != nil {
		return api.Metadata{}, false
	}
	if err := json.Unmarshal(plain, &m); err != nil {
		return api.Metadata{}, false
	}
	return m, true
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(b))
	return err
}

// humanBytes renders a byte count as a short human string (e.g. 1.2 KB).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
