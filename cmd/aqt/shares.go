package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

func sharesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shares",
		Short: "List resources other accounts granted you (read-only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			items, err := cl.ListShares()
			if err != nil {
				return err
			}
			if len(items) == 0 {
				fmt.Println("no incoming shares")
				return nil
			}
			mk, err := unlockMaster(prof)
			if err != nil {
				return err
			}
			defer mk.Wipe()
			for _, it := range items {
				since := time.Unix(it.CreatedAt, 0).Format("2006-01-02")
				ck, err := crypto.UnwrapGrant(it.WrappedKey, mk, it.ResourceID, it.OwnerHandle, prof.OwnerHandle)
				if err != nil {
					// The owner rotated the key after granting (or the wrap is bound to
					// someone else); the grant row exists but no longer opens anything.
					fmt.Printf("aqt://%s  (stale grant — ask the owner to re-share)  from %s  since %s\n",
						it.ResourceID, it.OwnerHandle, since)
					continue
				}
				meta, err := decodeMeta(it.EncryptedMeta, ck, it.ResourceID)
				ck.Wipe()
				name := "(undecryptable metadata)"
				kind := ""
				if err == nil {
					name = meta.Name
					kind = string(meta.Kind)
				}
				fmt.Printf("aqt://%s  %s  %s  from %s  since %s\n", it.ResourceID, name, kind, it.OwnerHandle, since)
			}
			fmt.Println("\npull with `aqt pull aqt://<id>`; folders: `aqt clone aqt://<id>` (read-only)")
			return nil
		},
	}
}
