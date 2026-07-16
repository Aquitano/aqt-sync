package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// shareRow is one incoming grant, as shown by `aqt shares`.
type shareRow struct {
	Ref   string `json:"ref"`
	Name  string `json:"name,omitempty"`
	Kind  string `json:"kind,omitempty"`
	From  string `json:"from"`
	Since string `json:"since"`
	Stale bool   `json:"stale,omitempty"` // the wrap no longer opens (owner rotated the key)
}

func sharesCmd() *cobra.Command {
	cmd := &cobra.Command{
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
				if flagJSON {
					return printJSON([]shareRow{})
				}
				fmt.Println("no incoming shares")
				return nil
			}
			mk, err := unlockMaster(prof)
			if err != nil {
				return err
			}
			defer mk.Wipe()
			rows := make([]shareRow, 0, len(items))
			for _, it := range items {
				row := shareRow{
					Ref:   "aqt://" + it.ResourceID,
					From:  it.OwnerHandle,
					Since: time.Unix(it.CreatedAt, 0).Format("2006-01-02"),
				}
				ck, err := crypto.UnwrapGrant(it.WrappedKey, mk, it.ResourceID, it.OwnerHandle, prof.OwnerHandle)
				if err != nil {
					// The owner rotated the key after granting (or the wrap is bound to
					// someone else); the grant row exists but no longer opens anything.
					row.Stale = true
					rows = append(rows, row)
					continue
				}
				meta, err := decodeMeta(it.EncryptedMeta, ck, it.ResourceID)
				ck.Wipe()
				row.Name = "(undecryptable metadata)"
				if err == nil {
					row.Name = meta.Name
					row.Kind = string(meta.Kind)
				}
				rows = append(rows, row)
			}
			if flagJSON {
				return printJSON(rows)
			}
			for _, r := range rows {
				if r.Stale {
					fmt.Printf("%s  (stale grant — ask the owner to re-share)  from %s  since %s\n", r.Ref, r.From, r.Since)
					continue
				}
				fmt.Printf("%s  %s  %s  from %s  since %s\n", r.Ref, r.Name, r.Kind, r.From, r.Since)
			}
			fmt.Println("\npull with `aqt pull aqt://<id>`; folders: `aqt clone aqt://<id>` (read-only)")
			return nil
		},
	}
	markJSONSupported(cmd)
	return cmd
}
