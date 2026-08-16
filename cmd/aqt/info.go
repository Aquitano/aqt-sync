// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func infoCmd() *cobra.Command {
	var pw passwordFlags
	cmd := &cobra.Command{
		Use:   "info <name-or-id|tracked-path|url>",
		Short: "Show one resource's metadata and link lifecycle",
		Long: "Show one resource's metadata. For a link you own it also prints the link's\n" +
			"lifecycle (expiry and read counts); those fields are withheld from public links.\n\n" +
			"Inspecting someone else's public link fetches the resource, which counts as one\n" +
			"of the link's reads. Reads of your own resources are never counted.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return runInfo(args[0], password, flagJSON)
		},
	}
	pw.bind(cmd, "password for a gated link")
	markJSONSupported(cmd)
	return cmd
}

type infoRow struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Size           int64  `json:"size"`
	Visibility     string `json:"visibility"`
	Version        int    `json:"version"`
	CreatedAt      int64  `json:"createdAt,omitempty"`
	UpdatedAt      int64  `json:"updatedAt,omitempty"`
	ExpiresAt      int64  `json:"expiresAt,omitempty"`
	Reads          int64  `json:"reads,omitempty"`
	MaxReads       int64  `json:"maxReads,omitempty"`
	ReadsRemaining *int64 `json:"readsRemaining,omitempty"`
}

func runInfo(ref, password string, asJSON bool) error {
	id, fragment, origin := parseRef(ref)

	prof := loadProfileOptional()
	cl, err := newLinkClient(origin, prof)
	if err != nil {
		return err
	}
	// Unlock the master key at most once per invocation: resolving an owned ref by name
	// and unwrapping the owner key below both need it, and a second unlockMaster would
	// prompt for the passphrase again whenever session caching is unavailable.
	var master *crypto.MasterKey
	if origin == "" && fragment == "" && prof != nil {
		mk, err := unlockMaster(prof)
		if err != nil {
			return err
		}
		defer mk.Wipe()
		master = &mk
		id, err = resolveOwnedResourceID(cl, mk, ref)
		if err != nil {
			return err
		}
	}

	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found (or private and you're not its owner)", id)
	}
	if err != nil {
		return err
	}

	ck, err := contentKeyWithMaster(res, fragment, password, prof, master)
	if err != nil {
		return err
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck, res.ID)
	if err != nil {
		return err
	}

	kind := meta.Kind
	if kind == "" {
		kind = api.KindFile
	}
	// `aqt info <link>` inspects resources this account did not write, so the name and
	// kind are another author's plaintext (see foreignText).
	row := infoRow{
		ID: res.ID, Name: foreignText(meta.Name), Kind: foreignText(kind), Size: meta.Size,
		Visibility: foreignText(string(res.Visibility)), Version: res.Version,
		CreatedAt: res.CreatedAt, UpdatedAt: res.UpdatedAt,
		ExpiresAt: res.ExpiresAt, Reads: res.Reads, MaxReads: res.MaxReads,
	}
	if res.MaxReads > 0 {
		remaining := max(res.MaxReads-res.Reads, 0)
		row.ReadsRemaining = &remaining
	}
	if asJSON {
		return printJSON(row)
	}
	name := row.Name
	if name == "" {
		name = "(unnamed)"
	}
	fmt.Println(name)
	fmt.Printf("%s · %s · %s · v%d · %s\n", row.Kind, sizeCell(kind, meta.Size), row.Visibility, res.Version, res.ID)
	if res.ExpiresAt > 0 {
		until := time.Until(time.Unix(res.ExpiresAt, 0)).Round(time.Second)
		fmt.Printf("link expires %s (%s remaining)\n", cliutil.FormatUnix(res.ExpiresAt), until)
	}
	if row.ReadsRemaining != nil {
		fmt.Printf("link reads %d/%d (%d remaining)\n", res.Reads, res.MaxReads, *row.ReadsRemaining)
	}
	return nil
}
