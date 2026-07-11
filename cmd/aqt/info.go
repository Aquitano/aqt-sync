package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
)

func infoCmd() *cobra.Command {
	var pw passwordFlags
	cmd := &cobra.Command{
		Use:   "info <id|url>",
		Short: "Show one resource's metadata (name, kind, size, visibility)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return runInfo(args[0], password, flagJSON)
		},
	}
	pw.bind(cmd, "password for a gated link")
	return cmd
}

func runInfo(ref, password string, asJSON bool) error {
	id, fragment, origin := parseRef(ref)

	// Metadata for your own resource needs the account token (to fetch) and the
	// master key (to unwrap); a public link instead decrypts from its fragment and
	// needs no profile — the same key recovery as pull. Honor a host embedded in
	// the ref, without attaching the token to a foreign host (see newLinkClient).
	prof := loadProfileOptional()
	cl, err := newLinkClient(origin, prof)
	if err != nil {
		return err
	}

	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found (or private and you're not its owner)", id)
	}
	if err != nil {
		return err
	}

	ck, err := contentKey(res, fragment, password, prof)
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
	if asJSON {
		return printJSON(lsRow{
			ID: res.ID, Name: meta.Name, Kind: kind, Size: meta.Size,
			Visibility: string(res.Visibility), Version: res.Version,
		})
	}
	name := meta.Name
	if name == "" {
		name = "(unnamed)"
	}
	fmt.Println(name)
	fmt.Printf("%s · %s · %s · v%d · %s\n", kind, sizeCell(kind, meta.Size), res.Visibility, res.Version, res.ID)
	return nil
}
