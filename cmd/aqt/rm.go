package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/client"
)

func rmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>...",
		Short: "Delete the server-side ciphertext and metadata for one or more resources",
		Args:  cobra.MinimumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runRemove(args) },
	}
}

func runRemove(refs []string) error {
	cl, _, err := authedClient()
	if err != nil {
		return err
	}
	for _, ref := range refs {
		id, _ := parseRef(ref)
		if err := cl.DeleteResource(id); err != nil {
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours); run `aqt ls` to list yours", id)
			}
			return err
		}
		fmt.Fprintf(os.Stderr, "deleted %s\n", id)
	}
	return nil
}
