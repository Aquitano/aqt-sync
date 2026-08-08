package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/server"
)

func TestWithStoreRejectsMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	err := withStore(adminTestCommand(dir), func(*server.Store) error {
		t.Fatal("callback ran without a server database")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "no server database") {
		t.Fatalf("withStore error = %v, want a missing-database error", err)
	}
}

func TestWithStoreOpensExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	store, err := server.OpenStore(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	called := false
	if err := withStore(adminTestCommand(dir), func(*server.Store) error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("withStore: %v", err)
	}
	if !called {
		t.Fatal("withStore did not run callback")
	}
}

func TestParseQuotaRejectsNonFiniteAndOverflow(t *testing.T) {
	for _, input := range []string{"NaN", "Inf", "+Inf", "-Inf", "1e30", "1e30TB", "9223372036854775808"} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseQuota(input); err == nil {
				t.Fatalf("parseQuota(%q) succeeded, want error", input)
			}
		})
	}
}

func TestParseQuotaScalesFractionalValues(t *testing.T) {
	got, err := parseQuota("1.5GB")
	if err != nil {
		t.Fatalf("parseQuota: %v", err)
	}
	want := int64(3 << 29)
	if got == nil || *got != want {
		t.Fatalf("parseQuota = %v, want %d", got, want)
	}
}

func adminTestCommand(dir string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("data-dir", dir, "")
	return cmd
}
