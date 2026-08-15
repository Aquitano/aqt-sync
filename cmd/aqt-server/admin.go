// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/server"
)

// runAdmin executes the `aqt-server admin` subtree against the data directory and
// reports the process exit code.
//
// Admin verbs act on the store directly rather than through an HTTP surface. The
// operator already has filesystem access to the data dir — that is the trust
// boundary — so an authenticated admin API would add a remotely reachable
// privileged surface without adding any capability. SQLite's WAL mode lets these
// commands run against a live server; the two policy changes that a running server
// caches (suspension, quota) are read per request or invalidated on write, so they
// take effect without a restart.
// runAdmin takes the full argument list after the program name, `admin` included,
// so every rendered usage line reads `aqt-server admin ...` and is copy-pasteable.
func runAdmin(args []string) int {
	cmd := adminRootCmd()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// adminRootCmd mirrors the real command path: a nominal `aqt-server` root whose
// only child is `admin`. Running the server itself is not a cobra command (it is
// configured entirely by environment), so this tree exists only to give the admin
// verbs correct names in help and usage output.
func adminRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:               "aqt-server",
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	admin := &cobra.Command{
		Use:   "admin",
		Short: "Operator commands against the server data directory",
		Long: "Operator commands against the server data directory.\n\n" +
			"These act on the store directly, so they need read/write access to AQT_DATA_DIR\n" +
			"(or --data-dir). They are safe to run against a live server.",
	}
	admin.PersistentFlags().String("data-dir", "", "server data directory (default $AQT_DATA_DIR, else ./aqt-data)")
	admin.AddCommand(adminAccountsCmd())
	root.AddCommand(admin)
	return root
}

func adminAccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "accounts",
		Short:   "Inspect and manage accounts",
		Aliases: []string{"account"},
	}
	cmd.AddCommand(
		adminAccountsListCmd(),
		adminAccountsShowCmd(),
		adminAccountsQuotaCmd(),
		adminAccountsDisableCmd(),
		adminAccountsEnableCmd(),
		adminAccountsDeleteCmd(),
	)
	return cmd
}

// --- verbs ---

func adminAccountsListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every account with its storage usage and policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withStore(cmd, func(store *server.Store) error {
				accounts, err := store.ListAdminAccounts()
				if err != nil {
					return err
				}
				if asJSON {
					return writeJSON(cmd.OutOrStdout(), adminAccountsJSON(accounts, serverQuotaDefault()))
				}
				return printAccountTable(cmd.OutOrStdout(), accounts, serverQuotaDefault())
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func adminAccountsShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show <email|handle>",
		Short: "Show one account in detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAccount(cmd, args[0], func(store *server.Store, a server.AdminAccount) error {
				if asJSON {
					return writeJSON(cmd.OutOrStdout(), adminAccountJSON(a, serverQuotaDefault()))
				}
				return printAccountDetail(cmd.OutOrStdout(), a, serverQuotaDefault())
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func adminAccountsQuotaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "quota <email|handle> <bytes|unlimited|default>",
		Short: "Set, lift, or clear one account's storage quota",
		Long: "Set one account's storage quota.\n\n" +
			"  <bytes>     a byte count, optionally suffixed: 500MB, 20GB, 1TB\n" +
			"  unlimited   exempt this account from any cap\n" +
			"  default     clear the override; the account follows AQT_QUOTA_BYTES again\n\n" +
			"`unlimited` and `default` differ on a server that caps everyone: `unlimited`\n" +
			"keeps this account exempt when AQT_QUOTA_BYTES changes, `default` does not.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			quota, err := parseQuota(args[1])
			if err != nil {
				return err
			}
			return withAccount(cmd, args[0], func(store *server.Store, a server.AdminAccount) error {
				if err := store.SetAccountQuota(a.OwnerHandle, quota); err != nil {
					return err
				}
				switch {
				case quota == nil:
					fmt.Fprintf(cmd.OutOrStdout(), "%s now follows the server default (%s)\n",
						a.Email, formatQuota(serverQuotaDefault()))
				case *quota == 0:
					fmt.Fprintf(cmd.OutOrStdout(), "%s is now exempt from any storage quota\n", a.Email)
				default:
					fmt.Fprintf(cmd.OutOrStdout(), "%s quota set to %s (currently using %s)\n",
						a.Email, formatBytes(*quota), formatBytes(a.Usage.StorageBytes))
				}
				if quota != nil && *quota > 0 && a.Usage.StorageBytes > *quota {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"warning: %s is already over the new quota; existing data is untouched, but the next write is refused\n",
						a.Email)
				}
				return nil
			})
		},
	}
}

func adminAccountsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <email|handle>",
		Short: "Suspend an account's API access",
		Long: "Suspend an account. Its devices receive 403 on every authenticated route.\n\n" +
			"Nothing is deleted and no key is destroyed, so `enable` fully restores access.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAccount(cmd, args[0], func(store *server.Store, a server.AdminAccount) error {
				if a.Disabled() {
					fmt.Fprintf(cmd.OutOrStdout(), "%s was already disabled (since %s)\n",
						a.Email, a.DisabledAt.Format(time.RFC3339))
					return nil
				}
				if err := store.SetAccountDisabled(a.OwnerHandle, true); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s disabled; its %d device(s) are refused within %s\n",
					a.Email, a.Usage.Devices, server.SuspensionLag())
				return nil
			})
		},
	}
}

func adminAccountsEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <email|handle>",
		Short: "Restore a suspended account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAccount(cmd, args[0], func(store *server.Store, a server.AdminAccount) error {
				if !a.Disabled() {
					fmt.Fprintf(cmd.OutOrStdout(), "%s was already active\n", a.Email)
					return nil
				}
				if err := store.SetAccountDisabled(a.OwnerHandle, false); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s enabled; its existing device tokens work again\n", a.Email)
				return nil
			})
		},
	}
}

func adminAccountsDeleteCmd() *cobra.Command {
	var (
		assumeYes bool
		dryRun    bool
	)
	cmd := &cobra.Command{
		Use:     "delete <email|handle>",
		Aliases: []string{"rm"},
		Short:   "Erase an account and everything it stores",
		Long: "Erase an account: its devices, resources, snapshots, grants, objects, packs,\n" +
			"and the ciphertext files behind them.\n\n" +
			"This is irreversible and the server holds no keys, so nothing about the\n" +
			"account can be reconstructed afterwards. Take a data-dir backup first if the\n" +
			"deletion might need undoing.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAccount(cmd, args[0], func(store *server.Store, a server.AdminAccount) error {
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "%s (%s)\n", a.Email, a.OwnerHandle)
				fmt.Fprintf(out, "  %s across %d resource(s), %d snapshot(s), %d pack(s), %d object(s), %d device(s)\n",
					formatBytes(a.Usage.StorageBytes), a.Usage.Resources, a.Usage.Snapshots,
					a.Usage.Packs, a.Usage.Objects, a.Usage.Devices)
				if dryRun {
					fmt.Fprintln(out, "dry run: nothing was deleted")
					return nil
				}
				if err := confirm(cmd, fmt.Sprintf("Permanently erase %s and all of the above?", a.Email), assumeYes); err != nil {
					return err
				}
				deleted, err := store.DeleteAccount(a.OwnerHandle)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "deleted %s: freed %s\n", deleted.Email, formatBytes(deleted.Bytes))
				for _, fe := range deleted.FileErrors {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: orphaned file, remove by hand: %s\n", fe)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be erased and stop")
	return cmd
}

// --- plumbing ---

// withStore opens the data dir, runs fn, and closes it. Opening applies pending
// migrations, exactly as the server does, so an admin command run before the first
// server start of a new release still sees the current schema.
func withStore(cmd *cobra.Command, fn func(*server.Store) error) error {
	dir, err := cmd.Flags().GetString("data-dir")
	if err != nil {
		return err
	}
	if dir == "" {
		dir = envOr("AQT_DATA_DIR", "./aqt-data")
	}
	dbPath := filepath.Join(dir, "aqt.db")
	info, err := os.Stat(dbPath)
	if errors.Is(err, os.ErrNotExist) || err == nil && info.IsDir() {
		return fmt.Errorf("no server database in %s; set --data-dir or AQT_DATA_DIR to the server data directory", dir)
	}
	if err != nil {
		return fmt.Errorf("inspect server database %s: %w", dbPath, err)
	}
	store, err := server.OpenStore(dir)
	if err != nil {
		return fmt.Errorf("open data dir %s: %w", dir, err)
	}
	defer store.Close()
	return fn(store)
}

// withAccount resolves the reference before running fn, so every verb reports a
// missing or ambiguous account the same way.
func withAccount(cmd *cobra.Command, ref string, fn func(*server.Store, server.AdminAccount) error) error {
	return withStore(cmd, func(store *server.Store) error {
		a, err := store.AdminAccountByRef(ref)
		if errors.Is(err, server.ErrNotFound) {
			return fmt.Errorf("no account matches %q", ref)
		}
		if errors.Is(err, server.ErrAmbiguousAccount) {
			return fmt.Errorf("%q matches more than one account; use the full email or handle", ref)
		}
		if err != nil {
			return err
		}
		return fn(store, a)
	})
}

// serverQuotaDefault reads the server-wide cap from the environment, so operator
// output can distinguish "inherits the default" from the default's current value.
func serverQuotaDefault() int64 {
	n, err := strconv.ParseInt(envOr("AQT_QUOTA_BYTES", "0"), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// confirm gates a destructive verb. Without --yes it requires a terminal: a piped
// or scripted invocation must pass --yes explicitly rather than have a prompt
// silently read EOF and be taken as consent.
func confirm(cmd *cobra.Command, prompt string, assumeYes bool) error {
	if assumeYes {
		return nil
	}
	in, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(in.Fd())) {
		return errors.New("refusing to prompt without a terminal; pass --yes to confirm")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s [y/N] ", prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return errors.New("aborted")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	default:
		return errors.New("aborted")
	}
}

// --- rendering ---

func printAccountTable(w io.Writer, accounts []server.AdminAccount, serverDefault int64) error {
	if len(accounts) == 0 {
		fmt.Fprintln(w, "no accounts")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tHANDLE\tSTORED\tQUOTA\tRES\tSNAP\tDEV\tSTATUS")
	for _, a := range accounts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n",
			a.Email, a.OwnerHandle, formatBytes(a.Usage.StorageBytes),
			quotaColumn(a, serverDefault),
			a.Usage.Resources, a.Usage.Snapshots, a.Usage.Devices, accountStatus(a))
	}
	return tw.Flush()
}

func printAccountDetail(w io.Writer, a server.AdminAccount, serverDefault int64) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	rows := [][2]string{
		{"email", a.Email},
		{"handle", a.OwnerHandle},
		{"created", formatTime(a.CreatedAt)},
		{"status", accountStatus(a)},
		{"stored", formatBytes(a.Usage.StorageBytes)},
		{"quota", quotaColumn(a, serverDefault)},
		{"resources", strconv.FormatInt(a.Usage.Resources, 10)},
		{"snapshots", strconv.FormatInt(a.Usage.Snapshots, 10)},
		{"packs", strconv.FormatInt(a.Usage.Packs, 10)},
		{"objects", strconv.FormatInt(a.Usage.Objects, 10)},
		{"devices", strconv.FormatInt(a.Usage.Devices, 10)},
	}
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r[0], r[1])
	}
	return tw.Flush()
}

func accountStatus(a server.AdminAccount) string {
	if a.Disabled() {
		return "disabled " + a.DisabledAt.Format("2006-01-02")
	}
	return "active"
}

// quotaColumn distinguishes the three states an operator needs to tell apart: an
// explicit per-account cap, an explicit exemption, and inheritance of the server
// default (whose current value is shown, since that is what actually applies).
func quotaColumn(a server.AdminAccount, serverDefault int64) string {
	if !a.QuotaBytes.Valid {
		return "default (" + formatQuota(serverDefault) + ")"
	}
	return formatQuota(a.QuotaBytes.Int64)
}

func formatQuota(n int64) string {
	if n == 0 {
		return "unlimited"
	}
	return formatBytes(n)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format(time.RFC3339)
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// parseQuota reads the quota argument. A nil result means "clear the override";
// a pointer to 0 means "explicitly unlimited". Suffixes are accepted because an
// operator setting 20GB should not have to count zeroes.
func parseQuota(raw string) (*int64, error) {
	s := strings.TrimSpace(raw)
	switch strings.ToLower(s) {
	case "default", "inherit", "":
		return nil, nil
	case "unlimited", "none", "0":
		var zero int64
		return &zero, nil
	}

	mult := int64(1)
	lower := strings.ToLower(s)
	for _, suffix := range []struct {
		name string
		mult int64
	}{
		{"tb", 1 << 40}, {"tib", 1 << 40},
		{"gb", 1 << 30}, {"gib", 1 << 30},
		{"mb", 1 << 20}, {"mib", 1 << 20},
		{"kb", 1 << 10}, {"kib", 1 << 10},
		{"b", 1},
	} {
		if strings.HasSuffix(lower, suffix.name) {
			mult = suffix.mult
			s = strings.TrimSpace(s[:len(s)-len(suffix.name)])
			break
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	scaled := n * float64(mult)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 ||
		math.IsInf(scaled, 0) || scaled >= math.Exp2(63) {
		return nil, fmt.Errorf("invalid quota %q: want a byte count (optionally suffixed MB/GB/TB), `unlimited`, or `default`", raw)
	}
	bytes := int64(scaled)
	return &bytes, nil
}

// --- JSON ---

type adminAccountOut struct {
	Email string `json:"email"`
	// Handle is the opaque owner id the server uses internally; it is what metrics
	// and log lines carry, so operator output names it for correlation.
	Handle       string `json:"handle"`
	CreatedAt    string `json:"createdAt,omitempty"`
	Disabled     bool   `json:"disabled"`
	DisabledAt   string `json:"disabledAt,omitempty"`
	StorageBytes int64  `json:"storageBytes"`
	// QuotaBytes is the cap that actually applies; 0 is unlimited.
	QuotaBytes int64 `json:"quotaBytes"`
	// QuotaSource is "account" when an override is set, "server" when the account
	// inherits AQT_QUOTA_BYTES.
	QuotaSource string `json:"quotaSource"`
	Resources   int64  `json:"resources"`
	Snapshots   int64  `json:"snapshots"`
	Packs       int64  `json:"packs"`
	Objects     int64  `json:"objects"`
	Devices     int64  `json:"devices"`
}

func adminAccountJSON(a server.AdminAccount, serverDefault int64) adminAccountOut {
	out := adminAccountOut{
		Email:        a.Email,
		Handle:       a.OwnerHandle,
		Disabled:     a.Disabled(),
		StorageBytes: a.Usage.StorageBytes,
		QuotaBytes:   a.EffectiveQuota(serverDefault),
		QuotaSource:  "server",
		Resources:    a.Usage.Resources,
		Snapshots:    a.Usage.Snapshots,
		Packs:        a.Usage.Packs,
		Objects:      a.Usage.Objects,
		Devices:      a.Usage.Devices,
	}
	if a.QuotaBytes.Valid {
		out.QuotaSource = "account"
	}
	if !a.CreatedAt.IsZero() {
		out.CreatedAt = a.CreatedAt.Format(time.RFC3339)
	}
	if a.Disabled() {
		out.DisabledAt = a.DisabledAt.Format(time.RFC3339)
	}
	return out
}

func adminAccountsJSON(accounts []server.AdminAccount, serverDefault int64) []adminAccountOut {
	out := make([]adminAccountOut, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, adminAccountJSON(a, serverDefault))
	}
	return out
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
