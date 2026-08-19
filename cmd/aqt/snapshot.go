// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/fsatomic"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func snapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create, browse, and restore point-in-time snapshots",
		Long: "Snapshots are immutable, point-in-time copies of a tracked folder or file, " +
			"pinned server-side so a later sync (or a mistaken delete) cannot reclaim them. " +
			"They are account-global: any of your devices can browse and restore them.",
	}
	cmd.AddCommand(snapshotCreateCmd(), snapshotListCmd(), snapshotFindCmd(), snapshotDiffCmd(), snapshotExportCmd(), snapshotPruneCmd(), snapshotAnchorCmd(), snapshotUnanchorCmd(), snapshotAutoCmd())
	return cmd
}

// --- anchor ---

func snapshotAnchorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "anchor <snapshot-id>",
		Short: "Protect a snapshot from retention",
		Long: "An anchored snapshot is exempt from every retention path — the scheduled job's\n" +
			"prune, `snapshot prune --keep-last/--before`, and an explicit prune, which is\n" +
			"refused until the snapshot is unanchored. `aqt checkpoint` anchors as it creates.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, _, err := authedClient()
			if err != nil {
				return err
			}
			return setSnapshotAnchor(cl, args[0], true)
		},
	}
	markJSONSupported(cmd)
	return cmd
}

func snapshotUnanchorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unanchor <snapshot-id>",
		Short: "Make an anchored snapshot eligible for retention again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, _, err := authedClient()
			if err != nil {
				return err
			}
			return setSnapshotAnchor(cl, args[0], false)
		},
	}
	markJSONSupported(cmd)
	return cmd
}

// setSnapshotAnchor toggles a snapshot's anchor and fails closed unless the server
// echoes the state that was asked for. A server that ignored the anchor field echoes
// the old state, so a mismatch is treated as a hard error rather than a silently
// unprotected (or still-protected) snapshot.
func setSnapshotAnchor(cl *client.Client, id string, want bool) error {
	info, err := cl.SetSnapshotAnchor(id, want)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("snapshot %s not found (or not yours)", id)
	}
	if err != nil {
		return err
	}
	if info.Anchored != want {
		return fmt.Errorf("server did not apply the anchor change to %s; this is a server bug, report it", id)
	}
	if flagJSON {
		return printJSON(map[string]any{"id": info.ID, "anchored": info.Anchored})
	}
	if want {
		fmt.Printf("anchored %s (protected from retention)\n", id)
	} else {
		fmt.Printf("unanchored %s (prunable again)\n", id)
	}
	return nil
}

// --- create ---

func snapshotCreateCmd() *cobra.Command {
	var (
		id    string
		label string
	)
	cmd := &cobra.Command{
		Use:   "create [dir] [label]",
		Short: "Snapshot a tracked folder's (or a resource's) current state",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 2 {
				if cmd.Flags().Changed("label") {
					return errors.New("specify the snapshot label either positionally or with --label, not both")
				}
				label = args[1]
			}
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}
			if id == "" {
				if err := bindTrackedDir(dir); err != nil {
					return err
				}
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			resourceID, err := resolveResourceID(dir, id)
			if err != nil {
				return err
			}
			// A label is sealed under the resource content key here, so the server stores
			// only ciphertext; this needs the key, so it is the one path that unlocks.
			var sealed *crypto.SealedBlob
			if label != "" {
				if sealed, err = sealSnapshotLabel(cl, prof, resourceID, label); err != nil {
					return err
				}
			}
			info, err := cl.CreateSnapshot(resourceID, sealed, false)
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours)", resourceID)
			}
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(info)
			}
			if flagQuiet {
				fmt.Println(info.ID)
				return nil
			}
			fmt.Printf("snapshot %s of %s (version %d)\n", info.ID, resourceID, info.Version)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "snapshot this resource id directly (e.g. a pushed file) instead of a tracked dir")
	cmd.Flags().StringVarP(&label, "label", "l", "", "attach a label, encrypted on this machine before upload")
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	return cmd
}

// sealSnapshotLabel encrypts a snapshot label under the resource's content key, so
// the server stores it as opaque ciphertext that a later browse decrypts the same
// way it decrypts the name. It fetches the resource to recover its wrapped key, then
// unwraps it with the master key.
func sealSnapshotLabel(cl *client.Client, prof *identity.Profile, resourceID, label string) (*crypto.SealedBlob, error) {
	res, err := cl.GetResource(resourceID)
	if errors.Is(err, client.ErrNotFound) {
		return nil, fmt.Errorf("resource %s not found (or not yours)", resourceID)
	}
	if err != nil {
		return nil, err
	}
	if res.WrappedKey == nil {
		return nil, errors.New("cannot label this snapshot: the resource is public (no owner key to seal under)")
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return nil, err
	}
	defer mk.Wipe()
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return nil, fmt.Errorf("unwrap resource key: %w", err)
	}
	defer ck.Wipe()
	sealed, err := crypto.SealBound([]byte(label), ck, crypto.AADSnapshotLabel, resourceID)
	if err != nil {
		return nil, err
	}
	return &sealed, nil
}

// --- list ---

func snapshotListCmd() *cobra.Command {
	var (
		id     string
		limit  int
		since  time.Duration
		before time.Duration
	)
	cmd := &cobra.Command{
		Use:     "list [dir]",
		Aliases: []string{"ls"},
		Short:   "List snapshots, newest first, with decrypted names",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" && len(args) > 0 {
				if err := bindTrackedDir(args[0]); err != nil {
					return err
				}
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			// A bare `snapshot list` lists every snapshot; a dir or --id scopes it to one
			// resource's history.
			resourceID := id
			if resourceID == "" && len(args) > 0 {
				if resourceID, err = resolveResourceID(args[0], ""); err != nil {
					return err
				}
			}
			snaps, err := cl.ListSnapshots(resourceID)
			if err != nil {
				return err
			}
			snaps = filterSnapshots(snaps, limit, since, before, time.Now())
			mk, err := unlockMaster(prof)
			if err != nil {
				return err
			}
			defer mk.Wipe()
			if flagJSON {
				return printJSON(snapshotRows(snaps, mk))
			}
			if len(snaps) == 0 {
				if limit > 0 || since > 0 || before > 0 {
					fmt.Fprintln(os.Stderr, "no snapshots match these filters")
				} else {
					fmt.Fprintln(os.Stderr, "no snapshots yet")
				}
				return nil
			}
			return printSnapshotTable(snapshotRows(snaps, mk))
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "list snapshots of this resource id")
	cmd.Flags().IntVar(&limit, "limit", 0, "show at most N snapshots (0 = all)")
	cmd.Flags().DurationVar(&since, "since", 0, "only snapshots created within this window (e.g. 168h)")
	cmd.Flags().DurationVar(&before, "before", 0, "only snapshots older than this (e.g. 720h)")
	markJSONSupported(cmd)
	return cmd
}

// filterSnapshots applies the list view filters to a newest-first snapshot list,
// preserving order. since keeps snapshots created within that window; before keeps
// those older than it; limit caps the count. A zero duration or limit disables that
// bound.
func filterSnapshots(snaps []api.SnapshotInfo, limit int, since, before time.Duration, now time.Time) []api.SnapshotInfo {
	out := make([]api.SnapshotInfo, 0, len(snaps))
	for _, s := range snaps {
		age := now.Sub(time.Unix(s.CreatedAt, 0))
		if since > 0 && age > since {
			continue
		}
		if before > 0 && age < before {
			continue
		}
		out = append(out, s)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func printSnapshotTable(rows []snapshotRow) error {
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		cells = append(cells, []string{
			r.Created, r.Name, r.Label, anchorMark(r.Anchored),
			strconv.Itoa(r.Version), r.ID, r.ResourceID,
		})
	}
	return printTable(os.Stdout, []string{"CREATED", "NAME", "LABEL", "ANCHOR", "VERSION", "SNAPSHOT-ID", "RESOURCE"}, cells)
}

// anchorMark renders the anchor column: a `*` for a protected snapshot, blank
// otherwise, so an anchored checkpoint stands out at a glance.
func anchorMark(anchored bool) string {
	if anchored {
		return "*"
	}
	return ""
}

// snapshotRow is one snapshot as shown by `aqt snapshot list`, with its name
// decrypted locally from the copied sealed metadata.
type snapshotRow struct {
	ID         string `json:"id"`
	ResourceID string `json:"resourceId"`
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Anchored   bool   `json:"anchored,omitempty"`
	Version    int    `json:"version"`
	Created    string `json:"created"`
	CreatedAt  int64  `json:"createdAt"`
}

// displayName prefers the user's checkpoint label over the resource name — the
// label is what distinguishes one snapshot of a folder from another.
func (r snapshotRow) displayName() string {
	if r.Label != "" {
		return r.Label
	}
	return r.Name
}

func snapshotRows(snaps []api.SnapshotInfo, mk crypto.MasterKey) []snapshotRow {
	rows := make([]snapshotRow, 0, len(snaps))
	for _, s := range snaps {
		name, label := snapshotNameLabel(s, mk)
		rows = append(rows, snapshotRow{
			ID: s.ID, ResourceID: s.ResourceID, Name: name, Label: label, Anchored: s.Anchored, Version: s.Version,
			Created: cliutil.FormatUnix(s.CreatedAt), CreatedAt: s.CreatedAt,
		})
	}
	return rows
}

// snapshotNameLabel decrypts the resource name and the optional user label a
// snapshot carries, unwrapping the content key once for both (the same key both
// were sealed under). A snapshot that cannot be decrypted is still listed, with a
// placeholder name and no label.
func snapshotNameLabel(s api.SnapshotInfo, mk crypto.MasterKey) (name, label string) {
	name = "(unreadable)"
	if s.WrappedKey == nil {
		return name, ""
	}
	ck, err := crypto.UnwrapKey(*s.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return name, ""
	}
	defer ck.Wipe()
	if plain, err := crypto.OpenBound(s.EncryptedMeta, ck, crypto.AADMeta, s.ResourceID); err == nil {
		var m api.Metadata
		if json.Unmarshal(plain, &m) == nil {
			if name = m.Name; name == "" {
				name = "(unnamed)"
			}
		}
	}
	if s.EncryptedLabel != nil {
		if plain, err := crypto.OpenBound(*s.EncryptedLabel, ck, crypto.AADSnapshotLabel, s.ResourceID); err == nil {
			label = string(plain)
		}
	}
	return name, label
}

// --- find (fzf search) ---

func snapshotFindCmd() *cobra.Command {
	var (
		id    string
		noFzf bool
	)
	cmd := &cobra.Command{
		Use:   "find [query]",
		Short: "Fuzzy-search your snapshots (via fzf) and print the selected id",
		Long: "Open your snapshots in fzf and print the selected snapshot id, so it composes:\n" +
			"`aqt restore \"$(aqt snapshot find)\"`.\n\n" +
			"Without a terminal or fzf, the index is printed as a table instead.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotFind(strings.Join(args, " "), id, flagJSON, noFzf)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "scope to this resource id instead of all snapshots")
	cmd.Flags().BoolVar(&noFzf, "no-fzf", false, "print the index as a table instead of opening fzf")
	markJSONSupported(cmd)
	return cmd
}

func runSnapshotFind(query, resourceID string, asJSON, noFzf bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	snaps, err := cl.ListSnapshots(resourceID)
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	rows := snapshotRows(snaps, mk)
	// --json emits the index (even an empty []) before the human "nothing here" path,
	// so a script always gets valid JSON.
	if asJSON {
		return printJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no snapshots yet")
		return nil
	}
	fzfPath, _ := exec.LookPath("fzf")
	interactive := term.IsTerminal(int(os.Stdout.Fd()))
	if noFzf || fzfPath == "" || !interactive {
		if fzfPath == "" && interactive && !noFzf {
			fmt.Fprintln(os.Stderr, "fzf not found; printing the index (install fzf for interactive search)")
		}
		return printSnapshotTable(rows)
	}
	return snapshotFzfSelect(fzfPath, query, rows)
}

// snapshotFzfSelect feeds the snapshot index to fzf and prints the chosen snapshot
// id. The id is the last, hidden column (--with-nth shows the rest) so it survives
// the round trip without cluttering the view. Cancelling fzf exits quietly. This
// mirrors find.go's fzfSelect; it is kept self-contained rather than refactoring the
// sibling command for one shared exec.
func snapshotFzfSelect(fzfPath, query string, rows []snapshotRow) error {
	var input strings.Builder
	for _, r := range rows {
		label := r.Label
		if label == "" {
			label = "-"
		}
		anchor := "-"
		if r.Anchored {
			anchor = "anchor"
		}
		fmt.Fprintf(&input, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", r.Created, r.Name, label, anchor, r.Version, r.ResourceID, r.ID)
	}
	args := []string{
		"--delimiter", "\t",
		"--with-nth", "1,2,3,4,5,6",
		"--header", "Enter prints the snapshot id · Esc cancels",
	}
	if query != "" {
		args = append(args, "--query", query)
	}
	cmd := exec.Command(fzfPath, args...)
	cmd.Stdin = strings.NewReader(input.String())
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		// fzf exits 130 when interrupted (Esc/Ctrl-C) and 1 when nothing matched; both
		// mean "no selection", not a failure.
		if errors.As(err, &ee) && (ee.ExitCode() == 130 || ee.ExitCode() == 1) {
			return nil
		}
		return fmt.Errorf("fzf: %w", err)
	}
	line := strings.TrimRight(out.String(), "\n")
	if line == "" {
		return nil
	}
	fields := strings.Split(line, "\t")
	fmt.Println(fields[len(fields)-1])
	return nil
}

// --- restore (in place; the `restore` command owns the surface) ---

// restoreInPlace rolls a tracked folder back to a snapshot and pushes the result to
// every device. It reconstructs the snapshot into a staging dir first, so a failed
// reconstruction never leaves the live folder half-overwritten, then swaps it in and
// runs a normal sync (force: an explicit rollback wins any divergence).
func restoreInPlace(cl *client.Client, prof *identity.Profile, snap api.GetSnapshotResponse, dir string, assumeYes bool) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	st, err := loadState(root)
	if err != nil {
		return fmt.Errorf("read folder state: %w", err)
	}
	if st.ID != snap.Snapshot.ResourceID {
		return fmt.Errorf("snapshot belongs to resource %s, but %s tracks %s; "+
			"restore it side-by-side with --out instead", snap.Snapshot.ResourceID, root, st.ID)
	}
	if err := confirmDestructive(fmt.Sprintf("Roll %s back to snapshot %s and push to every device? "+
		"Current contents are replaced. [y/N] ", root, snap.Snapshot.ID), assumeYes); err != nil {
		return err
	}

	staging, err := os.MkdirTemp(filepath.Dir(root), ".aqt-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	meta, err := reconstructSnapshot(cl, prof, snap, staging, false)
	if err != nil {
		return err
	}
	if meta.Kind != api.KindFolder {
		return errors.New("in-place restore is only for tracked folders; use --out for a single file")
	}
	// The swap and the sync that publishes it are one operation and must hold the
	// sync lock together. A watcher firing on the swap's deletions would otherwise
	// take the lock first and push a manifest of the half-emptied root — committing
	// the deletions to the server and to every other device. The lock is re-entrant,
	// so the runSync below acquires it again underneath this one.
	release, err := acquireSyncLock(root)
	if err != nil {
		return err
	}
	defer release()
	// The marker turns a kill mid-swap from silent data loss into a refusal: a
	// half-emptied root scans as mass deletion, and the next sync (or watch tick)
	// would push those deletions fleet-wide. It covers only the swap — once the
	// tree is whole again the marker comes off, before the propagation sync.
	if err := writeMarker(root, restoreMarkerFile, interruptedRestore{SnapshotID: snap.Snapshot.ID}); err != nil {
		return err
	}
	if err := swapTree(root, staging); err != nil {
		return fmt.Errorf("swap restored tree into place: %w", err)
	}
	// The swap replaced the whole tree, so a tree an earlier interrupted pull had torn
	// is whole again — and it is the snapshot's, not the remote's. Leaving the marker
	// would send the sync below pulling the remote back over the restore.
	if err := clearMarker(root, pullMarkerFile); err != nil {
		return err
	}
	if err := clearMarker(root, restoreMarkerFile); err != nil {
		return err
	}
	if !flagJSON && !flagQuiet {
		fmt.Fprintln(os.Stderr, "rolled back; syncing to propagate...")
	}
	// conflicts is pinned to block: the restored tree's own .aqtconfig may select
	// copy or merge, which contradict --force — a wedge the user never caused, hit
	// only after the tree was already swapped.
	return runSync(root, syncOptions{force: true, conflicts: "block"})
}

// swapTree replaces root's contents (everything but the .aqt control dir) with
// staging's. It moves the live entries aside into a sibling backup dir first, then
// moves the staged entries in, so a rename that fails partway can be rolled back to
// the original tree rather than left half-replaced. Backup, staging, and root share
// a parent, so every rename stays on one filesystem (and is atomic).
func swapTree(root, staging string) error {
	backup, err := os.MkdirTemp(filepath.Dir(root), ".aqt-backup-*")
	if err != nil {
		return err
	}

	// On any failure, undo the moves in reverse: staged entries back to staging, live
	// entries back to root. A clean rollback drops the backup dir; an incomplete one
	// keeps it (it still holds the original contents) so a partial swap never loses
	// data, and reports where it is.
	var movedOut, movedIn []string
	fail := func(cause error) error {
		ok := true
		for i := len(movedIn) - 1; i >= 0; i-- {
			if e := os.Rename(filepath.Join(root, movedIn[i]), filepath.Join(staging, movedIn[i])); e != nil {
				ok = false
			}
		}
		for i := len(movedOut) - 1; i >= 0; i-- {
			if e := os.Rename(filepath.Join(backup, movedOut[i]), filepath.Join(root, movedOut[i])); e != nil {
				ok = false
			}
		}
		if !ok {
			return fmt.Errorf("%w (rolled back partially; original contents preserved in %s)", cause, backup)
		}
		os.RemoveAll(backup)
		return cause
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return fail(err)
	}
	for _, e := range entries {
		if e.Name() == syncengine.ControlDir {
			continue
		}
		if err := os.Rename(filepath.Join(root, e.Name()), filepath.Join(backup, e.Name())); err != nil {
			return fail(err)
		}
		movedOut = append(movedOut, e.Name())
	}

	staged, err := os.ReadDir(staging)
	if err != nil {
		return fail(err)
	}
	for _, e := range staged {
		if err := os.Rename(filepath.Join(staging, e.Name()), filepath.Join(root, e.Name())); err != nil {
			return fail(err)
		}
		movedIn = append(movedIn, e.Name())
	}

	return os.RemoveAll(backup)
}

// --- export ---

func snapshotExportCmd() *cobra.Command {
	var (
		out   string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "export <snapshot-id>",
		Short: "Decrypt a snapshot to a plaintext tree for offsite backup",
		Long: "Reconstructs a snapshot and writes it as plaintext to --out. Decryption happens " +
			"entirely on this machine; the server never sees a key. The output is NOT encrypted, " +
			"so it leaves aqt's zero-knowledge boundary: store it somewhere you trust.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return errors.New("--out <dir> is required")
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			snap, err := cl.GetSnapshot(args[0])
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("snapshot %s not found (or not yours)", args[0])
			}
			if err != nil {
				return err
			}
			abs, err := filepath.Abs(out)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "warning: writing DECRYPTED plaintext to %s (outside aqt's encryption)\n", abs)
			meta, err := reconstructSnapshot(cl, prof, snap, abs, force)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(map[string]any{
					"snapshotId": snap.Snapshot.ID, "name": meta.Name,
					"version": snap.Snapshot.Version, "to": abs,
				})
			}
			fmt.Printf("exported %q (version %d) to %s\n", meta.Name, snap.Snapshot.Version, abs)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "write the decrypted plaintext tree here (required)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file at the destination")
	markJSONSupported(cmd)
	return cmd
}

// --- diff ---

func snapshotDiffCmd() *cobra.Command {
	var against string
	cmd := &cobra.Command{
		Use:   "diff <snapshot-id>",
		Short: "Show what changed between a snapshot and the live tree (or another snapshot)",
		Long: "Compares both sides by file path and content. Chunked folders are diffed by " +
			"their content-addressed metadata alone — no file content is downloaded and " +
			"unchanged subtrees are skipped by hash; other resources are reconstructed to " +
			"temp dirs and compared on disk. By default the snapshot is compared against " +
			"the current live state of its resource; --against compares it to a second " +
			"snapshot instead. Added (+), removed (-), and modified (~) files are listed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			return runSnapshotDiff(cl, prof, args[0], against)
		},
	}
	cmd.Flags().StringVar(&against, "against", "", "compare against this second snapshot instead of the live resource")
	markJSONSupported(cmd)
	return cmd
}

func runSnapshotDiff(cl *client.Client, prof *identity.Profile, leftID, against string) error {
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	result, err := computeSnapshotDiff(cl, mk, leftID, against)
	if err != nil {
		return err
	}
	if flagJSON {
		return printJSON(result)
	}
	printSnapshotDiff(result)
	return nil
}

// computeSnapshotDiff needs the already-unlocked master key: it must never
// prompt, because the TUI calls it from inside a raw-mode terminal session.
func computeSnapshotDiff(cl *client.Client, mk crypto.MasterKey, leftID, against string) (comparison, error) {
	var zero comparison
	left, err := cl.GetSnapshot(leftID)
	if errors.Is(err, client.ErrNotFound) {
		return zero, fmt.Errorf("snapshot %s not found (or not yours)", leftID)
	}
	if err != nil {
		return zero, err
	}

	// The right side is either a second snapshot or the resource's current live state.
	var (
		rightRes   api.GetResourceResponse
		rightLabel string
		rightVer   int
	)
	if against != "" {
		r, err := cl.GetSnapshot(against)
		if errors.Is(err, client.ErrNotFound) {
			return zero, fmt.Errorf("snapshot %s not found (or not yours)", against)
		}
		if err != nil {
			return zero, err
		}
		rightRes = snapshotAsResource(r)
		rightLabel = "snapshot " + against
		rightVer = r.Snapshot.Version
	} else {
		r, err := cl.GetResource(left.Snapshot.ResourceID)
		if errors.Is(err, client.ErrNotFound) {
			return zero, fmt.Errorf("resource %s no longer exists; use --against to diff two snapshots", left.Snapshot.ResourceID)
		}
		if err != nil {
			return zero, err
		}
		rightRes = r
		rightLabel = "live"
		rightVer = r.Version
	}

	diff, err := diffResources(cl, mk, snapshotAsResource(left), rightRes, leftID, rightLabel)
	if err != nil {
		return zero, err
	}
	return newComparison(
		diffSide{Label: "snapshot " + leftID, Version: left.Snapshot.Version},
		diffSide{Label: rightLabel, Version: rightVer},
		diff,
	), nil
}

// diffResources compares two resource states. When both sides are chunked tree
// folders it diffs their Merkle DAGs by content address — identical subtrees are
// pruned by hash without a fetch, and no file-content chunk is ever downloaded —
// which turns the old "download both trees, hash them on disk" diff into a
// metadata-only walk of the changed spines. Anything else (single files,
// pack-and-seal folders, a mixed pair) still materializes both sides to temp
// dirs; that fallback scans each side back into a manifest so both routes report
// the same classification rather than the old regular-files-only comparison.
func diffResources(cl *client.Client, mk crypto.MasterKey, left, right api.GetResourceResponse, leftID, rightLabel string) (syncengine.Delta, error) {
	var zero syncengine.Delta
	leftRoot, leftOK, err := treeRootOf(left, mk)
	if err != nil {
		return zero, fmt.Errorf("reconstruct snapshot %s: %w", leftID, err)
	}
	rightRoot, rightOK, err := treeRootOf(right, mk)
	if err != nil {
		return zero, fmt.Errorf("reconstruct %s: %w", rightLabel, err)
	}
	if leftOK && rightOK {
		// One fetcher serves both sides, so a node the two versions share is
		// fetched at most once (and usually not at all, via the disk node cache).
		return syncengine.DiffTreeRoots(leftRoot, rightRoot, newBatchNodeFetcher(cl, nil))
	}

	leftDir, err := os.MkdirTemp("", "aqt-diff-old-*")
	if err != nil {
		return zero, err
	}
	defer os.RemoveAll(leftDir)
	rightDir, err := os.MkdirTemp("", "aqt-diff-new-*")
	if err != nil {
		return zero, err
	}
	defer os.RemoveAll(rightDir)
	if _, err := materializeWithMaster(cl, mk, left, leftDir); err != nil {
		return zero, fmt.Errorf("reconstruct snapshot %s: %w", leftID, err)
	}
	if _, err := materializeWithMaster(cl, mk, right, rightDir); err != nil {
		return zero, fmt.Errorf("reconstruct %s: %w", rightLabel, err)
	}
	return diffTrees(leftDir, rightDir)
}

// treeRootOf opens a resource's sealed TreeRoot when it is a chunked tree folder;
// ok=false routes every other shape (single file, pack-and-seal, legacy, or a
// public resource with no owner key) to the materialize fallback.
func treeRootOf(res api.GetResourceResponse, mk crypto.MasterKey) (syncengine.TreeRoot, bool, error) {
	if res.WrappedKey == nil {
		return syncengine.TreeRoot{}, false, nil
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return syncengine.TreeRoot{}, false, fmt.Errorf("unwrap key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck, res.ID)
	if err != nil {
		return syncengine.TreeRoot{}, false, err
	}
	if meta.Kind != api.KindFolder || !meta.Tree || meta.Packed {
		return syncengine.TreeRoot{}, false, nil
	}
	root, err := syncengine.OpenTreeRoot(res.Blob, ck, res.ID)
	if err != nil {
		return syncengine.TreeRoot{}, false, fmt.Errorf("decrypt folder root: %w", err)
	}
	return root, true, nil
}

func printSnapshotDiff(r comparison) {
	fmt.Printf("%s (v%d)  ->  %s (v%d)\n", r.Left.Label, r.Left.Version, r.Right.Label, r.Right.Version)
	total := len(r.Added) + len(r.Removed) + len(r.Modified) + len(r.Renamed)
	if total == 0 {
		fmt.Println("no differences")
		return
	}
	type line struct{ mark, path string }
	lines := make([]line, 0, total)
	for _, c := range r.Changes {
		lines = append(lines, line{diffMark(c.Kind), changePath(c)})
	}
	for _, rn := range r.Renamed {
		lines = append(lines, line{"renamed", renameArrow(rn)})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].path < lines[j].path })
	for _, l := range lines {
		fmt.Printf("%s %s\n", l.mark, l.path)
	}
	fmt.Printf("%d changed: %d added, %d removed, %d modified, %d renamed\n",
		total, len(r.Added), len(r.Removed), len(r.Modified), len(r.Renamed))
}

// renameArrow renders one rename pair; directories get the trailing slash the
// plan printer uses.
func renameArrow(r syncengine.Rename) string {
	if r.Dir {
		return r.From + "/ -> " + r.To + "/"
	}
	return r.From + " -> " + r.To
}

// diffTrees compares two materialized trees by scanning each back into a manifest
// and classifying the difference, so this fallback reports files, symlinks,
// directories, modes, and type switches exactly as the Merkle-DAG path does. Scan
// honors .aqtignore and skips the .aqt control dir, which a live tracked tree carries
// but a reconstructed snapshot does not.
func diffTrees(oldDir, newDir string) (syncengine.Delta, error) {
	old, err := syncengine.Scan(oldDir)
	if err != nil {
		return syncengine.Delta{}, err
	}
	cur, err := syncengine.Scan(newDir)
	if err != nil {
		return syncengine.Delta{}, err
	}
	return syncengine.Diff(old, cur), nil
}

// nonNil returns an empty slice for a nil one, so the diff marshals "added": []
// rather than null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// --- prune ---

func snapshotPruneCmd() *cobra.Command {
	var (
		id       string
		dir      string
		keepLast int
		before   string
		dryRun   bool
		yes      bool
	)
	cmd := &cobra.Command{
		Use:   "prune [snapshot-id...]",
		Short: "Delete snapshots by id, or by retention (--keep-last/--before)",
		Long: "Delete snapshots and let GC reclaim any objects no other snapshot or resource\n" +
			"needs. Pass explicit ids, or select by retention with --keep-last / --before.\n" +
			"A retention run spans every snapshot unless scoped to one resource with --dir or\n" +
			"--id; --keep-last is applied per resource. Use --dry-run to preview.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			byRetention := keepLast > 0 || before != ""
			if byRetention && len(args) > 0 {
				return errors.New("with --keep-last/--before, scope with --dir/--id; positional ids are not allowed")
			}
			if !byRetention && len(args) == 0 {
				return errors.New("specify snapshot ids, or use --keep-last/--before")
			}
			if id == "" && dir != "" {
				if err := bindTrackedDir(dir); err != nil {
					return err
				}
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			return runSnapshotPrune(cl, prof, args, id, dir, keepLast, before, dryRun, yes)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "scope a retention prune to this resource id")
	cmd.Flags().StringVar(&dir, "dir", "", "scope a retention prune to this tracked dir")
	cmd.Flags().IntVar(&keepLast, "keep-last", 0, "keep the N newest snapshots per resource, prune the rest (anchored snapshots are excluded from the count and never pruned)")
	cmd.Flags().StringVar(&before, "before", "", "prune snapshots older than this duration (e.g. 720h)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would be pruned without deleting")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(cmd)
	return cmd
}

type snapshotPruneClient interface {
	ListSnapshots(string) ([]api.SnapshotInfo, error)
	DeleteSnapshot(string) error
}

func runSnapshotPrune(cl snapshotPruneClient, prof *identity.Profile, explicit []string, id, dir string, keepLast int, before string, dryRun, yes bool) error {
	cutoff, err := parseSnapshotBefore(before)
	if err != nil {
		return err
	}
	resourceID := id
	if resourceID == "" && dir != "" {
		if resourceID, err = resolveResourceID(dir, ""); err != nil {
			return err
		}
	}
	snaps, err := cl.ListSnapshots(resourceID)
	if err != nil {
		return err
	}

	targets := uniqueBatchIDs(explicit)
	if keepLast > 0 || before != "" {
		targets = selectSnapshotsToPrune(snaps, keepLast, cutoff, time.Now())
	}
	if len(targets) == 0 {
		if !flagJSON {
			fmt.Fprintln(os.Stderr, "nothing to prune")
		}
		return finishDestructiveBatch(destructiveBatchReport{Complete: true, DryRun: dryRun, Results: []destructiveBatchResult{}}, "pruned", nil)
	}

	results := newBatchResults(targets)
	known := make(map[string]api.SnapshotInfo, len(snaps))
	for _, snapshot := range snaps {
		known[snapshot.ID] = snapshot
	}
	failures := map[int]error{}
	for i, target := range targets {
		snapshot, ok := known[target]
		switch {
		case !ok:
			failures[i] = fmt.Errorf("snapshot %s not found (or not yours)", target)
		case snapshot.Anchored:
			failures[i] = fmt.Errorf("snapshot %s is anchored; unanchor it before pruning", target)
		}
	}
	if len(failures) > 0 {
		err = failBatchPreflight(results, failures)
		return finishDestructiveBatch(destructiveBatchReport{Results: results}, "prune", err)
	}

	if dryRun {
		if flagJSON {
			return finishDestructiveBatch(destructiveBatchReport{Complete: true, DryRun: true, Results: results}, "prune", nil)
		}
		return reportPruneTargets(snaps, targets, prof)
	}
	if err := confirmDestructive(fmt.Sprintf("Permanently delete %d snapshot(s)? [y/N] ", len(targets)), yes); err != nil {
		return err
	}
	for i, target := range targets {
		deleteErr := cl.DeleteSnapshot(target)
		if deleteErr != nil {
			if errors.Is(deleteErr, client.ErrNotFound) {
				deleteErr = fmt.Errorf("snapshot %s not found (or not yours)", target)
			}
			err = markBatchFailure(results, i, deleteErr)
			return finishDestructiveBatch(destructiveBatchReport{Results: results}, "prune", err)
		}
		results[i].Status = batchSucceeded
	}
	return finishDestructiveBatch(destructiveBatchReport{Complete: true, Results: results}, "pruned", nil)
}

func parseSnapshotBefore(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --before: %w", err)
	}
	return d, nil
}

// selectSnapshotsToPrune chooses which snapshots a retention policy deletes. snaps
// must be newest-first (as ListSnapshots returns). keepLast > 0 keeps that many newest
// per resource; before > 0 selects snapshots created before now-before. When
// both are set, only snapshots beyond the keep-last window AND older than the cutoff
// are selected (the conservative intersection). It returns the ids to prune.
//
// Anchored snapshots are outside the retention universe entirely: they are never
// selected, and they do not count toward the --keep-last quota, so anchoring a
// snapshot never pushes an unanchored one out of the keep window.
func selectSnapshotsToPrune(snaps []api.SnapshotInfo, keepLast int, before time.Duration, now time.Time) []string {
	var cutoff int64
	if before > 0 {
		cutoff = now.Add(-before).Unix()
	}
	perResource := map[string]int{}
	var prune []string
	for _, s := range snaps {
		if s.Anchored {
			continue
		}
		perResource[s.ResourceID]++ // newest-first, so this rank rises going back in time
		beyondKeep := keepLast > 0 && perResource[s.ResourceID] > keepLast
		beforeCutoff := before > 0 && s.CreatedAt < cutoff

		var selected bool
		switch {
		case keepLast > 0 && before > 0:
			selected = beyondKeep && beforeCutoff
		case keepLast > 0:
			selected = beyondKeep
		case before > 0:
			selected = beforeCutoff
		}
		if selected {
			prune = append(prune, s.ID)
		}
	}
	return prune
}

// reportPruneTargets prints the snapshots a retention prune selected, for --dry-run
// or --json inspection, decrypting names locally like `snapshot list`.
func reportPruneTargets(snaps []api.SnapshotInfo, targets []string, prof *identity.Profile) error {
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		want[t] = true
	}
	rows := make([]snapshotRow, 0, len(targets))
	for _, r := range snapshotRows(snaps, mk) {
		if want[r.ID] {
			rows = append(rows, r)
		}
	}
	if flagJSON {
		return printJSON(rows)
	}
	fmt.Fprintf(os.Stderr, "would prune %d snapshot(s):\n", len(rows))
	return printSnapshotTable(rows)
}

// --- auto (scheduled opt-out) ---

func snapshotAutoCmd() *cobra.Command {
	var (
		id  string
		on  bool
		off bool
	)
	cmd := &cobra.Command{
		Use:   "auto [dir]",
		Short: "Show or toggle whether the scheduled job snapshots tracked roots (default: on)",
		Long: "With no target, prints whether the scheduled snapshot job covers each of your\n" +
			"resources. With a tracked dir or --id, toggles coverage for that one root.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if on && off {
				return errors.New("--on and --off are mutually exclusive")
			}
			if id == "" && len(args) > 0 {
				if err := bindTrackedDir(args[0]); err != nil {
					return err
				}
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			// No target and no toggle intent: report coverage rather than change it.
			if len(args) == 0 && id == "" && !on && !off {
				return printAutoStatus(cl, prof)
			}
			resourceID, err := resolveResourceID(dirArg(args), id)
			if err != nil {
				return err
			}
			enabled := !off
			if err := cl.SetAutoSnapshot(resourceID, enabled); errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours)", resourceID)
			} else if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(map[string]any{"id": resourceID, "autoSnapshot": enabled})
			}
			state := "enabled"
			if !enabled {
				state = "disabled"
			}
			fmt.Printf("scheduled snapshots %s for %s\n", state, resourceID)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "target this resource id instead of a tracked dir")
	cmd.Flags().BoolVar(&on, "on", false, "include this root in the scheduled job (the default)")
	cmd.Flags().BoolVar(&off, "off", false, "exclude this root from the scheduled job")
	markJSONSupported(cmd)
	return cmd
}

// autoRow is one resource's scheduled-snapshot coverage, as shown by a bare
// `aqt snapshot auto`.
type autoRow struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Auto    bool   `json:"auto"`
	Version int    `json:"version"`
}

// printAutoStatus lists every resource and whether the scheduled job covers it,
// decrypting names locally the same way `ls`/`find` do.
func printAutoStatus(cl *client.Client, prof *identity.Profile) error {
	items, err := cl.ListResources()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	rows := make([]autoRow, 0, len(items))
	for _, it := range items {
		name := "(unreadable)"
		if m, ok := openMetadata(it, mk); ok && m.Name != "" {
			name = m.Name
		}
		rows = append(rows, autoRow{ID: it.ID, Name: name, Auto: it.AutoSnapshot, Version: it.Version})
	}
	if flagJSON {
		return printJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no resources yet")
		return nil
	}
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		state := "off"
		if r.Auto {
			state = "on"
		}
		cells = append(cells, []string{r.Name, state, strconv.Itoa(r.Version), r.ID})
	}
	return printTable(os.Stdout, []string{"NAME", "AUTO", "VERSION", "ID"}, cells)
}

// --- shared ---

// reconstructSnapshot decrypts a snapshot client-side and materializes it under
// destDir, reusing the same paths as clone/pull: a folder is untarred or streamed
// from its objects, a single file is written by its name. It returns the decrypted
// metadata. The server only ever returned ciphertext and the wrapped key.
func reconstructSnapshot(cl *client.Client, prof *identity.Profile, snap api.GetSnapshotResponse, destDir string, force bool) (api.Metadata, error) {
	info := snap.Snapshot
	if info.WrappedKey == nil {
		return api.Metadata{}, errors.New("snapshot has no owner key (the resource was public); cannot restore")
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return api.Metadata{}, err
	}
	defer mk.Wipe()
	ck, err := crypto.UnwrapKey(*info.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.Metadata{}, fmt.Errorf("unwrap snapshot key: %w", err)
	}
	defer ck.Wipe()
	return materializeResource(cl, snapshotAsResource(snap), ck, destDir, force)
}

// snapshotAsResource adapts a fetched snapshot to the resource shape the materialize
// path expects; the server returned the snapshot's own sealed blob, meta and key.
func snapshotAsResource(snap api.GetSnapshotResponse) api.GetResourceResponse {
	info := snap.Snapshot
	return api.GetResourceResponse{
		ID:            info.ResourceID,
		Visibility:    api.Private,
		Blob:          snap.Blob,
		EncryptedMeta: info.EncryptedMeta,
		WrappedKey:    info.WrappedKey,
		Version:       info.Version,
	}
}

// materializeResource decrypts a resource's sealed root under the content key ck and
// writes its plaintext tree under destDir: a folder is untarred or streamed from its
// objects, a single file is written by its name. The caller owns ck's lifetime.
func materializeResource(cl *client.Client, res api.GetResourceResponse, ck crypto.ContentKey, destDir string, force bool) (api.Metadata, error) {
	meta, err := decodeMeta(res.EncryptedMeta, ck, res.ID)
	if err != nil {
		return api.Metadata{}, err
	}
	if meta.Kind == api.KindFolder {
		return meta, materializeStaged(destDir, func(staging string) error {
			_, err := materializeClone(cl, staging, res, ck, meta)
			return err
		})
	}
	// A single file (inline or streamed): write it under destDir by its name. The
	// folder branch above refuses a non-empty destination; this one refuses an
	// existing file for the same reason, and the way `aqt pull` does — a restore is
	// side-by-side by default and must not overwrite what it lands next to.
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return meta, err
	}
	dest := filepath.Join(destDir, safeOutputName(meta.Name))
	if !force {
		if _, err := os.Stat(dest); err == nil {
			return meta, fmt.Errorf("%s already exists (use --force to overwrite)", dest)
		}
	}
	if meta.Streamed {
		root, err := syncengine.OpenFileRoot(res.Blob, ck, res.ID)
		if err != nil {
			return meta, fmt.Errorf("decrypt file root: %w", err)
		}
		chunks := root.Chunks
		if root.Indirect() {
			segSrc, err := newPackSource(cl, root.ChunkIDs())
			if err != nil {
				return meta, err
			}
			chunks, err = root.Resolve(segSrc.get)
			if err != nil {
				return meta, err
			}
		}
		src, err := newPackSource(cl, distinctChunkIDs([]syncengine.Entry{{Chunks: chunks}}))
		if err != nil {
			return meta, err
		}
		return meta, fsatomic.WriteStream(dest, 0o600, func(f *os.File) error {
			return syncengine.WriteFileRoot(f, chunks, src.get)
		})
	}
	plain, err := crypto.OpenBound(res.Blob, ck, crypto.AADBlob, res.ID)
	if err != nil {
		return meta, fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
	}
	return meta, fsatomic.WriteFile(dest, plain, 0o600)
}

// materializeWithMaster unwraps res's content key under the master key, then writes
// its plaintext tree under destDir. Used by diff, which materializes both sides under
// one unlocked master key.
func materializeWithMaster(cl *client.Client, mk crypto.MasterKey, res api.GetResourceResponse, destDir string) (api.Metadata, error) {
	if res.WrappedKey == nil {
		return api.Metadata{}, errors.New("resource has no owner key (public); cannot decrypt")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.Metadata{}, fmt.Errorf("unwrap key: %w", err)
	}
	defer ck.Wipe()
	return materializeResource(cl, res, ck, destDir, false) // diff always lands in a fresh temp dir
}

// resolveResourceID maps a tracked-folder path (or an explicit --id) to a resource
// id. An explicit id wins; otherwise the nearest .aqt root's recorded id is used.
func resolveResourceID(dir, id string) (string, error) {
	if id != "" {
		// The CLI hands out aqt:// refs (push, find, shares), so --id accepts one
		// rather than only the bare id inside it.
		parsed, _, _ := parseRef(id)
		return parsed, nil
	}
	root, err := trackedRoot(dir)
	if err != nil {
		return "", err
	}
	st, err := loadState(root)
	if err != nil {
		return "", fmt.Errorf("read folder state: %w", err)
	}
	if st.ID == "" {
		return "", fmt.Errorf("%s has no synced resource yet; run `aqt sync` first", root)
	}
	return st.ID, nil
}
