package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// kindFolderFile labels an entry that is a file inside a tracked folder (as
// opposed to a top-level file or folder resource).
const kindFolderFile = "folder-file"

// findEntry is one searchable row: a file resource, a folder resource, or a file
// within a folder. Ref is what `find` prints when the entry is selected — always
// the owning resource (the folder, for a folder member), so it composes with
// `aqt pull` / `aqt clone`.
type findEntry struct {
	Kind       string `json:"kind"` // file | folder | folder-file
	Name       string `json:"name"` // display: resource name, or "folder/path"
	Path       string `json:"path,omitempty"`
	Size       int64  `json:"size"`
	Visibility string `json:"visibility"`
	Ref        string `json:"ref"` // aqt://<id>
	ID         string `json:"id"`
}

func findCmd() *cobra.Command {
	var noFzf bool
	cmd := &cobra.Command{
		Use:   "find [query]",
		Short: "Fuzzy-search all your files and folder contents (via fzf)",
		Long: "Build a searchable index of every resource — single files, folders, and the\n" +
			"files inside each folder — and open it in fzf. The selected entry's ref is\n" +
			"printed, so it composes: `aqt pull \"$(aqt find)\"`.\n\n" +
			"Without a terminal or fzf, the index is printed as a table instead.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFind(strings.Join(args, " "), flagJSON, noFzf)
		},
	}
	cmd.Flags().BoolVar(&noFzf, "no-fzf", false, "print the index as a table instead of opening fzf")
	return cmd
}

func runFind(query string, asJSON, noFzf bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()

	entries, err := buildFindIndex(cl, mk)
	if err != nil {
		return err
	}
	// --json emits the index (even an empty []) before the human "nothing here"
	// path, so a script always gets valid JSON.
	if asJSON {
		return printJSON(entries)
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no resources yet")
		return nil
	}

	fzfPath, _ := exec.LookPath("fzf")
	interactive := term.IsTerminal(int(os.Stdout.Fd()))
	if noFzf || fzfPath == "" || !interactive {
		if fzfPath == "" && interactive && !noFzf {
			fmt.Fprintln(os.Stderr, "fzf not found; printing the index (install fzf for interactive search)")
		}
		return printFindTable(entries)
	}
	return fzfSelect(fzfPath, query, entries)
}

// buildFindIndex lists the owner's resources and expands each tracked folder into
// its member files, so a single search covers everything. A folder whose manifest
// cannot be read is reported and skipped rather than aborting the whole index.
func buildFindIndex(cl *client.Client, mk crypto.MasterKey) ([]findEntry, error) {
	items, err := cl.ListResources()
	if err != nil {
		return nil, err
	}
	out := []findEntry{} // non-nil so an empty index marshals to [] not null
	for _, it := range items {
		meta, ok := openMetadata(it, mk)
		name := meta.Name
		if !ok || name == "" {
			name = "(unreadable)"
		}
		kind := meta.Kind
		if kind == "" {
			kind = api.KindFile
		}
		ref := "aqt://" + it.ID
		out = append(out, findEntry{
			Kind: kind, Name: name, Size: meta.Size,
			Visibility: string(it.Visibility), Ref: ref, ID: it.ID,
		})

		// A pack-and-seal folder's blob is an opaque tarball, not a per-file
		// manifest, so its members can't be listed without untarring; skip them.
		if kind != api.KindFolder || it.WrappedKey == nil || meta.Packed {
			continue
		}
		members, err := folderMembers(cl, it.ID, mk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not read folder %q: %v\n", name, err)
			continue
		}
		for _, e := range members {
			out = append(out, findEntry{
				Kind: kindFolderFile, Name: name + "/" + e.Path, Path: e.Path,
				Size: e.Size, Visibility: string(it.Visibility), Ref: ref, ID: it.ID,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// folderMembers fetches a folder resource, unwraps its content key, and returns
// the entries of its sealed manifest.
func folderMembers(cl *client.Client, id string, mk crypto.MasterKey) ([]syncengine.Entry, error) {
	res, err := cl.GetResource(id)
	if err != nil {
		return nil, err
	}
	if res.WrappedKey == nil {
		return nil, errors.New("no owner key")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return nil, err
	}
	defer ck.Wipe()
	m, err := openRemoteTree(cl, res.Blob, ck)
	if err != nil {
		return nil, err
	}
	return m.Entries, nil
}

func printFindTable(entries []findEntry) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tKIND\tSIZE\tVISIBILITY\tREF")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.Name, e.Kind, findSize(e), e.Visibility, e.Ref)
	}
	return w.Flush()
}

// fzfSelect feeds the index to fzf and prints the chosen entry's ref. Cancelling
// fzf (Esc / no match) exits quietly with no output.
func fzfSelect(fzfPath, query string, entries []findEntry) error {
	var input strings.Builder
	for _, e := range entries {
		// Display columns first, hidden ref last; --with-nth hides the ref from the
		// view but keeps it on the returned line so we can recover it on select.
		fmt.Fprintf(&input, "%s\t%s\t%s\t%s\t%s\n", e.Name, e.Kind, findSize(e), e.Visibility, e.Ref)
	}
	args := []string{
		"--delimiter", "\t",
		"--with-nth", "1,2,3,4",
		"--header", "Enter prints the resource ref · Esc cancels",
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
		// fzf exits 130 when interrupted (Esc/Ctrl-C) and 1 when nothing matched;
		// both mean "no selection", not a failure.
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

// findSize renders an entry's size, dashing folder resources (no tracked size).
func findSize(e findEntry) string {
	if e.Kind == api.KindFolder {
		return "-"
	}
	return humanBytes(e.Size)
}
