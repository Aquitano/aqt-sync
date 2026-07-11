package main

import (
	"errors"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func tuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui [dir]",
		Short: "Interactive terminal UI for sync, snapshots, and shares",
		Long: "A lazygit-style dashboard over the tracked folder at [dir] (default: the\n" +
			"folder the current directory is inside, if any): local and incoming changes,\n" +
			"snapshots and checkpoints, and every pushed resource, with single-key actions\n" +
			"for sync, share, checkpoint, and restore. Actions run the corresponding aqt\n" +
			"command and stream its output into a log pane. Outside a tracked folder the\n" +
			"resources and snapshots panels still work account-wide.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			return runTUI(dir, len(args) == 1)
		},
	}
}

// explicitDir reports whether the user named the directory themselves: then a
// non-tracked path is an error, not a silent fall-back to account-wide mode.
func runTUI(dir string, explicitDir bool) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("the TUI needs a terminal")
	}
	prof, err := loadProfile()
	if err != nil {
		return fmt.Errorf("%w — run `aqt login` first", err)
	}
	cl, err := client.New(prof.Server, prof.Token)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ctx := &tuiCtx{prof: prof, cl: cl, exe: exe}
	if mk, ok := identity.LoadSession(prof.Name); ok {
		ctx.mk = mk
		ctx.unlocked = true
	}
	defer func() {
		if ctx.unlocked {
			ctx.mk.Wipe()
		}
	}()

	// Outside a tracked folder the TUI still opens account-wide; the folder
	// panels explain. But a directory the user named explicitly must resolve.
	folderID := ""
	root, rerr := trackedRoot(dir)
	if rerr != nil && explicitDir {
		return fmt.Errorf("%s is not (inside) a tracked folder: %w", dir, rerr)
	}
	if rerr == nil {
		ctx.root = root
		if st, serr := loadState(root); serr == nil {
			folderID = st.ID
		}
	}

	// Kernel file events keep the files panel live while the user edits in
	// another window. Best-effort: without a watcher (inotify budget, exotic
	// fs) the panel still refreshes on focus, action, and `r`.
	var fsEvents <-chan struct{}
	if ctx.root != "" {
		if w, werr := syncengine.WatchTree(ctx.root); werr == nil {
			defer w.Close()
			fsEvents = w.Events()
		}
	}

	_, err = tea.NewProgram(
		newTUIModel(ctx, folderID, fsEvents),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	).Run()
	return err
}
