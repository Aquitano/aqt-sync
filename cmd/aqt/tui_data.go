package main

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// tuiCtx is the TUI's connection to the world: profile, API client, unlocked
// master key, and the tracked folder it was opened in (root == "" when outside
// one — the resources and snapshots panels still work account-wide).
type tuiCtx struct {
	prof     *identity.Profile
	cl       *client.Client
	mk       crypto.MasterKey
	unlocked bool
	root     string
	exe      string // this binary, re-executed for mutating actions
}

// --- messages ---

type tuiUnlockResultMsg struct {
	mk  crypto.MasterKey
	err error
	// cacheWarn reports a session-cache failure. It cannot be written to stderr:
	// the alt screen is up and the renderer owns the tty, so it rides back to
	// Update and becomes a toast.
	cacheWarn error
}

// tuiLocalMsg is the offline half of the files panel: working tree vs base,
// plus any conflict copies a previous `sync --conflicts=copy` left on disk.
type tuiLocalMsg struct {
	changes   changeSet
	conflicts []string
	err       error
}

// tuiRemoteMsg is the server half: version freshness plus, when the folder key
// allows it, the entry-level incoming diff.
type tuiRemoteMsg struct {
	note      string // one-line freshness verdict for the status panel
	stale     bool   // server is behind our pin (restored from backup?)
	incoming  changeSet
	fileLevel bool // incoming carries per-file paths, not just a version delta
	err       error
}

type tuiResourcesMsg struct {
	rows []lsRow
	err  error
}

type tuiSnapshotsMsg struct {
	rows []snapshotRow
	err  error
}

type tuiDevicesMsg struct {
	devices []api.Device
	err     error
}

type tuiAgentMsg struct {
	running bool
	pid     int
}

type tuiDiffMsg struct {
	snapshotID string
	result     snapshotDiffResult
	err        error
}

type tuiCopiedMsg struct {
	ref   string
	kind  string
	ok    bool
	err   error
	retry tea.Cmd
}

type tuiPublicLinkError struct {
	Stage string
	Err   error
}

func (e *tuiPublicLinkError) Error() string {
	return "build public link (" + e.Stage + "): " + e.Err.Error()
}
func (e *tuiPublicLinkError) Unwrap() error { return e.Err }

type tuiFsEventMsg struct{}
type tuiFsSettledMsg struct{ seq int }

// --- loaders (each runs in its own goroutine via tea.Cmd) ---

func (c *tuiCtx) unlockCmd(passphrase string) tea.Cmd {
	prof := c.prof
	return func() tea.Msg {
		mk, err := prof.Unlock(passphrase)
		if err != nil {
			return tuiUnlockResultMsg{err: err}
		}
		// The unlock itself succeeded; a failed cache only means the next action
		// subprocess would prompt, which it cannot — so it has to be visible.
		if err := identity.SaveSession(prof.Name, mk, sessionTTL(prof)); err != nil {
			return tuiUnlockResultMsg{mk: mk, cacheWarn: err}
		}
		return tuiUnlockResultMsg{mk: mk}
	}
}

func (c *tuiCtx) localStatusCmd() tea.Cmd {
	root := c.root
	return func() tea.Msg {
		base, err := loadBase(root)
		if err != nil {
			return tuiLocalMsg{err: err}
		}
		local, err := syncengine.ScanReusing(root, &base, false)
		if err != nil {
			return tuiLocalMsg{err: err}
		}
		conflicts, err := tuiConflictCopies(root)
		if err != nil {
			return tuiLocalMsg{err: err}
		}
		return tuiLocalMsg{changes: computeLocalChanges(local, base), conflicts: conflicts}
	}
}

// tuiConflictCopies lists the conflict-copy files `sync --conflicts=copy` wrote:
// they are ordinary tracked content, so they surface until the user resolves and
// deletes them.
func tuiConflictCopies(root string) ([]string, error) {
	paths, err := syncengine.ListPaths(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range paths {
		if strings.Contains(p, ".conflict-") {
			out = append(out, p)
		}
	}
	return out, nil
}

func (c *tuiCtx) remoteStatusCmd() tea.Cmd {
	ctx := *c
	return func() tea.Msg {
		st, err := loadState(ctx.root)
		if err != nil {
			return tuiRemoteMsg{err: err, note: "cannot read .aqt/state.json — " + err.Error()}
		}
		res, err := ctx.cl.GetResource(st.ID)
		if err != nil {
			return tuiRemoteMsg{err: err, note: tuiRemoteErrNote(err)}
		}
		switch {
		case st.RemoteVersion > 0 && res.Version < st.RemoteVersion:
			return tuiRemoteMsg{stale: true, note: fmt.Sprintf("server reports an older version (%d < %d) — restored from backup?", res.Version, st.RemoteVersion)}
		case st.RemoteVersion > 0 && res.Version == st.RemoteVersion:
			return tuiRemoteMsg{note: "up to date with the server"}
		}
		// Server is ahead: entry-level breakdown when the folder is chunked (a
		// pack-and-seal folder is one opaque blob with no per-file remote diff).
		if cfg, cerr := syncengine.LoadConfig(ctx.root); cerr == nil && !cfg.Pack {
			base, berr := loadBase(ctx.root)
			if berr == nil {
				if inc, ierr := incomingFiles(ctx.cl, res, base, ctx.mk); ierr == nil {
					return tuiRemoteMsg{
						incoming: inc, fileLevel: true,
						note: fmt.Sprintf("incoming: %d change(s) to pull", inc.total()),
					}
				}
			}
		}
		if st.RemoteVersion == 0 {
			return tuiRemoteMsg{note: "the server may hold changes to pull"}
		}
		return tuiRemoteMsg{note: fmt.Sprintf("server is ahead by %d version(s)", res.Version-st.RemoteVersion)}
	}
}

// tuiRemoteErrNote compresses a failed server check into the short status-panel
// freshness line.
func tuiRemoteErrNote(err error) string {
	switch {
	case errors.Is(err, client.ErrNotFound):
		return "remote resource is gone (deleted on the server?)"
	case isNetworkError(err):
		return "server unreachable — showing local changes only"
	default:
		return "server check failed"
	}
}

func (c *tuiCtx) resourcesCmd() tea.Cmd {
	ctx := *c
	return func() tea.Msg {
		rows, err := collectResources(ctx.cl, ctx.mk)
		return tuiResourcesMsg{rows: rows, err: err}
	}
}

// snapshotsCmd lists snapshots — scoped to the tracked folder's resource when
// inside one, account-wide otherwise.
func (c *tuiCtx) snapshotsCmd() tea.Cmd {
	ctx := *c
	return func() tea.Msg {
		resourceID := ""
		if ctx.root != "" {
			st, err := loadState(ctx.root)
			if err != nil {
				return tuiSnapshotsMsg{err: err}
			}
			resourceID = st.ID
		}
		snaps, err := ctx.cl.ListSnapshots(resourceID)
		if err != nil {
			return tuiSnapshotsMsg{err: err}
		}
		return tuiSnapshotsMsg{rows: snapshotRows(snaps, ctx.mk)}
	}
}

func (c *tuiCtx) devicesCmd() tea.Cmd {
	cl, currentID := c.cl, c.prof.DeviceID
	return func() tea.Msg {
		devs, err := cl.ListDevices()
		for i := range devs {
			devs[i].Current = devs[i].ID == currentID
		}
		return tuiDevicesMsg{devices: devs, err: err}
	}
}

func (c *tuiCtx) agentStatusCmd() tea.Cmd {
	root := c.root
	return func() tea.Msg {
		pid, ok := readLockPID(controlPath(root, agentPIDFile))
		running := ok && processAlive(pid) && looksLikeAqtProcess(pid)
		return tuiAgentMsg{running: running, pid: pid}
	}
}

// diffCmd computes what changed between a snapshot and the live resource, the
// same metadata-only walk `aqt snapshot diff` does.
func (c *tuiCtx) diffCmd(snapshotID string) tea.Cmd {
	ctx := *c
	return func() tea.Msg {
		result, err := computeSnapshotDiff(ctx.cl, ctx.mk, snapshotID, "")
		return tuiDiffMsg{snapshotID: snapshotID, result: result, err: err}
	}
}

// copyRefCmd puts the resource's ref on the clipboard: the private aqt:// form,
// or the full fragment link for a public resource (rebuilt from the owner's
// wrapped key — the fragment never exists server-side).
func (c *tuiCtx) copyRefCmd(row lsRow) tea.Cmd {
	ctx := *c
	return func() tea.Msg {
		retry := ctx.copyRefCmd(row)
		if row.Visibility != string(api.Public) {
			ref := "aqt://" + row.ID
			return tuiCopiedMsg{ref: ref, kind: "private ref", ok: copyToClipboard(ref), retry: retry}
		}
		res, err := ctx.cl.GetResource(row.ID)
		if err != nil {
			return tuiCopiedMsg{kind: "public link", err: &tuiPublicLinkError{Stage: "fetch resource", Err: err}, retry: retry}
		}
		if res.WrappedKey == nil {
			return tuiCopiedMsg{kind: "public link", err: &tuiPublicLinkError{Stage: "recover key", Err: errors.New("resource has no owner-wrapped key")}, retry: retry}
		}
		ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(ctx.mk))
		if err != nil {
			return tuiCopiedMsg{kind: "public link", err: &tuiPublicLinkError{Stage: "unwrap key", Err: err}, retry: retry}
		}
		defer ck.Wipe()
		ref, err := buildRef(ctx.prof.Server, row.ID, api.Public, ck, "")
		if err != nil {
			return tuiCopiedMsg{kind: "public link", err: &tuiPublicLinkError{Stage: "encode link", Err: err}, retry: retry}
		}
		return tuiCopiedMsg{ref: ref, kind: "public link", ok: copyToClipboard(ref), retry: retry}
	}
}

// tuiWaitFs turns the tree watcher's channel into a message; the model
// re-subscribes after each event.
func tuiWaitFs(events <-chan struct{}) tea.Cmd {
	return func() tea.Msg {
		if _, ok := <-events; !ok {
			return nil
		}
		return tuiFsEventMsg{}
	}
}
