// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

type tuiPanelID int

const (
	tuiPanelStatus tuiPanelID = iota
	tuiPanelFiles
	tuiPanelSnapshots
	tuiPanelResources
	tuiPanelCount
)

const (
	tuiTabDetail = iota
	tuiTabLog
)

// tuiFsSettle is how long the tree must stay quiet after a burst of fs events
// before the files panel rescans, mirroring the watch daemon's debounce idea.
const tuiFsSettle = 400 * time.Millisecond

// tuiLogMax bounds the command log ring so a day-long session cannot grow
// memory without bound.
const tuiLogMax = 5000

type tuiPanel struct {
	title   string
	list    tuiList
	loading bool
	err     error
}

// tuiOpenDialogMsg lets a resolving dialog (e.g. a menu entry) open the next
// dialog in a chain, such as share → password prompt.
type tuiOpenDialogMsg struct{ dialog tuiDialog }

type tuiModel struct {
	ctx *tuiCtx

	w, h  int
	focus tuiPanelID
	// mainFocus routes movement keys to the main viewport (esc returns).
	mainFocus bool
	mainTab   int

	panels [tuiPanelCount]tuiPanel

	// loaded data (panels render from these)
	folderID  string
	local     changeSet
	conflicts []string
	remote    tuiRemoteMsg
	remoteOK  bool
	resources []lsRow
	snaps     []snapshotRow
	devices   []api.Device
	devErr    error
	agent     tuiAgentMsg

	// on-demand snapshot diff, keyed by snapshot id
	diffFor string
	diff    *comparison
	diffErr error
	diffing bool

	// on-demand working-tree-versus-remote comparison
	compared   *comparison
	compareErr error
	comparing  bool

	vp viewport.Model

	dialog tuiDialog

	// pre-unlock passphrase screen
	unlockIn  textinput.Model
	unlocking bool
	unlockErr error

	filtering bool
	filterIn  textinput.Model

	// One action at a time. execBusy is set synchronously when a request is
	// accepted (before the subprocess Cmd runs) so a double-tapped key cannot
	// start two; execCh carries the running action's output.
	execBusy  bool
	execCh    chan tea.Msg
	execCmd   *exec.Cmd
	execTitle string
	// execCanceled records that the running action was stopped by the user, so
	// its non-zero exit reads as "canceled" rather than a failure.
	execCanceled bool
	// execStart timestamps the running action so the completion line can report
	// how long it took.
	execStart time.Time
	log       []string
	// logFollow keeps the log pinned to the bottom as new lines arrive; a manual
	// upward scroll pauses it until the user returns to the bottom (G).
	logFollow bool

	fsEvents <-chan struct{}
	fsSeq    int

	spin       spinner.Model
	statusLine string
	// statusStyle colors the current toast by its meaning (accent info, green
	// success, red failure).
	statusStyle lipgloss.Style
	// toastSeq tags each transient status line so its expiry tick only clears
	// the line it was scheduled for, never a newer one.
	toastSeq int
	// toastTTL is how long a status line stays up. It is a field rather than a
	// constant so a test can assert on the expiry tick without waiting it out.
	toastTTL time.Duration
}

// defaultToastTTL is how long a status line stays up in a real session.
const defaultToastTTL = 4 * time.Second

// tuiToastExpiredMsg fires a few seconds after a status line is set.
type tuiToastExpiredMsg struct{ seq int }

// toast sets the transient status line and returns the command that clears it
// once it has had its moment. Callers that already return a command should batch
// this alongside it.
func (m *tuiModel) toast(s string) tea.Cmd { return m.toastStyled(s, tuiStyleAccent) }

// toastErr is the failure-colored toast; used for actions that ended non-zero.
func (m *tuiModel) toastErr(s string) tea.Cmd { return m.toastStyled(s, tuiStyleErr) }

func (m *tuiModel) toastStyled(s string, style lipgloss.Style) tea.Cmd {
	m.statusLine = s
	m.statusStyle = style
	m.toastSeq++
	seq := m.toastSeq
	return tea.Tick(m.toastTTL, func(time.Time) tea.Msg { return tuiToastExpiredMsg{seq: seq} })
}

func newTUIModel(ctx *tuiCtx, folderID string, fsEvents <-chan struct{}) *tuiModel {
	m := &tuiModel{ctx: ctx, folderID: folderID, fsEvents: fsEvents, focus: tuiPanelFiles, logFollow: true, toastTTL: defaultToastTTL}
	if ctx.root == "" {
		m.focus = tuiPanelResources
	}
	m.spin = spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(tuiStyleAccent))
	m.panels[tuiPanelStatus].title = "Status"
	m.panels[tuiPanelFiles].title = "Files"
	m.panels[tuiPanelSnapshots].title = "Snapshots"
	m.panels[tuiPanelResources].title = "Resources"
	m.unlockIn = textinput.New()
	m.unlockIn.Placeholder = "passphrase"
	m.unlockIn.EchoMode = textinput.EchoPassword
	m.unlockIn.Focus()
	m.filterIn = textinput.New()
	m.filterIn.Prompt = "/"
	m.rebuildAll()
	return m
}

func (m *tuiModel) Init() tea.Cmd {
	if !m.ctx.unlocked {
		return textinput.Blink
	}
	return m.initialLoads()
}

func (m *tuiModel) initialLoads() tea.Cmd {
	cmds := []tea.Cmd{m.reloadPanels()}
	if m.fsEvents != nil {
		cmds = append(cmds, tuiWaitFs(m.fsEvents))
	}
	return tea.Batch(cmds...)
}

// reloadPanels refreshes every data panel: the initial load, and again after
// each action (which may have moved data on both sides).
func (m *tuiModel) reloadPanels() tea.Cmd {
	cmds := []tea.Cmd{m.ctx.resourcesCmd(), m.ctx.snapshotsCmd(), m.ctx.devicesCmd(), m.spin.Tick}
	m.panels[tuiPanelResources].loading = true
	m.panels[tuiPanelSnapshots].loading = true
	if m.ctx.root != "" {
		cmds = append(cmds, m.ctx.localStatusCmd(), m.ctx.remoteStatusCmd(), m.ctx.agentStatusCmd())
		m.panels[tuiPanelFiles].loading = true
	}
	return tea.Batch(cmds...)
}

func (m *tuiModel) busy() bool {
	if m.execBusy || m.diffing || m.comparing || m.unlocking {
		return true
	}
	for i := range m.panels {
		if m.panels[i].loading {
			return true
		}
	}
	return false
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		first := m.w == 0
		m.w, m.h = msg.Width, msg.Height
		m.vp.Width, m.vp.Height = m.mainWidth()-2, m.h-3
		if first {
			m.refreshMain() // later resizes keep content and scroll position
		}
		return m, nil

	case spinner.TickMsg:
		if !m.busy() {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tuiUnlockResultMsg:
		m.unlocking = false
		if msg.err != nil {
			m.unlockErr = msg.err
			m.unlockIn.SetValue("")
			return m, textinput.Blink
		}
		m.ctx.mk = msg.mk
		m.ctx.unlocked = true
		if msg.cacheWarn != nil {
			return m, tea.Batch(
				m.toastErr("session not cached — actions may fail with exit 3: "+msg.cacheWarn.Error()),
				m.initialLoads(),
			)
		}
		return m, m.initialLoads()

	case tuiLocalMsg:
		m.panels[tuiPanelFiles].loading = false
		m.panels[tuiPanelFiles].err = msg.err
		if msg.err == nil {
			m.local, m.conflicts = msg.changes, msg.conflicts
		}
		m.retireComparison()
		m.rebuildFilesPanel()
		m.rebuildStatusPanel()
		m.refreshMain()
		return m, nil

	case tuiRemoteMsg:
		m.remote, m.remoteOK = msg, true
		m.rebuildFilesPanel()
		m.rebuildStatusPanel()
		m.refreshMain()
		return m, nil

	case tuiResourcesMsg:
		m.panels[tuiPanelResources].loading = false
		m.panels[tuiPanelResources].err = msg.err
		if msg.err == nil {
			m.resources = msg.rows
		}
		m.rebuildResourcesPanel()
		m.refreshMain()
		return m, nil

	case tuiSnapshotsMsg:
		m.panels[tuiPanelSnapshots].loading = false
		m.panels[tuiPanelSnapshots].err = msg.err
		if msg.err == nil {
			m.snaps = msg.rows
		}
		m.rebuildSnapshotsPanel()
		m.refreshMain()
		return m, nil

	case tuiDevicesMsg:
		m.devices, m.devErr = msg.devices, msg.err
		m.refreshMain()
		return m, nil

	case tuiAgentMsg:
		m.agent = msg
		m.rebuildStatusPanel()
		return m, nil

	case tuiStartDiffMsg:
		m.diffFor = msg.snapshotID
		m.diff, m.diffErr, m.diffing = nil, nil, true
		m.refreshMain()
		return m, tea.Batch(m.ctx.diffCmd(msg.snapshotID), m.spin.Tick)

	case tuiDiffMsg:
		if msg.snapshotID != m.diffFor {
			return m, nil // selection moved on; drop the stale result
		}
		m.diffing = false
		m.diffErr = msg.err
		if msg.err == nil {
			m.diff = &msg.result
		}
		m.refreshMain()
		return m, nil

	case tuiStartCompareMsg:
		// A held key must not stack tree walks: one comparison at a time.
		if m.ctx.root == "" || m.comparing {
			return m, nil
		}
		m.comparing, m.compareErr = true, nil
		m.rebuildFilesPanel()
		m.refreshMain()
		return m, tea.Batch(m.ctx.compareCmd(), m.spin.Tick)

	case tuiCompareMsg:
		m.comparing = false
		m.compareErr = msg.err
		if msg.err == nil {
			m.compared = &msg.result
		}
		m.rebuildFilesPanel()
		m.refreshMain()
		return m, nil

	case tuiCopiedMsg:
		if msg.err != nil {
			m.dialog = &tuiResultDialog{title: "Could not create " + msg.kind, body: msg.err.Error() + "\n\nNo private reference was substituted.", retry: msg.retry}
			return m, nil
		}
		if !msg.ok {
			m.dialog = &tuiResultDialog{title: "Clipboard unavailable", body: "The exact " + msg.kind + " is below. Select and copy it manually:\n\n" + msg.ref, retry: msg.retry}
			return m, nil
		}
		cmd := m.toast("copied " + msg.kind)
		m.refreshMain()
		return m, cmd

	case tuiOpenDialogMsg:
		m.dialog = msg.dialog
		return m, textinput.Blink

	case tuiExecRequestMsg:
		if m.execBusy {
			return m, m.toast("an action is already running — see the log (@)")
		}
		m.execBusy = true
		// Stamped here, not on Started: a subprocess that fails to start reports
		// Done without ever reporting Started, and a zero execStart would render
		// the elapsed time as seconds-since-the-epoch.
		m.execStart = time.Now()
		return m, tuiExecCmd(m.ctx.exe, msg.sub, msg.stdin)

	case tuiExecStartedMsg:
		m.execCh = msg.ch
		m.execCmd = msg.cmd
		m.execTitle = msg.title
		m.logFollow = true
		m.appendLog(tuiStyleDim.Render(m.execStart.Format("15:04:05")) + " " + tuiStyleAccent.Render("$ "+msg.title))
		m.mainTab = tuiTabLog
		m.refreshMain()
		return m, tea.Batch(tuiExecListen(msg.ch), m.spin.Tick)

	case tuiExecOutMsg:
		m.appendLog(msg.line)
		m.refreshMain()
		return m, tuiExecListen(msg.ch)

	case tuiExecDoneMsg:
		m.execBusy = false
		m.execCh = nil
		m.execCmd = nil
		canceled := m.execCanceled
		m.execCanceled = false
		elapsed := tuiStyleDim.Render(fmt.Sprintf(" (%.1fs)", time.Since(m.execStart).Seconds()))
		var note string
		var toast tea.Cmd
		switch {
		case canceled:
			note = "canceled"
			m.appendLog(tuiStyleErr.Render("✗ canceled") + elapsed)
			toast = m.toast(note)
		case msg.exit == 0:
			note = tuiExitNote(msg.exit)
			m.appendLog(tuiStyleAdd.Render("✓ "+note) + elapsed)
			toast = m.toastStyled(note, tuiStyleAdd)
		case msg.exit == exitDeferred:
			// EX_TEMPFAIL is a deliberate deferral (a git operation held the sync
			// back), not a failure; a red ✗ would tell the user something broke.
			note = tuiExitNote(msg.exit)
			m.appendLog(tuiStyleDim.Render("○ "+note) + elapsed)
			toast = m.toastStyled(note, tuiStyleDim)
		default:
			note = tuiExitNote(msg.exit)
			// A failure to even start the child (bad exe, fork failure) reports no
			// output and no ExitError, so without this the log shows only "failed".
			var ee *exec.ExitError
			if msg.err != nil && !errors.As(msg.err, &ee) {
				note = msg.err.Error()
			}
			m.appendLog(tuiStyleErr.Render("✗ "+note) + elapsed)
			toast = m.toastErr(note)
			// Exit 3 is the child reporting there is no unlocked session: the cached key
			// expired, or `aqt lock` cleared it, while this TUI still held its own copy.
			// Drop back to the unlock view rather than failing every action until quit.
			if msg.exit == 3 {
				m.ctx.unlocked = false
				m.ctx.mk.Wipe()
				m.unlockIn.SetValue("")
				m.unlockErr = nil
				m.refreshMain()
				return m, tea.Batch(toast, textinput.Blink)
			}
		}
		m.refreshMain()
		return m, tea.Batch(toast, m.reloadPanels())

	case tuiCancelExecMsg:
		if m.execBusy && m.execCmd != nil && m.execCmd.Process != nil {
			m.execCanceled = true
			_ = terminateAgent(m.execCmd.Process.Pid)
		}
		return m, nil

	case tuiKillAndQuitMsg:
		m.terminateExec()
		return m, tea.Quit

	case tuiToastExpiredMsg:
		if msg.seq == m.toastSeq {
			m.statusLine = ""
			m.refreshMain()
		}
		return m, nil

	case tuiFsEventMsg:
		m.fsSeq++
		seq := m.fsSeq
		return m, tea.Batch(
			tuiWaitFs(m.fsEvents),
			tea.Tick(tuiFsSettle, func(time.Time) tea.Msg { return tuiFsSettledMsg{seq: seq} }),
		)

	case tuiFsSettledMsg:
		// Only the last event of a burst triggers the rescan, and never while an
		// action is running (its own completion reloads).
		if msg.seq != m.fsSeq || m.execBusy || m.ctx.root == "" {
			return m, nil
		}
		m.panels[tuiPanelFiles].loading = true
		return m, tea.Batch(m.ctx.localStatusCmd(), m.spin.Tick)

	case tea.MouseMsg:
		return m.handleMouse(msg)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *tuiModel) appendLog(line string) {
	m.log = append(m.log, line)
	if len(m.log) > tuiLogMax {
		m.log = m.log[len(m.log)-tuiLogMax:]
	}
}

// --- key routing ---

func (m *tuiModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		m.terminateExec()
		return m, tea.Quit
	}

	if !m.ctx.unlocked {
		return m.handleUnlockKey(msg)
	}

	// ctrl+x cancels the running action from anywhere; a plain `x` is bound to
	// delete in the snapshots and resources panels, so cancel takes the modifier.
	if msg.String() == "ctrl+x" && m.execBusy && m.dialog == nil {
		m.dialog = &tuiConfirm{
			title:   "Cancel running action?",
			body:    m.execTitle + "\nis running. Send SIGTERM to stop it?",
			confirm: tuiCancelExec(),
		}
		return m, nil
	}

	if m.dialog != nil {
		cmd, done := m.dialog.Update(msg)
		if done {
			m.dialog = nil
		}
		return m, cmd
	}

	if m.filtering {
		switch msg.String() {
		case "enter":
			m.filtering = false
			return m, nil
		case "esc":
			m.filtering = false
			m.filterIn.SetValue("")
			m.panel().list.setFilter("")
			m.refreshMain()
			return m, nil
		}
		var cmd tea.Cmd
		m.filterIn, cmd = m.filterIn.Update(msg)
		m.panel().list.setFilter(m.filterIn.Value())
		m.refreshMain()
		return m, cmd
	}

	if m.mainFocus {
		switch msg.String() {
		case "esc", "h":
			m.mainFocus = false
			return m, nil
		case "q":
			return m.quitOrConfirm()
		case "@":
			m.toggleTab()
			return m, nil
		case "1", "2", "3", "4":
			m.mainFocus = false
			m.setFocus(tuiPanelID(int(msg.String()[0] - '1')))
			return m, nil
		case "tab":
			m.mainFocus = false
			m.setFocus((m.focus + 1) % tuiPanelCount)
			return m, nil
		case "shift+tab":
			m.mainFocus = false
			m.setFocus((m.focus + tuiPanelCount - 1) % tuiPanelCount)
			return m, nil
		}
		if m.mainTab == tuiTabLog {
			return m, m.scrollLog(msg)
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	}

	// With the log covering the detail pane, a panel cursor is meaningless: send
	// the movement keys to the log viewport instead of the focused list.
	if m.mainTab == tuiTabLog {
		switch msg.String() {
		case "j", "k", "down", "up", "ctrl+d", "ctrl+u", "pgdown", "pgup", "g", "G", "home", "end":
			return m, m.scrollLog(msg)
		}
	}

	switch msg.String() {
	case "q":
		return m.quitOrConfirm()
	case "?":
		m.dialog = &tuiHelp{tracked: m.ctx.root != ""}
		return m, nil
	case "1", "2", "3", "4":
		m.setFocus(tuiPanelID(int(msg.String()[0] - '1')))
		return m, nil
	case "tab":
		m.setFocus((m.focus + 1) % tuiPanelCount)
		return m, nil
	case "shift+tab":
		m.setFocus((m.focus + tuiPanelCount - 1) % tuiPanelCount)
		return m, nil
	case "j", "down":
		m.panel().list.move(1)
		m.onSelectionMoved()
		return m, nil
	case "k", "up":
		m.panel().list.move(-1)
		m.onSelectionMoved()
		return m, nil
	case "ctrl+d", "pgdown":
		m.panel().list.move(m.halfPage())
		m.onSelectionMoved()
		return m, nil
	case "ctrl+u", "pgup":
		m.panel().list.move(-m.halfPage())
		m.onSelectionMoved()
		return m, nil
	case "g", "home":
		m.panel().list.home()
		m.onSelectionMoved()
		return m, nil
	case "G", "end":
		m.panel().list.end()
		m.onSelectionMoved()
		return m, nil
	case "enter", "l":
		m.mainFocus = true
		m.mainTab = tuiTabDetail
		m.refreshMain()
		return m, nil
	case "@":
		m.toggleTab()
		return m, nil
	case "/":
		m.filtering = true
		m.filterIn.SetValue(m.panel().list.filter)
		m.filterIn.Focus()
		return m, textinput.Blink
	case "r":
		return m, m.refreshFocused()
	case " ":
		if opts := m.panelActions(); len(opts) > 0 {
			m.dialog = &tuiMenu{title: m.panel().title + " actions", options: opts}
		}
		return m, nil
	case "esc":
		if m.panel().list.filter != "" {
			m.filterIn.SetValue("")
			m.panel().list.setFilter("")
			m.refreshMain()
		}
		return m, nil
	}

	return m.handleActionKey(msg)
}

// terminateExec stops the running action, if one is still running. The liveness
// check reads the live model state, so a child that finished (and was reaped)
// while a dialog was open is never signalled by pid.
func (m *tuiModel) terminateExec() {
	if m.execBusy && m.execCmd != nil && m.execCmd.Process != nil {
		m.execCanceled = true
		_ = terminateAgent(m.execCmd.Process.Pid)
	}
}

// quitOrConfirm quits immediately when idle; while an action subprocess runs it
// asks first — quitting tears down the output pipes and would kill e.g. a
// restore mid-swap. ctrl+c stays an unconditional exit, but still stops the
// child rather than orphaning it against dead pipes.
func (m *tuiModel) quitOrConfirm() (tea.Model, tea.Cmd) {
	if !m.execBusy {
		return m, tea.Quit
	}
	m.dialog = &tuiConfirm{
		title:   "Action running",
		body:    m.execTitle + "\nis still running. Quit anyway and kill it?",
		confirm: tuiKillAndQuit(),
	}
	return m, nil
}

func (m *tuiModel) handleUnlockKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.unlocking {
		return m, nil
	}
	switch msg.String() {
	case "esc":
		return m, tea.Quit
	case "enter":
		pass := m.unlockIn.Value()
		if pass == "" {
			return m, nil
		}
		m.unlocking = true
		m.unlockErr = nil
		return m, tea.Batch(m.ctx.unlockCmd(pass), m.spin.Tick)
	}
	var cmd tea.Cmd
	m.unlockIn, cmd = m.unlockIn.Update(msg)
	return m, cmd
}

// handleActionKey dispatches the focused panel's contextual actions. The panel's
// actions menu is the mapping: a key press runs the option carrying that key, so
// the shortcut and the menu entry cannot drift apart. A key press opens a dialog
// synchronously (so the model reflects it immediately); the menu wraps the same
// dialog in tuiOpenDialog so a selection opens it one tick later. Mutating
// actions resolve to tuiExecRequestMsg, where the busy guard lives; read-only
// ones (copy, diff) stay usable while an action runs.
func (m *tuiModel) handleActionKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pressed := msg.String()
	for _, o := range m.panelActions() {
		if o.key == "" || o.key != pressed {
			continue
		}
		if o.dialog != nil {
			m.dialog = o.dialog
			return m, textinput.Blink
		}
		return m, o.cmd
	}
	return m, m.unavailableActionHint(pressed)
}

// unavailableActionHint explains a shortcut the focused panel would offer under
// different conditions. Those options are absent from the actions menu, so the
// key press is the only place the reason can be given.
func (m *tuiModel) unavailableActionHint(pressed string) tea.Cmd {
	switch m.focus {
	case tuiPanelSnapshots:
		if m.ctx.root != "" {
			return nil
		}
		switch pressed {
		case "n":
			return m.toast("open the TUI inside a tracked folder to create snapshots")
		case "R":
			if m.selectedSnapshot() != nil {
				return m.toast("in-place restore needs a tracked folder — use `aqt restore <id> --out` instead")
			}
		}
	case tuiPanelResources:
		res := m.selectedResource()
		if res == nil {
			return nil
		}
		folder := res.Kind == string(api.KindFolder)
		switch {
		case pressed == "o" && folder:
			return m.toast("use clone for a whole folder; aqt pull aqt://id/path fetches one entry")
		case pressed == "v" && folder:
			return m.toast("cat needs a file or folder subpath")
		case pressed == "c" && !folder:
			return m.toast("clone is only available for folders; use pull for files")
		case pressed == "p" && res.Visibility != string(api.Public):
			return m.toast("already private")
		}
	}
	return nil
}

// tuiStartDiffMsg begins a snapshot diff, so the pending-diff state is set in
// exactly one place.
type tuiStartDiffMsg struct{ snapshotID string }

func tuiStartDiff(id string) tea.Cmd {
	return func() tea.Msg { return tuiStartDiffMsg{snapshotID: id} }
}

type tuiStartCompareMsg struct{}

func tuiStartCompare() tea.Cmd {
	return func() tea.Msg { return tuiStartCompareMsg{} }
}

// tuiOpenDialog defers opening a dialog to the next Update, for the menu path
// where the resolving option cannot set m.dialog itself.
func tuiOpenDialog(d tuiDialog) tea.Cmd {
	return func() tea.Msg { return tuiOpenDialogMsg{dialog: d} }
}

// hasActions reports whether the focused panel has any action to offer right now.
func (m *tuiModel) hasActions() bool { return len(m.panelActions()) > 0 }

func (m *tuiModel) panelActions() []tuiMenuOption {
	switch m.focus {
	case tuiPanelStatus:
		return m.statusActions()
	case tuiPanelFiles:
		return m.filesActions()
	case tuiPanelSnapshots:
		return m.snapshotsActions()
	case tuiPanelResources:
		return m.resourcesActions()
	}
	return nil
}

func (m *tuiModel) filesActions() []tuiMenuOption {
	if m.ctx.root == "" {
		return nil
	}
	return []tuiMenuOption{
		{key: "s", label: "sync (two-way)", cmd: m.syncCmd()},
		{key: "u", label: "push local changes only", cmd: tuiRequestExec("sync", m.ctx.root, "--push-only")},
		{key: "d", label: "pull remote changes only", cmd: tuiRequestExec("sync", m.ctx.root, "--pull-only")},
		{key: "C", label: "compare working tree with remote (read-only)", cmd: tuiStartCompare()},
		{key: "S", label: "sync options…", dialog: m.syncOptionsDialog()},
		{key: "c", label: "checkpoint (named, never pruned)", dialog: m.checkpointDialog()},
		{key: "w", label: m.agentToggleLabel(), cmd: m.agentToggleCmd()},
	}
}

func (m *tuiModel) syncCmd() tea.Cmd { return tuiRequestExec("sync", m.ctx.root) }

func (m *tuiModel) syncOptionsDialog() tuiDialog {
	root := m.ctx.root
	return &tuiMenu{title: "Sync options", options: []tuiMenuOption{
		{key: "s", label: "sync (two-way)", cmd: m.syncCmd()},
		{key: "d", label: "dry-run — plan only, change nothing", cmd: tuiRequestExec("sync", root, "--dry-run")},
		{key: "c", label: "sync, keep conflict copies (conflicts=copy)", cmd: tuiRequestExec("sync", root, "--conflicts=copy")},
		{key: "u", label: "push only", cmd: tuiRequestExec("sync", root, "--push-only")},
		{key: "l", label: "pull only", cmd: tuiRequestExec("sync", root, "--pull-only")},
		{key: "r", label: "reconcile without a base", cmd: tuiRequestExec("sync", root, "--reconcile")},
		{key: "h", label: "rehash every file", cmd: tuiRequestExec("sync", root, "--rehash")},
		{key: "b", label: "accept server rollback and reconcile", dialog: &tuiConfirm{
			title:   "Accept server rollback",
			body:    "Proceed although the server is older than this device?\nThe trees are reconciled from scratch and differences become conflicts.",
			confirm: tuiRequestExec("sync", root, "--accept-rollback"),
		}},
		{key: "o", label: "offline status (skip server check)", cmd: tuiRequestExec("status", root, "--offline")},
		{key: "f", label: "force — local wins every conflict", dialog: &tuiConfirm{
			title:   "Force sync",
			body:    "Conflicting remote versions are discarded in favor of local files.",
			confirm: tuiRequestExec("sync", root, "--force"),
		}},
	}}
}

func (m *tuiModel) checkpointDialog() tuiDialog {
	root := m.ctx.root
	return tuiNewInput("Checkpoint", "name (e.g. before-refactor)", func(name string) tea.Cmd {
		return tuiRequestExec("checkpoint", name, root)
	})
}

func (m *tuiModel) snapshotsActions() []tuiMenuOption {
	var opts []tuiMenuOption
	if m.ctx.root != "" {
		opts = append(opts, tuiMenuOption{key: "n", label: "new snapshot (optional label)", dialog: m.newSnapshotDialog()})
	}
	snap := m.selectedSnapshot()
	if snap == nil {
		return opts
	}
	anchorLabel := "anchor (never pruned)"
	if snap.Anchored {
		anchorLabel = "unanchor"
	}
	opts = append(opts,
		tuiMenuOption{key: "d", label: "diff against live tree", cmd: tuiStartDiff(snap.ID)},
		tuiMenuOption{key: "a", label: anchorLabel, cmd: m.anchorCmd(*snap)},
		tuiMenuOption{key: "o", label: "restore side-by-side…", dialog: snapshotRestoreOutDialog(*snap)},
		tuiMenuOption{key: "e", label: "export plaintext…", dialog: snapshotExportDialog(*snap)},
		tuiMenuOption{key: "k", label: "retention prune…", dialog: snapshotRetentionDialog(*snap)},
		tuiMenuOption{key: "f", label: "list with time/limit filters…", dialog: snapshotListFiltersDialog(*snap)},
	)
	if m.ctx.root != "" {
		opts = append(opts, tuiMenuOption{key: "R", label: "restore in place", dialog: m.restoreDialog(*snap)})
	}
	opts = append(opts, tuiMenuOption{key: "x", label: "delete", dialog: m.deleteSnapshotDialog(*snap)})
	return opts
}

// selectedSnapshot is the snapshot row under the cursor, or nil.
func (m *tuiModel) selectedSnapshot() *snapshotRow {
	row := m.panels[tuiPanelSnapshots].list.current()
	if row == nil {
		return nil
	}
	if s, ok := row.tag.(snapshotRow); ok {
		return &s
	}
	return nil
}

func (m *tuiModel) newSnapshotDialog() tuiDialog {
	root := m.ctx.root
	in := tuiNewInput("New snapshot", "label (optional)", func(label string) tea.Cmd {
		args := []string{"snapshot", "create", root}
		if label != "" {
			args = append(args, label)
		}
		return tuiRequestExec(args...)
	})
	in.allowEmpty = true
	return in
}

func (m *tuiModel) anchorCmd(snap snapshotRow) tea.Cmd {
	if snap.Anchored {
		return tuiRequestExec("snapshot", "unanchor", snap.ID)
	}
	return tuiRequestExec("snapshot", "anchor", snap.ID)
}

func (m *tuiModel) restoreDialog(snap snapshotRow) tuiDialog {
	return &tuiConfirm{
		title: "Restore in place",
		body: fmt.Sprintf("Roll %s back to %q (version %d)?\nThe rollback syncs to every device.",
			tuiAbbrevHome(m.ctx.root), snap.displayName(), snap.Version),
		confirm: tuiRequestExec("restore", snap.ID, m.ctx.root, "--in-place", "-y"),
	}
}

func (m *tuiModel) deleteSnapshotDialog(snap snapshotRow) tuiDialog {
	body := fmt.Sprintf("Delete snapshot %q (version %d)?", snap.displayName(), snap.Version)
	if snap.Anchored {
		body += "\nIt is anchored; the server will refuse until it is unanchored (a)."
	}
	return &tuiConfirm{title: "Delete snapshot", body: body, confirm: tuiRequestExec("snapshot", "prune", snap.ID, "-y")}
}

func (m *tuiModel) resourcesActions() []tuiMenuOption {
	res := m.selectedResource()
	if res == nil {
		return nil
	}
	opts := []tuiMenuOption{
		{key: "y", label: func() string {
			if res.Visibility == string(api.Public) {
				return "copy public share link"
			}
			return "copy private aqt:// ref"
		}(), cmd: m.ctx.copyRefCmd(*res)},
	}
	if res.Kind != string(api.KindFolder) {
		opts = append(opts,
			tuiMenuOption{key: "o", label: "pull to disk…", dialog: m.pullDialog(*res)},
			tuiMenuOption{key: "v", label: "cat into command log", cmd: tuiRequestExec("cat", "aqt://"+res.ID)})
	}
	opts = append(opts,
		tuiMenuOption{key: "s", label: "share…", dialog: m.shareDialog(*res)},
		tuiMenuOption{key: "g", label: "grant read-only access…", dialog: grantDialog(*res)},
		tuiMenuOption{key: "r", label: "revoke account grant…", dialog: revokeGrantDialog(*res)},
		tuiMenuOption{key: "A", label: autoSnapshotLabel(*res), cmd: autoSnapshotCmd(*res)})
	if res.Kind == string(api.KindFolder) {
		opts = append(opts, tuiMenuOption{key: "c", label: "clone into a new directory…", dialog: resourceCloneDialog(*res, false)}, tuiMenuOption{key: "C", label: "clone and adopt an existing directory…", dialog: resourceCloneDialog(*res, true)})
	}
	if res.Visibility == string(api.Public) {
		opts = append(opts, tuiMenuOption{key: "p", label: "make private (rotates key, old links die)", dialog: m.makePrivateDialog(*res)})
	}
	opts = append(opts,
		tuiMenuOption{key: "x", label: "delete (keep snapshots)", dialog: m.deleteResourceDialog(*res)},
		tuiMenuOption{key: "X", label: "delete with every snapshot", dialog: deleteResourceWithSnapshotsDialog(*res)})
	return opts
}

// selectedResource is the resource row under the cursor, or nil.
func (m *tuiModel) selectedResource() *lsRow {
	row := m.panels[tuiPanelResources].list.current()
	if row == nil {
		return nil
	}
	if r, ok := row.tag.(lsRow); ok {
		return &r
	}
	return nil
}

func (m *tuiModel) shareDialog(res lsRow) tuiDialog {
	id := res.ID
	return &tuiMenu{title: "Share " + res.Name, options: []tuiMenuOption{
		{key: "s", label: "share — public link", cmd: tuiRequestExec("share", id)},
		{key: "d", label: "share for 24 hours", cmd: tuiRequestExec("share", id, "--expire", "24h")},
		{key: "w", label: "share for 7 days", cmd: tuiRequestExec("share", id, "--expire", "7d")},
		{key: "b", label: "burn after reading (one download)", cmd: tuiRequestExec("share", id, "--burn")},
		{key: "e", label: "custom expiry…", dialog: shareExpiryDialog(res)},
		{key: "n", label: "custom maximum downloads…", dialog: shareMaxReadsDialog(res)},
		{key: "g", label: "grant to an account…", dialog: grantDialog(res)},
		{key: "r", label: "revoke an account grant…", dialog: revokeGrantDialog(res)},
		{key: "p", label: "password-gated link…", dialog: tuiNewSecretInput(
			"Share password", "recipients need link and password", func(pw string) tea.Cmd {
				// Over stdin, not -P: argv is world-readable in ps, and a masked
				// prompt promising secrecy has to actually deliver it.
				return tuiRequestExecStdin(pw+"\n", "share", id, "--password-stdin")
			})},
	}}
}

func (m *tuiModel) makePrivateDialog(res lsRow) tuiDialog {
	return &tuiConfirm{
		title:   "Make private",
		body:    fmt.Sprintf("Rotate %q's content key? Existing share links stop working.", res.Name),
		confirm: tuiRequestExec("unshare", res.ID, "-y"),
	}
}

func (m *tuiModel) deleteResourceDialog(res lsRow) tuiDialog {
	return &tuiConfirm{
		title:   "Delete resource",
		body:    fmt.Sprintf("Delete %q from the server? Ciphertext and metadata are removed.", res.Name),
		confirm: tuiRequestExec("rm", res.ID, "-y"),
	}
}

// --- selection / focus plumbing ---

func (m *tuiModel) panel() *tuiPanel { return &m.panels[m.focus] }

func (m *tuiModel) setFocus(id tuiPanelID) {
	if id == m.focus {
		return
	}
	m.focus = id
	m.mainTab = tuiTabDetail
	m.onSelectionMoved()
}

// onSelectionMoved refreshes the detail pane and drops a stale snapshot diff.
func (m *tuiModel) onSelectionMoved() {
	if m.focus == tuiPanelSnapshots {
		if row := m.panel().list.current(); row != nil {
			if s, ok := row.tag.(snapshotRow); ok && s.ID != m.diffFor {
				m.diff, m.diffErr, m.diffing = nil, nil, false
				m.diffFor = ""
			}
		}
	}
	m.refreshMain()
}

func (m *tuiModel) toggleTab() {
	if m.mainTab == tuiTabDetail {
		m.mainTab = tuiTabLog
	} else {
		m.mainTab = tuiTabDetail
	}
	m.refreshMain()
}

// retireComparison drops a finished working-tree-versus-remote comparison when the
// local tree has been rescanned. The comparison is a point-in-time answer against a
// specific remote version, so once a sync, an action, or an edit has moved either
// side, keeping it would leave the panel showing two sections that contradict each
// other. A comparison still in flight is left to land and replace it.
func (m *tuiModel) retireComparison() {
	if !m.comparing {
		m.compared, m.compareErr = nil, nil
	}
}

func (m *tuiModel) refreshFocused() tea.Cmd {
	switch m.focus {
	case tuiPanelStatus:
		if m.ctx.root == "" {
			return m.ctx.devicesCmd()
		}
		return tea.Batch(m.ctx.remoteStatusCmd(), m.ctx.agentStatusCmd(), m.ctx.devicesCmd(), m.spin.Tick)
	case tuiPanelFiles:
		if m.ctx.root == "" {
			return nil
		}
		m.panels[tuiPanelFiles].loading = true
		return tea.Batch(m.ctx.localStatusCmd(), m.ctx.remoteStatusCmd(), m.spin.Tick)
	case tuiPanelSnapshots:
		m.panels[tuiPanelSnapshots].loading = true
		return tea.Batch(m.ctx.snapshotsCmd(), m.spin.Tick)
	case tuiPanelResources:
		m.panels[tuiPanelResources].loading = true
		return tea.Batch(m.ctx.resourcesCmd(), m.spin.Tick)
	}
	return nil
}

// --- panel row building ---

func (m *tuiModel) rebuildAll() {
	m.rebuildStatusPanel()
	m.rebuildFilesPanel()
	m.rebuildSnapshotsPanel()
	m.rebuildResourcesPanel()
}

// statusVerdict distills the folder's sync state into one severity-colored line:
// conflicts first, then pending work up/down, then a server problem, then clean.
// It stays honest before the first server reply by showing only what the local
// scan already knows.
func (m *tuiModel) statusVerdict() (string, lipgloss.Style) {
	localN := m.local.total()
	conflictN := len(m.conflicts)
	incomingN := 0
	if m.remoteOK && m.remote.fileLevel {
		incomingN = m.remote.incoming.total()
	}
	// Without an entry-level breakdown (no base, or the incoming diff failed) the
	// remote half reports only a version delta, so any note other than the
	// up-to-date one means the server holds more.
	coarseAhead := m.remoteOK && m.remote.err == nil && !m.remote.stale &&
		!m.remote.fileLevel && m.remote.note != "up to date with the server"

	if conflictN > 0 {
		noun := "conflict copies"
		if conflictN == 1 {
			noun = "conflict copy"
		}
		return fmt.Sprintf("! %d %s to resolve", conflictN, noun), tuiStyleConflict
	}

	if localN > 0 || incomingN > 0 || coarseAhead {
		var parts []string
		if localN > 0 {
			parts = append(parts, fmt.Sprintf("%d up", localN))
		}
		switch {
		case incomingN > 0:
			parts = append(parts, fmt.Sprintf("%d down", incomingN))
		case coarseAhead:
			parts = append(parts, "server ahead")
		}
		return "● needs sync — " + strings.Join(parts, " · "), tuiStyleMod
	}

	if !m.remoteOK {
		return "… checking server", tuiStyleDim
	}
	if m.remote.err != nil || m.remote.stale {
		return "! " + m.remote.note, tuiStyleErr
	}
	return "✓ in sync", tuiStyleAdd
}

func (m *tuiModel) rebuildStatusPanel() {
	var rows []tuiRow
	if m.ctx.root != "" {
		verdict, vstyle := m.statusVerdict()
		rows = append(rows,
			tuiRow{body: verdict, bodyStyle: vstyle, tag: "account"},
			tuiRow{body: tuiAbbrevHome(m.ctx.root), bodyStyle: tuiStyleTitle, tag: "account"},
			tuiRow{body: "aqt://" + m.folderID, bodyStyle: tuiStyleDim, tag: "account"},
		)
		fresh := "checking the server…"
		style := tuiStyleDim
		if m.remoteOK {
			fresh = m.remote.note
			switch {
			case m.remote.stale, m.remote.err != nil:
				style = tuiStyleErr
			case m.remote.incoming.total() > 0:
				style = tuiStyleMod
			default:
				style = tuiStyleAdd
			}
		}
		rows = append(rows, tuiRow{body: fresh, bodyStyle: style, tag: "account"})
		ag := "watch agent: not running"
		agStyle := tuiStyleDim
		if m.agent.running {
			ag = fmt.Sprintf("watch agent: running (pid %d)", m.agent.pid)
			agStyle = tuiStyleAdd
		}
		rows = append(rows, tuiRow{body: ag, bodyStyle: agStyle, tag: "account"})
	} else {
		rows = append(rows,
			tuiRow{body: "not inside a tracked folder", bodyStyle: tuiStyleDim, tag: "account"},
			tuiRow{body: "aqt init <dir> to track one", bodyStyle: tuiStyleDim, tag: "account"},
		)
	}
	rows = append(rows, tuiRow{
		body:      m.ctx.prof.Email + " @ " + m.ctx.prof.Server,
		bodyStyle: tuiStyleDim,
		tag:       "account",
	})
	m.panels[tuiPanelStatus].list.setRows(rows)
}

func (m *tuiModel) rebuildFilesPanel() {
	var rows []tuiRow
	if m.ctx.root == "" {
		m.panels[tuiPanelFiles].list.setRows([]tuiRow{
			{body: "not a tracked folder", bodyStyle: tuiStyleDim, header: true},
		})
		return
	}
	section := func(title string, n int) tuiRow {
		return tuiRow{body: fmt.Sprintf("%s (%d)", title, n), bodyStyle: tuiStyleTitle, header: true}
	}
	// incoming rows carry the "incoming" detail kind regardless of what changed;
	// local rows carry the change's own label so mode and type edits are named.
	addChanges := func(prefix, kindOverride string, changes []syncengine.Change) {
		for _, c := range orderedChanges(changes) {
			kind := kindOverride
			if kind == "" {
				kind = changeLabel(c.Kind)
			}
			rows = append(rows, tuiRow{
				mark:      prefix + changeMark(c.Kind),
				markStyle: tuiChangeStyle(c.Kind),
				body:      changePath(c),
				tag:       tuiFileItem{kind: kind, path: c.Path, dir: c.IsDir()},
			})
		}
	}

	rows = append(rows, section("Local changes", m.local.total()))
	if m.local.total() == 0 {
		rows = append(rows, tuiRow{body: "clean", bodyStyle: tuiStyleDim, header: true})
	}
	addChanges("", "", m.local.changes)
	for _, r := range m.local.renamed {
		rows = append(rows, tuiRow{
			mark:      "R",
			markStyle: tuiStyleMod,
			body:      renameArrow(r),
			tag:       tuiFileItem{kind: "renamed", path: renameArrow(r)},
		})
	}

	if m.remoteOK && m.remote.fileLevel {
		inc := m.remote.incoming
		rows = append(rows, section("Incoming", inc.total()))
		addChanges("↓", "incoming", inc.changes)
		for _, r := range inc.renamed {
			rows = append(rows, tuiRow{
				mark:      "↓R",
				markStyle: tuiStyleMod,
				body:      renameArrow(r),
				tag:       tuiFileItem{kind: "incoming", path: renameArrow(r)},
			})
		}
	}

	// The on-demand comparison against the current remote. Unlike the two sections
	// above it is not base-relative: it reports how the working tree and the server's
	// current state differ outright, which is why it renders as its own section
	// rather than being folded into either of them, and why retireComparison drops it
	// once the sections beside it have been rescanned.
	switch {
	case m.comparing:
		rows = append(rows,
			tuiRow{body: "Compared with remote", bodyStyle: tuiStyleTitle, header: true},
			tuiRow{body: "comparing…", bodyStyle: tuiStyleDim, header: true})
	case m.compareErr != nil:
		rows = append(rows,
			tuiRow{body: "Compared with remote", bodyStyle: tuiStyleTitle, header: true},
			tuiRow{body: "comparison failed: " + m.compareErr.Error(), bodyStyle: tuiStyleErr, header: true})
	case m.compared != nil:
		cmp := *m.compared
		rows = append(rows, section("Compared with "+cmp.Left.String(), cmp.total()))
		switch {
		case !cmp.Complete:
			rows = append(rows, tuiRow{body: comparisonUnavailable(cmp.Reason), bodyStyle: tuiStyleDim, header: true})
		case cmp.total() == 0:
			rows = append(rows, tuiRow{body: "identical", bodyStyle: tuiStyleDim, header: true})
		}
		addChanges("≠", "compared", cmp.Changes)
		for _, r := range cmp.Renamed {
			rows = append(rows, tuiRow{
				mark:      "≠R",
				markStyle: tuiStyleMod,
				body:      renameArrow(r),
				tag:       tuiFileItem{kind: "compared", path: renameArrow(r)},
			})
		}
	}

	if len(m.conflicts) > 0 {
		rows = append(rows, section("Conflict copies", len(m.conflicts)))
		for _, p := range m.conflicts {
			rows = append(rows, tuiRow{
				mark:      "!",
				markStyle: tuiStyleConflict,
				body:      p,
				tag:       tuiFileItem{kind: "conflict", path: p},
			})
		}
	}
	m.panels[tuiPanelFiles].list.setRows(rows)
}

func (m *tuiModel) rebuildSnapshotsPanel() {
	rows := make([]tuiRow, 0, len(m.snaps))
	for _, s := range m.snaps {
		// A space mark keeps unanchored rows aligned under the ★ column.
		mark, markStyle := " ", lipgloss.Style{}
		if s.Anchored {
			mark, markStyle = "★", tuiStyleAccent
		}
		rows = append(rows, tuiRow{
			mark:      mark,
			markStyle: markStyle,
			body:      s.Created + "  " + s.displayName(),
			tag:       s,
		})
	}
	if len(rows) == 0 {
		empty := "no snapshots yet"
		if m.ctx.root != "" {
			empty = "no snapshots — n creates one"
		}
		rows = append(rows, tuiRow{body: empty, bodyStyle: tuiStyleDim, header: true})
	}
	m.panels[tuiPanelSnapshots].list.setRows(rows)
}

func (m *tuiModel) rebuildResourcesPanel() {
	rows := make([]tuiRow, 0, len(m.resources))
	for _, r := range m.resources {
		// A resource carries one leading indicator: "/" for a folder or a filled
		// dot for a public file. The public dot must be its own segment (not a
		// trailing word) so its color survives the selection bar.
		mark, markStyle := "", lipgloss.Style{}
		size := ""
		if r.Kind == api.KindFolder {
			mark, markStyle = "/", tuiStyleAccent
		} else {
			size = "  " + cliutil.HumanBytes(r.Size)
			if r.Visibility == string(api.Public) {
				mark, markStyle = "●", tuiStylePublic
			}
		}
		rows = append(rows, tuiRow{
			mark:      mark,
			markStyle: markStyle,
			body:      r.Name + size,
			tag:       r,
		})
	}
	if len(rows) == 0 {
		rows = append(rows, tuiRow{body: "nothing pushed — aqt push <file>", bodyStyle: tuiStyleDim, header: true})
	}
	m.panels[tuiPanelResources].list.setRows(rows)
}

// --- main pane ---

func (m *tuiModel) refreshMain() {
	if m.w == 0 {
		return
	}
	m.vp.SetContent(m.mainContent())
	if m.mainTab == tuiTabLog {
		if m.logFollow {
			m.vp.GotoBottom()
		}
	} else {
		m.vp.GotoTop()
	}
}

// scrollLog routes a movement key to the log viewport and tracks follow mode: G
// (or scrolling back to the bottom) re-pins the tail, any move that leaves the
// bottom pauses it so the arriving lines stop yanking the view down.
func (m *tuiModel) scrollLog(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "G", "end":
		m.logFollow = true
		m.vp.GotoBottom()
		return nil
	case "g", "home":
		m.logFollow = false
		m.vp.GotoTop()
		return nil
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	m.logFollow = m.vp.AtBottom()
	return cmd
}

func (m *tuiModel) mainContent() string {
	if m.mainTab == tuiTabLog {
		return tuiLogView(m.log)
	}
	p := m.panel()
	if p.err != nil {
		return tuiStyleErr.Render("error: ") + p.err.Error()
	}
	switch m.focus {
	case tuiPanelStatus:
		return tuiAccountDetail(m.ctx, m.devices, m.devErr)
	case tuiPanelFiles:
		if row := p.list.current(); row != nil {
			if it, ok := row.tag.(tuiFileItem); ok {
				return tuiFileDetail(it, m.ctx.root)
			}
		}
		if m.ctx.root == "" {
			return tuiStyleDim.Render("Open the TUI inside a tracked folder (aqt init) to see and sync changes.")
		}
		return tuiStyleDim.Render("Working tree matches the last sync.")
	case tuiPanelSnapshots:
		if row := p.list.current(); row != nil {
			if s, ok := row.tag.(snapshotRow); ok {
				var diff *comparison
				var diffErr error
				diffing := false
				if s.ID == m.diffFor {
					diff, diffErr, diffing = m.diff, m.diffErr, m.diffing
				}
				return tuiSnapshotDetail(s, diff, diffErr, diffing)
			}
		}
		return tuiStyleDim.Render("No snapshots yet — press n to create one, or c in Files for a named checkpoint.")
	case tuiPanelResources:
		if row := p.list.current(); row != nil {
			if r, ok := row.tag.(lsRow); ok {
				return tuiResourceDetail(r)
			}
		}
		return tuiStyleDim.Render("Nothing pushed yet — `aqt push <file>` uploads an encrypted file.")
	}
	return ""
}

// --- view ---

func (m *tuiModel) View() string {
	if m.w == 0 || m.h == 0 {
		return ""
	}
	if !m.ctx.unlocked {
		return m.unlockView()
	}
	if m.w < 60 || m.h < 16 {
		return lipgloss.Place(m.w, m.h, lipgloss.Center, lipgloss.Center,
			tuiStyleDim.Render("terminal too small for the aqt TUI"))
	}
	left := m.leftColumn()
	main := m.mainBox()
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, main)
	screen := body + "\n" + m.bottomBar()
	if m.dialog != nil {
		// Composite the dialog centered over a dimmed copy of the layout, so the
		// context behind it stays visible (lazygit-style) instead of vanishing.
		return tuiOverlay(tuiDimBackground(screen), m.dialog.View(m.w), m.w, m.h)
	}
	return screen
}

func (m *tuiModel) leftWidth() int {
	lw := m.w / 3
	if lw < 30 {
		lw = 30
	}
	if lw > 46 {
		lw = 46
	}
	return lw
}

func (m *tuiModel) mainWidth() int { return m.w - m.leftWidth() }

// halfPage is half the focused panel's body height, for the page keys. It reads
// the live heights so the jump matches whatever the accordion currently shows.
func (m *tuiModel) halfPage() int {
	half := (m.panelHeights()[m.focus] - 2) / 2
	if half < 1 {
		half = 1
	}
	return half
}

// panelHeights splits the left column's outer height across its four boxes,
// accordion-style: the focused panel takes all the spare rows while the others
// collapse to just fit their contents. It is the single source of truth shared
// by the renderer (leftColumn), the mouse hit-tester (panelRanges), and the page
// keys, so they cannot drift.
func (m *tuiModel) panelHeights() [tuiPanelCount]int {
	total := m.h - 1 // the bottom bar owns the last row

	rowCount := func(id tuiPanelID) int { return len(m.panels[id].list.visibleRows()) }

	// A collapsed panel fits its rows up to a cap so a short list reserves no dead
	// space; the floor of 3 keeps the title and one row visible. Status is capped
	// lower still: its full detail lives in the main pane.
	fit := func(id tuiPanelID, cap int) int {
		h := rowCount(id) + 2
		if h > cap {
			h = cap
		}
		if h < 3 {
			h = 3
		}
		return h
	}

	// The spare rows go to the focused list, but not to Status (fixed detail) and
	// not while the main pane holds focus; in those cases the mode's primary list
	// grows instead.
	expand := m.focus
	if m.mainFocus || m.focus == tuiPanelStatus {
		if m.ctx.root != "" {
			expand = tuiPanelFiles
		} else {
			expand = tuiPanelResources
		}
	}

	var h [tuiPanelCount]int
	sum := 0
	for i := tuiPanelID(0); i < tuiPanelCount; i++ {
		if i == tuiPanelStatus {
			h[i] = fit(i, 6)
		} else {
			h[i] = fit(i, 5)
		}
		sum += h[i]
	}

	switch {
	case total-sum > 0:
		h[expand] += total - sum
	case total-sum < 0:
		// Not enough room: shrink the other panels to their floor first, then the
		// focused one, so the panel you are reading stays largest the longest.
		deficit := sum - total
		for i := tuiPanelID(0); i < tuiPanelCount && deficit > 0; i++ {
			if i == expand {
				continue
			}
			for h[i] > 3 && deficit > 0 {
				h[i]--
				deficit--
			}
		}
		if deficit > 0 {
			if h[expand] -= deficit; h[expand] < 1 {
				h[expand] = 1
			}
		}
	}
	return h
}

// panelRanges returns each left panel's outer [y0, y1) row span, stacked from
// the top with the same heights leftColumn draws.
func (m *tuiModel) panelRanges() [tuiPanelCount][2]int {
	h := m.panelHeights()
	var r [tuiPanelCount][2]int
	y := 0
	for i := 0; i < int(tuiPanelCount); i++ {
		r[i] = [2]int{y, y + h[i]}
		y += h[i]
	}
	return r
}

func (m *tuiModel) leftColumn() string {
	lw := m.leftWidth()
	h := m.panelHeights()
	boxes := make([]string, tuiPanelCount)
	for i := 0; i < int(tuiPanelCount); i++ {
		boxes[i] = m.panelBox(tuiPanelID(i), lw, h[i])
	}
	return lipgloss.JoinVertical(lipgloss.Left, boxes...)
}

// panelAt maps a screen cell to a left-column panel. A click in the main pane or
// on the bottom bar returns ok == false.
func (m *tuiModel) panelAt(x, y int) (tuiPanelID, bool) {
	if x >= m.leftWidth() {
		return 0, false
	}
	for i, r := range m.panelRanges() {
		if y >= r[0] && y < r[1] {
			return tuiPanelID(i), true
		}
	}
	return 0, false
}

func (m *tuiModel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if !m.ctx.unlocked || m.dialog != nil {
		return m, nil
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp, tea.MouseButtonWheelDown:
		delta := 1
		if msg.Button == tea.MouseButtonWheelUp {
			delta = -1
		}
		if id, ok := m.panelAt(msg.X, msg.Y); ok {
			m.panels[id].list.move(delta)
			if id == m.focus {
				m.onSelectionMoved()
			}
			return m, nil
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		if m.mainTab == tuiTabLog {
			m.logFollow = m.vp.AtBottom()
		}
		return m, cmd

	case tea.MouseButtonLeft:
		if msg.Action != tea.MouseActionPress {
			return m, nil
		}
		id, ok := m.panelAt(msg.X, msg.Y)
		if !ok {
			// A click in the main pane routes movement keys there.
			m.mainFocus = true
			m.refreshMain()
			return m, nil
		}
		m.mainFocus = false
		m.setFocus(id)
		// Map the row under the click, skipping the box border and header rows.
		r := m.panelRanges()[id]
		row := msg.Y - r[0] - 1
		if row >= 0 && row < m.panelHeights()[id]-2 {
			if m.panels[id].list.clickTo(row) {
				m.onSelectionMoved()
			}
		}
		return m, nil
	}
	return m, nil
}

func (m *tuiModel) panelBox(id tuiPanelID, width, height int) string {
	p := &m.panels[id]
	title := fmt.Sprintf("%d %s", int(id)+1, p.title)
	switch {
	case p.loading:
		title += " " + m.spin.View()
	case id == tuiPanelFiles && m.ctx.root != "":
		n := m.local.total() + len(m.conflicts)
		if m.remoteOK && m.remote.fileLevel {
			n += m.remote.incoming.total()
		}
		title += fmt.Sprintf(" %d", n)
	case id == tuiPanelSnapshots:
		title += fmt.Sprintf(" %d", len(m.snaps))
	case id == tuiPanelResources:
		title += fmt.Sprintf(" %d", len(m.resources))
	}
	// A load error keeps the last-good list visible; the full error is in the
	// detail pane, so the panel only flags it with a badge.
	if p.err != nil {
		title += " " + tuiStyleErr.Render("⚠")
	}
	bodyH := height - 2
	visible := len(p.list.visibleRows())
	filtering := p.list.filter != "" && id == m.focus
	if filtering {
		title += tuiStyleDim.Render(fmt.Sprintf(" /%s %d", p.list.filter, visible))
	}
	body := p.list.render(width-2, bodyH, m.focus == id && !m.mainFocus)
	switch {
	case filtering && visible == 0:
		body = tuiStyleDim.Render("no matches")
	case visible > bodyH:
		// Scroll position, so an overflowing list says where the cursor sits.
		title += tuiStyleDim.Render(fmt.Sprintf(" ‹%d/%d›", p.list.cursor+1, visible))
	}
	return tuiBox(title, body, width, height, m.focus == id)
}

func (m *tuiModel) mainBox() string {
	title := m.detailTitle()
	if m.mainTab == tuiTabLog {
		title = "Log"
		if m.logFollow {
			title += tuiStyleDim.Render(" · following")
		} else {
			title += tuiStyleDim.Render(" · paused — G to follow")
		}
		if m.execCh != nil {
			title += " " + m.spin.View() + " " + tuiStyleDim.Render(m.execTitle)
		}
	}
	m.vp.Width = m.mainWidth() - 2
	m.vp.Height = m.h - 3
	if m.vp.TotalLineCount() > m.vp.Height {
		title += " " + tuiStyleDim.Render(fmt.Sprintf("%d%%", int(m.vp.ScrollPercent()*100)))
	}
	return tuiBox(title, m.vp.View(), m.mainWidth(), m.h-1, m.mainFocus)
}

// detailTitle is the detail pane's breadcrumb: Details · <Panel> · <selection>,
// narrowing gracefully as the pane shrinks.
func (m *tuiModel) detailTitle() string {
	segs := []string{"Details", m.panels[m.focus].title}
	if row := m.panel().list.current(); row != nil {
		segs = append(segs, row.text())
	}
	// Leave room for the box's "╭─ " lead, one trailing "─╮", and the title's
	// surrounding spaces.
	budget := m.mainWidth() - 6
	if budget < 8 {
		budget = 8
	}
	return tuiBreadcrumb(segs, budget)
}

// tuiBreadcrumb joins plain segments with " · " to fit width: the final segment
// is truncated first, then trailing segments are dropped right-to-left so the
// panel name outlives the selection on a narrow pane.
func tuiBreadcrumb(segs []string, width int) string {
	const sep = " · "
	for len(segs) > 1 {
		if lipgloss.Width(strings.Join(segs, sep)) <= width {
			return strings.Join(segs, sep)
		}
		head := strings.Join(segs[:len(segs)-1], sep)
		if room := width - lipgloss.Width(head) - len(sep); room >= 4 {
			return head + sep + tuiEllipsis(segs[len(segs)-1], room)
		}
		segs = segs[:len(segs)-1]
	}
	return tuiEllipsis(segs[0], width)
}

// tuiEllipsis truncates plain (unstyled) text to width cells, marking the cut
// with a trailing ellipsis.
func tuiEllipsis(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > width {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

func (m *tuiModel) bottomBar() string {
	if m.filtering {
		return tuiPadTrunc(m.filterIn.View(), m.w)
	}
	var hints []string
	if m.mainFocus {
		hints = []string{tuiKeyHint("j/k", "scroll"), tuiKeyHint("esc", "back"), tuiKeyHint("@", "log")}
	} else {
		// Only advertise actions the focused panel can actually run right now: the
		// files actions need a tracked folder, and the per-item actions need a
		// selected row.
		switch m.focus {
		case tuiPanelStatus:
			hints = []string{tuiKeyHint("u", "push file"), tuiKeyHint("d", "devices")}
		case tuiPanelFiles:
			if m.ctx.root != "" {
				hints = []string{tuiKeyHint("s", "sync"), tuiKeyHint("u/d", "push/pull"), tuiKeyHint("S", "sync…"), tuiKeyHint("C", "compare"), tuiKeyHint("w", "agent")}
			}
		case tuiPanelSnapshots:
			if m.ctx.root != "" {
				hints = append(hints, tuiKeyHint("n", "new"))
			}
			if m.panels[tuiPanelSnapshots].list.current() != nil {
				hints = append(hints, tuiKeyHint("d", "diff"), tuiKeyHint("o", "restore"), tuiKeyHint("a", "anchor"), tuiKeyHint("x", "delete"))
			}
		case tuiPanelResources:
			if m.panels[tuiPanelResources].list.current() != nil {
				hints = []string{tuiKeyHint("o", "pull"), tuiKeyHint("g", "grant"), tuiKeyHint("s", "share"), tuiKeyHint("x", "delete")}
			}
		}
		hints = append(hints, tuiKeyHint("tab", "panel"), tuiKeyHint("/", "filter"))
		if m.hasActions() {
			hints = append(hints, tuiKeyHint("space", "actions"))
		}
		hints = append(hints, tuiKeyHint("?", "help"), tuiKeyHint("q", "quit"))
	}
	if m.execBusy {
		hints = append(hints, tuiKeyHint("ctrl+x", "cancel"))
	}
	bar := strings.Join(hints, tuiStyleDim.Render(" · "))
	if m.statusLine != "" {
		status := m.statusStyle.Render(m.statusLine)
		gap := m.w - lipgloss.Width(bar) - lipgloss.Width(status) - 1
		if gap > 0 {
			return bar + strings.Repeat(" ", gap) + status + " "
		}
	}
	return tuiPadTrunc(bar, m.w)
}

func (m *tuiModel) unlockView() string {
	var body strings.Builder
	body.WriteString(tuiStyleDim.Render(m.ctx.prof.Email+" @ "+m.ctx.prof.Server) + "\n\n")
	if m.unlocking {
		body.WriteString(m.spin.View() + " deriving key (Argon2id)…")
	} else {
		body.WriteString(m.unlockIn.View())
	}
	if m.unlockErr != nil {
		// Unlock has no sentinel for a bad passphrase (the AEAD tag just fails to
		// verify), so lead with the likely cause and show the real error under it
		// in case it is actually an infrastructure fault (keychain, file read).
		body.WriteString("\n\n" + tuiStyleErr.Render("unlock failed — wrong passphrase?"))
		body.WriteString("\n" + tuiStyleDim.Render(m.unlockErr.Error()))
	}
	body.WriteString("\n\n" + tuiKeyHint("enter", "unlock") + "  " + tuiKeyHint("esc", "quit"))
	box := tuiDialogBox("Session locked", body.String(), min(m.w, 70))
	return lipgloss.Place(m.w, m.h, lipgloss.Center, lipgloss.Center, box)
}

// tuiAbbrevHome shortens a path under $HOME to ~/… for display.
func tuiAbbrevHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
		if rel == "." {
			return "~"
		}
		return "~/" + rel
	}
	return path
}
