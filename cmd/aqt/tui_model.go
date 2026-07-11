package main

import (
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
	local     localChanges
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
	diff    *snapshotDiffResult
	diffErr error
	diffing bool

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
	log          []string

	fsEvents <-chan struct{}
	fsSeq    int

	spin       spinner.Model
	statusLine string
	// toastSeq tags each transient status line so its expiry tick only clears
	// the line it was scheduled for, never a newer one.
	toastSeq int
}

// tuiToastExpiredMsg fires a few seconds after a status line is set.
type tuiToastExpiredMsg struct{ seq int }

// toast sets the transient status line and returns the command that clears it
// once it has had its moment. Callers that already return a command should batch
// this alongside it.
func (m *tuiModel) toast(s string) tea.Cmd {
	m.statusLine = s
	m.toastSeq++
	seq := m.toastSeq
	return tea.Tick(4*time.Second, func(time.Time) tea.Msg { return tuiToastExpiredMsg{seq: seq} })
}

func newTUIModel(ctx *tuiCtx, folderID string, fsEvents <-chan struct{}) *tuiModel {
	m := &tuiModel{ctx: ctx, folderID: folderID, fsEvents: fsEvents, focus: tuiPanelFiles}
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
	cmds := []tea.Cmd{m.reloadPanels(), m.ctx.devicesCmd()}
	if m.fsEvents != nil {
		cmds = append(cmds, tuiWaitFs(m.fsEvents))
	}
	return tea.Batch(cmds...)
}

// reloadPanels refreshes every data panel: the initial load, and again after
// each action (which may have moved data on both sides).
func (m *tuiModel) reloadPanels() tea.Cmd {
	cmds := []tea.Cmd{m.ctx.resourcesCmd(), m.ctx.snapshotsCmd(), m.spin.Tick}
	m.panels[tuiPanelResources].loading = true
	m.panels[tuiPanelSnapshots].loading = true
	if m.ctx.root != "" {
		cmds = append(cmds, m.ctx.localStatusCmd(), m.ctx.remoteStatusCmd(), m.ctx.agentStatusCmd())
		m.panels[tuiPanelFiles].loading = true
	}
	return tea.Batch(cmds...)
}

func (m *tuiModel) busy() bool {
	if m.execBusy || m.diffing || m.unlocking {
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
		return m, m.initialLoads()

	case tuiLocalMsg:
		m.panels[tuiPanelFiles].loading = false
		m.panels[tuiPanelFiles].err = msg.err
		if msg.err == nil {
			m.local, m.conflicts = msg.changes, msg.conflicts
		}
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

	case tuiCopiedMsg:
		note := "copied: " + msg.ref
		if !msg.ok {
			note = "clipboard unavailable — " + msg.ref
		}
		cmd := m.toast(note)
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
		return m, tuiExecCmd(m.ctx.exe, msg.sub)

	case tuiExecStartedMsg:
		m.execCh = msg.ch
		m.execCmd = msg.cmd
		m.execTitle = msg.title
		m.appendLog(tuiStyleAccent.Render("$ " + msg.title))
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
		var note string
		switch {
		case canceled:
			note = "canceled"
			m.appendLog(tuiStyleErr.Render("✗ canceled"))
		case msg.exit == 0:
			note = tuiExitNote(msg.exit)
			m.appendLog(tuiStyleAdd.Render("✓ " + note))
		default:
			note = tuiExitNote(msg.exit)
			m.appendLog(tuiStyleErr.Render("✗ " + note))
		}
		m.refreshMain()
		return m, tea.Batch(m.toast(note), m.reloadPanels())

	case tuiCancelExecMsg:
		if m.execBusy && m.execCmd != nil && m.execCmd.Process != nil {
			m.execCanceled = true
			_ = terminateAgent(m.execCmd.Process.Pid)
		}
		return m, nil

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
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "q":
		return m.quitOrConfirm()
	case "?":
		m.dialog = &tuiHelp{}
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

// quitOrConfirm quits immediately when idle; while an action subprocess runs it
// asks first — quitting tears down the output pipes and would kill e.g. a
// restore mid-swap. ctrl+c stays an unconditional exit.
func (m *tuiModel) quitOrConfirm() (tea.Model, tea.Cmd) {
	if !m.execBusy {
		return m, tea.Quit
	}
	m.dialog = &tuiConfirm{
		title:   "Action running",
		body:    m.execTitle + "\nis still running. Quit anyway and kill it?",
		confirm: tuiKillAndQuit(m.execCmd),
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

// handleActionKey dispatches the focused panel's contextual actions. Mutating
// actions resolve to tuiExecRequestMsg, where the busy guard lives; read-only
// ones (copy, diff) stay usable while an action runs.
func (m *tuiModel) handleActionKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.focus {
	case tuiPanelFiles:
		return m.filesAction(msg)
	case tuiPanelSnapshots:
		return m.snapshotsAction(msg)
	case tuiPanelResources:
		return m.resourcesAction(msg)
	}
	return m, nil
}

func (m *tuiModel) filesAction(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.ctx.root == "" {
		return m, nil
	}
	root := m.ctx.root
	switch msg.String() {
	case "s":
		return m, tuiRequestExec("sync", root)
	case "S":
		m.dialog = &tuiMenu{title: "Sync options", options: []tuiMenuOption{
			{key: "s", label: "sync (two-way)", cmd: tuiRequestExec("sync", root)},
			{key: "d", label: "dry-run — plan only, change nothing", cmd: tuiRequestExec("sync", root, "--dry-run")},
			{key: "c", label: "sync, keep conflict copies (conflicts=copy)", cmd: tuiRequestExec("sync", root, "--conflicts=copy")},
			{key: "u", label: "push only", cmd: tuiRequestExec("sync", root, "--push-only")},
			{key: "l", label: "pull only", cmd: tuiRequestExec("sync", root, "--pull-only")},
			{key: "f", label: "force — local wins every conflict", cmd: func() tea.Msg {
				return tuiOpenDialogMsg{dialog: &tuiConfirm{
					title:   "Force sync",
					body:    "Conflicting remote versions are discarded in favor of local files.",
					confirm: tuiRequestExec("sync", root, "--force"),
				}}
			}},
		}}
		return m, nil
	case "c":
		m.dialog = tuiNewInput("Checkpoint", "name (e.g. before-refactor)", func(name string) tea.Cmd {
			return tuiRequestExec("checkpoint", name, root)
		})
		return m, textinput.Blink
	}
	return m, nil
}

func (m *tuiModel) snapshotsAction(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	row := m.panel().list.current()
	var snap *snapshotRow
	if row != nil {
		if s, ok := row.tag.(snapshotRow); ok {
			snap = &s
		}
	}
	switch msg.String() {
	case "n":
		if m.ctx.root == "" {
			return m, m.toast("open the TUI inside a tracked folder to create snapshots")
		}
		root := m.ctx.root
		in := tuiNewInput("New snapshot", "label (optional)", func(label string) tea.Cmd {
			args := []string{"snapshot", "create", root}
			if label != "" {
				args = append(args, "-l", label)
			}
			return tuiRequestExec(args...)
		})
		in.allowEmpty = true
		m.dialog = in
		return m, textinput.Blink
	}
	if snap == nil {
		return m, nil
	}
	switch msg.String() {
	case "d":
		m.diffFor = snap.ID
		m.diff, m.diffErr, m.diffing = nil, nil, true
		m.refreshMain()
		return m, tea.Batch(m.ctx.diffCmd(snap.ID), m.spin.Tick)
	case "a":
		args := []string{"snapshot", "anchor", snap.ID}
		if snap.Anchored {
			args = append(args, "--remove")
		}
		return m, tuiRequestExec(args...)
	case "R":
		if m.ctx.root == "" {
			return m, m.toast("in-place restore needs a tracked folder — use `aqt snapshot restore --into` instead")
		}
		m.dialog = &tuiConfirm{
			title: "Restore in place",
			body: fmt.Sprintf("Roll %s back to %q (version %d)?\nThe rollback syncs to every device.",
				tuiAbbrevHome(m.ctx.root), snap.displayName(), snap.Version),
			confirm: tuiRequestExec("snapshot", "restore", snap.ID, "--in-place", "--dir", m.ctx.root, "-y"),
		}
		return m, nil
	case "x":
		body := fmt.Sprintf("Delete snapshot %q (version %d)?", snap.displayName(), snap.Version)
		if snap.Anchored {
			body += "\nIt is anchored; the server will refuse until it is unanchored (a)."
		}
		m.dialog = &tuiConfirm{
			title:   "Delete snapshot",
			body:    body,
			confirm: tuiRequestExec("snapshot", "prune", snap.ID, "-y"),
		}
		return m, nil
	}
	return m, nil
}

func (m *tuiModel) resourcesAction(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	row := m.panel().list.current()
	if row == nil {
		return m, nil
	}
	res, ok := row.tag.(lsRow)
	if !ok {
		return m, nil
	}
	switch msg.String() {
	case "y":
		return m, m.ctx.copyRefCmd(res)
	case "s":
		if res.Kind == api.KindFolder {
			return m, m.toast("folders cannot be shared publicly yet")
		}
		id := res.ID
		m.dialog = &tuiMenu{title: "Share " + res.Name, options: []tuiMenuOption{
			{key: "s", label: "share — public link", cmd: tuiRequestExec("share", id)},
			{key: "d", label: "share for 24 hours", cmd: tuiRequestExec("share", id, "--expire", "24h")},
			{key: "w", label: "share for 7 days", cmd: tuiRequestExec("share", id, "--expire", "7d")},
			{key: "b", label: "burn after reading (one download)", cmd: tuiRequestExec("share", id, "--burn")},
			{key: "p", label: "password-gated link…", cmd: func() tea.Msg {
				in := tuiNewInput("Share password", "recipients need link and password", func(pw string) tea.Cmd {
					return tuiRequestExec("share", id, "-P", pw)
				})
				in.input.EchoMode = textinput.EchoPassword
				return tuiOpenDialogMsg{dialog: in}
			}},
		}}
		return m, nil
	case "p":
		if res.Visibility != string(api.Public) {
			return m, m.toast("already private")
		}
		m.dialog = &tuiConfirm{
			title:   "Make private",
			body:    fmt.Sprintf("Rotate %q's content key? Existing share links stop working.", res.Name),
			confirm: tuiRequestExec("private", res.ID),
		}
		return m, nil
	case "x":
		m.dialog = &tuiConfirm{
			title:   "Delete resource",
			body:    fmt.Sprintf("Delete %q from the server? Ciphertext and metadata are removed.", res.Name),
			confirm: tuiRequestExec("rm", res.ID),
		}
		return m, nil
	}
	return m, nil
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

func (m *tuiModel) rebuildStatusPanel() {
	var rows []tuiRow
	if m.ctx.root != "" {
		rows = append(rows,
			tuiRow{text: tuiAbbrevHome(m.ctx.root), styled: tuiStyleTitle.Render(tuiAbbrevHome(m.ctx.root)), tag: "account"},
			tuiRow{text: "aqt://" + m.folderID, styled: tuiStyleDim.Render("aqt://" + m.folderID), tag: "account"},
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
		rows = append(rows, tuiRow{text: fresh, styled: style.Render(fresh), tag: "account"})
		ag := "watch agent: not running"
		agStyled := tuiStyleDim.Render(ag)
		if m.agent.running {
			ag = fmt.Sprintf("watch agent: running (pid %d)", m.agent.pid)
			agStyled = tuiStyleAdd.Render(ag)
		}
		rows = append(rows, tuiRow{text: ag, styled: agStyled, tag: "account"})
	} else {
		rows = append(rows,
			tuiRow{text: "not inside a tracked folder", styled: tuiStyleDim.Render("not inside a tracked folder"), tag: "account"},
			tuiRow{text: "aqt init <dir> to track one", styled: tuiStyleDim.Render("aqt init <dir> to track one"), tag: "account"},
		)
	}
	rows = append(rows, tuiRow{
		text:   m.ctx.prof.Email + " @ " + m.ctx.prof.Server,
		styled: tuiStyleDim.Render(m.ctx.prof.Email + " @ " + m.ctx.prof.Server),
		tag:    "account",
	})
	m.panels[tuiPanelStatus].list.setRows(rows)
}

func (m *tuiModel) rebuildFilesPanel() {
	var rows []tuiRow
	if m.ctx.root == "" {
		m.panels[tuiPanelFiles].list.setRows(rows)
		return
	}
	section := func(title string, n int) tuiRow {
		t := fmt.Sprintf("%s (%d)", title, n)
		return tuiRow{text: t, styled: tuiStyleTitle.Render(t), header: true}
	}
	addPaths := func(kind, mark string, style lipgloss.Style, paths []string) {
		for _, p := range paths {
			rows = append(rows, tuiRow{
				text:   mark + " " + p,
				styled: style.Render(mark) + " " + p,
				tag:    tuiFileItem{kind: kind, path: p},
			})
		}
	}

	rows = append(rows, section("Local changes", m.local.total()))
	if m.local.total() == 0 {
		rows = append(rows, tuiRow{text: "clean", styled: tuiStyleDim.Render("clean"), header: true})
	}
	addPaths("new", "A", tuiStyleAdd, m.local.added)
	addPaths("modified", "M", tuiStyleMod, m.local.modified)
	addPaths("deleted", "D", tuiStyleDel, m.local.deleted)
	for _, r := range m.local.renamed {
		rows = append(rows, tuiRow{
			text:   "R " + renameArrow(r),
			styled: tuiStyleMod.Render("R") + " " + renameArrow(r),
			tag:    tuiFileItem{kind: "renamed", path: renameArrow(r)},
		})
	}

	if m.remoteOK && m.remote.fileLevel {
		inc := m.remote.incoming
		rows = append(rows, section("Incoming", inc.total()))
		addIncoming := func(mark string, style lipgloss.Style, paths []string) {
			for _, p := range paths {
				rows = append(rows, tuiRow{
					text:   "↓" + mark + " " + p,
					styled: style.Render("↓"+mark) + " " + p,
					tag:    tuiFileItem{kind: "incoming", path: p},
				})
			}
		}
		addIncoming("A", tuiStyleAdd, inc.added)
		addIncoming("M", tuiStyleMod, inc.modified)
		addIncoming("D", tuiStyleDel, inc.deleted)
		for _, r := range inc.renamed {
			rows = append(rows, tuiRow{
				text:   "↓R " + renameArrow(r),
				styled: tuiStyleMod.Render("↓R") + " " + renameArrow(r),
				tag:    tuiFileItem{kind: "incoming", path: renameArrow(r)},
			})
		}
	}

	if len(m.conflicts) > 0 {
		rows = append(rows, section("Conflict copies", len(m.conflicts)))
		for _, p := range m.conflicts {
			rows = append(rows, tuiRow{
				text:   "! " + p,
				styled: tuiStyleConflict.Render("!") + " " + p,
				tag:    tuiFileItem{kind: "conflict", path: p},
			})
		}
	}
	m.panels[tuiPanelFiles].list.setRows(rows)
}

func (m *tuiModel) rebuildSnapshotsPanel() {
	rows := make([]tuiRow, 0, len(m.snaps))
	for _, s := range m.snaps {
		name := s.displayName()
		mark, markStyled := "  ", "  "
		if s.Anchored {
			mark, markStyled = "★ ", tuiStyleAccent.Render("★ ")
		}
		text := fmt.Sprintf("%s%s  %s", mark, s.Created, name)
		styled := markStyled + tuiStyleDim.Render(s.Created) + "  " + name
		rows = append(rows, tuiRow{text: text, styled: styled, tag: s})
	}
	m.panels[tuiPanelSnapshots].list.setRows(rows)
}

func (m *tuiModel) rebuildResourcesPanel() {
	rows := make([]tuiRow, 0, len(m.resources))
	for _, r := range m.resources {
		vis, visStyled := "", ""
		if r.Visibility == string(api.Public) {
			vis, visStyled = " public", tuiStylePublic.Render(" public")
		}
		size := ""
		if r.Kind != api.KindFolder {
			size = "  " + humanBytes(r.Size)
		}
		kind := ""
		if r.Kind == api.KindFolder {
			kind = "/ "
		}
		text := kind + r.Name + size + vis
		styled := tuiStyleAccent.Render(kind) + r.Name + tuiStyleDim.Render(size) + visStyled
		rows = append(rows, tuiRow{text: text, styled: styled, tag: r})
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
		m.vp.GotoBottom()
	} else {
		m.vp.GotoTop()
	}
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
				return tuiFileDetail(it)
			}
		}
		if m.ctx.root == "" {
			return tuiStyleDim.Render("Open the TUI inside a tracked folder (aqt init) to see and sync changes.")
		}
		return tuiStyleDim.Render("Working tree matches the last sync.")
	case tuiPanelSnapshots:
		if row := p.list.current(); row != nil {
			if s, ok := row.tag.(snapshotRow); ok {
				var diff *snapshotDiffResult
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

// panelHeights splits the left column's outer height across its four boxes. It
// is the single source of truth shared by the renderer (leftColumn) and the
// mouse hit-tester, so the two cannot drift.
func (m *tuiModel) panelHeights() [tuiPanelCount]int {
	total := m.h - 1
	statusH := 7
	rest := total - statusH
	filesH := rest * 4 / 10
	snapsH := rest * 3 / 10
	resH := rest - filesH - snapsH
	return [tuiPanelCount]int{statusH, filesH, snapsH, resH}
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
		title += fmt.Sprintf(" %d", m.local.total()+len(m.conflicts))
	case id == tuiPanelSnapshots:
		title += fmt.Sprintf(" %d", len(m.snaps))
	case id == tuiPanelResources:
		title += fmt.Sprintf(" %d", len(m.resources))
	}
	if p.list.filter != "" && id == m.focus {
		title += tuiStyleDim.Render(" /" + p.list.filter)
	}
	body := p.list.render(width-2, height-2, m.focus == id && !m.mainFocus)
	if p.err != nil {
		body = tuiStyleErr.Render(tuiTrunc("error: "+p.err.Error(), width-2))
	}
	return tuiBox(title, body, width, height, m.focus == id)
}

func (m *tuiModel) mainBox() string {
	title := "Details"
	if m.mainTab == tuiTabLog {
		title = "Log"
		if m.execCh != nil {
			title += " " + m.spin.View() + " " + tuiStyleDim.Render(m.execTitle)
		}
	}
	m.vp.Width = m.mainWidth() - 2
	m.vp.Height = m.h - 3
	return tuiBox(title, m.vp.View(), m.mainWidth(), m.h-1, m.mainFocus)
}

func (m *tuiModel) bottomBar() string {
	if m.filtering {
		return tuiPadTrunc(m.filterIn.View(), m.w)
	}
	var hints []string
	if m.mainFocus {
		hints = []string{tuiKeyHint("j/k", "scroll"), tuiKeyHint("esc", "back"), tuiKeyHint("@", "log")}
	} else {
		switch m.focus {
		case tuiPanelFiles:
			hints = []string{tuiKeyHint("s", "sync"), tuiKeyHint("S", "sync…"), tuiKeyHint("c", "checkpoint")}
		case tuiPanelSnapshots:
			hints = []string{tuiKeyHint("d", "diff"), tuiKeyHint("n", "new"), tuiKeyHint("a", "anchor"), tuiKeyHint("R", "restore"), tuiKeyHint("x", "delete")}
		case tuiPanelResources:
			hints = []string{tuiKeyHint("y", "copy ref"), tuiKeyHint("s", "share"), tuiKeyHint("p", "private"), tuiKeyHint("x", "delete")}
		}
		hints = append(hints, tuiKeyHint("tab", "panel"), tuiKeyHint("/", "filter"), tuiKeyHint("?", "help"), tuiKeyHint("q", "quit"))
	}
	if m.execBusy {
		hints = append(hints, tuiKeyHint("ctrl+x", "cancel"))
	}
	bar := strings.Join(hints, tuiStyleDim.Render(" · "))
	if m.statusLine != "" {
		status := tuiStyleAccent.Render(m.statusLine)
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
		body.WriteString("\n\n" + tuiStyleErr.Render("unlock failed — wrong passphrase?"))
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
