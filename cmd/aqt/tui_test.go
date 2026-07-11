package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aquitano/aqt-sync/internal/identity"
)

func key(s string) tea.KeyMsg {
	if len(s) == 1 {
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEscape}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "ctrl+x":
		return tea.KeyMsg{Type: tea.KeyCtrlX}
	case "ctrl+d":
		return tea.KeyMsg{Type: tea.KeyCtrlD}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	}
	panic("unknown key " + s)
}

// testModel returns an unlocked model with canned panel data and a laid-out
// window, ready for key routing without any network or filesystem.
func testModel(t *testing.T) *tuiModel {
	t.Helper()
	ctx := &tuiCtx{
		prof:     &identity.Profile{Name: "t", Email: "t@example.com", Server: "http://localhost:8080"},
		unlocked: true,
		root:     "/tmp/vault",
		exe:      "/bin/aqt-test",
	}
	m := newTUIModel(ctx, "fold_1", nil)
	m.resources = []lsRow{
		{ID: "r1", Name: "notes.md", Kind: "file", Size: 100, Visibility: "private", Version: 1},
		{ID: "r2", Name: "deploy.log", Kind: "file", Size: 200, Visibility: "public", Version: 3},
		{ID: "r3", Name: "vault", Kind: "folder", Visibility: "private", Version: 9},
	}
	m.snaps = []snapshotRow{
		{ID: "s1", ResourceID: "fold_1", Name: "vault", Label: "pre-release", Anchored: true, Version: 4, Created: "2026-07-10 12:00"},
		{ID: "s2", ResourceID: "fold_1", Name: "vault", Version: 5, Created: "2026-07-11 09:00"},
	}
	m.local = localChanges{added: []string{"new.txt"}, modified: []string{"mod.txt"}}
	m.conflicts = []string{"a.txt.conflict-host-1"}
	m.rebuildAll()
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return m
}

func TestTUIPanelNavigation(t *testing.T) {
	m := testModel(t)
	if m.focus != tuiPanelFiles {
		t.Fatalf("initial focus = %v, want files", m.focus)
	}
	m.handleKey(key("tab"))
	if m.focus != tuiPanelSnapshots {
		t.Fatalf("after tab focus = %v, want snapshots", m.focus)
	}
	m.handleKey(key("shift+tab"))
	m.handleKey(key("shift+tab"))
	if m.focus != tuiPanelStatus {
		t.Fatalf("after 2x shift+tab focus = %v, want status", m.focus)
	}
	m.handleKey(key("4"))
	if m.focus != tuiPanelResources {
		t.Fatalf("after '4' focus = %v, want resources", m.focus)
	}
}

func TestTUIListSkipsHeadersAndKeepsSelection(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelFiles)
	l := &m.panels[tuiPanelFiles].list
	cur := l.current()
	if cur == nil {
		t.Fatal("no selection after rebuild")
	}
	if it := cur.tag.(tuiFileItem); it.path != "new.txt" {
		t.Fatalf("first selectable = %q, want new.txt (headers skipped)", it.path)
	}
	l.move(1)
	if it := l.current().tag.(tuiFileItem); it.path != "mod.txt" {
		t.Fatalf("after move = %q, want mod.txt", it.path)
	}
	// A refresh with the same data must not move the cursor.
	m.rebuildFilesPanel()
	if it := l.current().tag.(tuiFileItem); it.path != "mod.txt" {
		t.Fatalf("after rebuild = %q, want mod.txt kept", it.path)
	}
	// Cursor never rests on the trailing conflict header when moving down past
	// the end.
	l.end()
	if it := l.current().tag.(tuiFileItem); it.kind != "conflict" {
		t.Fatalf("end selects %q, want the conflict row", it.kind)
	}
}

func TestTUIListFilter(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelResources)
	l := &m.panels[tuiPanelResources].list
	l.setFilter("deploy")
	rows := l.visibleRows()
	if len(rows) != 1 {
		t.Fatalf("filtered rows = %d, want 1", len(rows))
	}
	if r := l.current().tag.(lsRow); r.ID != "r2" {
		t.Fatalf("filtered selection = %s, want r2", r.ID)
	}
	l.setFilter("")
	if len(l.visibleRows()) != 3 {
		t.Fatal("clearing the filter must restore all rows")
	}
}

func TestTUIResourceActionsOpenDialogs(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelResources)

	// r1 (private): share opens the menu, p is a no-op with a note.
	m.handleKey(key("s"))
	if _, ok := m.dialog.(*tuiMenu); !ok {
		t.Fatalf("s should open the share menu, got %T", m.dialog)
	}
	m.handleKey(key("esc"))
	if m.dialog != nil {
		t.Fatal("esc must close the dialog")
	}
	m.handleKey(key("p"))
	if m.dialog != nil {
		t.Fatal("p on a private resource must not open a dialog")
	}

	// r2 (public): p asks for confirmation; y resolves it with a command.
	m.panels[tuiPanelResources].list.move(1)
	m.handleKey(key("p"))
	c, ok := m.dialog.(*tuiConfirm)
	if !ok {
		t.Fatalf("p on a public resource should confirm, got %T", m.dialog)
	}
	if c.confirm == nil {
		t.Fatal("confirm dialog carries no command")
	}
	_, model := m.handleKey(key("n"))
	_ = model
	if m.dialog != nil {
		t.Fatal("n must cancel the confirm")
	}

	// r3 (folder): share is refused before any dialog.
	m.panels[tuiPanelResources].list.move(1)
	m.handleKey(key("s"))
	if m.dialog != nil {
		t.Fatal("folders cannot be shared; no dialog expected")
	}
	if !strings.Contains(m.statusLine, "folder") {
		t.Fatalf("statusLine = %q, want a folder note", m.statusLine)
	}
}

func TestTUISnapshotAnchorArgs(t *testing.T) {
	// The anchored snapshot toggles off with --remove; the plain one without.
	if got := tuiExecArgs([]string{"snapshot", "anchor", "s1", "--remove"}); strings.Join(got, " ") != "snapshot anchor s1 --remove" {
		t.Fatalf("unexpected args %v", got)
	}
}

func TestTUIExecArgsCarryGlobalFlags(t *testing.T) {
	oldServer, oldProfile := flagServer, flagProfile
	defer func() { flagServer, flagProfile = oldServer, oldProfile }()

	flagServer, flagProfile = "", ""
	if got := tuiExecArgs([]string{"sync", "/v"}); len(got) != 2 {
		t.Fatalf("no overrides expected, got %v", got)
	}
	flagServer, flagProfile = "http://s:1", "work"
	got := tuiExecArgs([]string{"sync", "/v"})
	want := "sync /v --server http://s:1 --profile work"
	if strings.Join(got, " ") != want {
		t.Fatalf("args = %v, want %q", got, want)
	}
}

func TestTUIExitNotes(t *testing.T) {
	for exit, frag := range map[int]string{
		0: "done", 3: "session", 4: "conflict", 5: "network", 6: "upgrade", 7: "gone", 9: "exit 9",
	} {
		if note := tuiExitNote(exit); !strings.Contains(note, frag) {
			t.Errorf("exit %d note %q missing %q", exit, note, frag)
		}
	}
}

func TestTUIBoxGeometry(t *testing.T) {
	box := tuiBox("Files", "a\nb", 30, 6, true)
	lines := strings.Split(box, "\n")
	if len(lines) != 6 {
		t.Fatalf("box has %d lines, want 6", len(lines))
	}
	for i, l := range lines {
		if w := lipgloss.Width(l); w != 30 {
			t.Errorf("line %d width = %d, want 30", i, w)
		}
	}
	if !strings.Contains(box, "Files") {
		t.Error("title missing from box")
	}
}

func TestTUIViewSmoke(t *testing.T) {
	m := testModel(t)
	for _, id := range []tuiPanelID{tuiPanelStatus, tuiPanelFiles, tuiPanelSnapshots, tuiPanelResources} {
		m.setFocus(id)
		out := m.View()
		if out == "" {
			t.Fatalf("empty view for panel %d", id)
		}
		lines := strings.Split(out, "\n")
		if len(lines) != 30 {
			t.Fatalf("panel %d view has %d lines, want 30", id, len(lines))
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > 100 {
				t.Fatalf("panel %d line %d overflows: %d > 100", id, i, w)
			}
		}
	}
	// Help overlay and log tab render too.
	m.handleKey(key("?"))
	if m.View() == "" {
		t.Fatal("empty help view")
	}
	m.handleKey(key("esc"))
	m.handleKey(key("@"))
	if m.mainTab != tuiTabLog {
		t.Fatal("@ must switch to the log tab")
	}
}

func TestTUIBusyGuardsActions(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelFiles)

	// The action key resolves to a request message; the busy guard lives in
	// Update, synchronously, so a second request cannot start a subprocess even
	// before the first one's started-message arrives.
	_, cmd := m.handleKey(key("s"))
	if cmd == nil {
		t.Fatal("s should produce an exec request")
	}
	req, ok := cmd().(tuiExecRequestMsg)
	if !ok {
		t.Fatalf("s produced %T, want tuiExecRequestMsg", cmd())
	}
	if strings.Join(req.sub, " ") != "sync /tmp/vault" {
		t.Fatalf("request args = %v", req.sub)
	}

	m.execBusy = true
	_, cmd = m.Update(req)
	// The rejection posts a toast (its expiry tick), never a subprocess start.
	if _, ok := cmd().(tuiToastExpiredMsg); !ok {
		t.Fatalf("busy rejection produced %T, want a toast tick", cmd())
	}
	if !strings.Contains(m.statusLine, "already running") {
		t.Fatalf("statusLine = %q, want busy note", m.statusLine)
	}
}

// A clean tracked folder renders a headers-only files list; moving the cursor
// backwards through it must not walk past the end (regression: index panic).
func TestTUIHeadersOnlyListNoPanic(t *testing.T) {
	m := testModel(t)
	m.local = localChanges{}
	m.conflicts = nil
	m.rebuildFilesPanel()
	m.setFocus(tuiPanelFiles)
	for _, k := range []string{"k", "j", "G", "g"} {
		m.handleKey(key(k))
	}
	if cur := m.panels[tuiPanelFiles].list.current(); cur != nil {
		t.Fatalf("headers-only list reports a selection: %+v", cur)
	}
	if m.View() == "" {
		t.Fatal("empty view")
	}
}

func TestTUIOverlayGeometry(t *testing.T) {
	// A styled base grid: every cell carries a background so a naive splice would
	// bleed that style into the dialog region.
	bg := lipgloss.NewStyle().Background(lipgloss.Color("236"))
	const w, h = 40, 12
	var lines []string
	for i := 0; i < h; i++ {
		lines = append(lines, bg.Render(strings.Repeat("x", w)))
	}
	base := strings.Join(lines, "\n")
	top := "ABC\nDEF"

	out := tuiOverlay(base, top, w, h)
	got := strings.Split(out, "\n")
	if len(got) != h {
		t.Fatalf("overlay line count = %d, want %d", len(got), h)
	}
	for i, l := range got {
		if lw := lipgloss.Width(l); lw != w {
			t.Fatalf("overlay line %d width = %d, want %d", i, lw, w)
		}
	}
	// The dialog text survives verbatim (no escape codes spliced into it).
	if !strings.Contains(out, "ABC") || !strings.Contains(out, "DEF") {
		t.Fatal("dialog content missing from overlay")
	}
	// Rows outside the vertical span of top are copied unchanged.
	if got[0] != lines[0] {
		t.Fatal("first base row must be untouched")
	}
}

func TestTUIListClickTo(t *testing.T) {
	var l tuiList
	l.setRows([]tuiRow{
		{body: "head", header: true},
		{body: "one", tag: "one"},
		{body: "two", tag: "two"},
		{body: "three", tag: "three"},
	})
	// clickTo honors the scroll offset: view row 0 maps to rows[offset].
	l.offset = 2
	if !l.clickTo(1) {
		t.Fatal("clickTo(1) at offset 2 should select a row")
	}
	if l.current().tag != "three" {
		t.Fatalf("selected %v, want three", l.current().tag)
	}
	// Headers and out-of-range rows are ignored.
	l.offset = 0
	if l.clickTo(0) {
		t.Fatal("clicking a header must not select")
	}
	if l.clickTo(99) {
		t.Fatal("clicking past the last row must not select")
	}
}

func TestTUIMouseFocusAndSelect(t *testing.T) {
	m := testModel(t) // 100x30 window
	m.setFocus(tuiPanelResources)

	// Positions come from panelRanges so the test tracks the accordion layout.
	// The files list is section header, A new.txt, M mod.txt: the third content
	// row is "M mod.txt".
	filesTop := m.panelRanges()[tuiPanelFiles][0]
	modY := filesTop + 1 + 2 // border, then the third (0-based row 2) content row
	if id, ok := m.panelAt(3, modY); !ok || id != tuiPanelFiles {
		t.Fatalf("panelAt(3,%d) = %v,%v, want files", modY, id, ok)
	}
	m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 3, Y: modY})
	if m.focus != tuiPanelFiles {
		t.Fatalf("click focus = %v, want files", m.focus)
	}
	if it := m.panels[tuiPanelFiles].list.current().tag.(tuiFileItem); it.path != "mod.txt" {
		t.Fatalf("clicked row = %q, want mod.txt", it.path)
	}

	// A click past the left column lands in the main pane.
	m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 80, Y: 10})
	if !m.mainFocus {
		t.Fatal("click in the main pane must set mainFocus")
	}
}

func TestTUIMouseWheelMovesPanelUnderCursor(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelResources) // r1 selected
	// Wheel down over the resources panel advances its cursor without the main
	// viewport stealing the event.
	resTop := m.panelRanges()[tuiPanelResources][0]
	m.handleMouse(tea.MouseMsg{Button: tea.MouseButtonWheelDown, X: 3, Y: resTop + 1})
	if r := m.panels[tuiPanelResources].list.current().tag.(lsRow); r.ID != "r2" {
		t.Fatalf("wheel selection = %s, want r2", r.ID)
	}
}

func TestTUIToastExpirySeq(t *testing.T) {
	m := testModel(t)
	cmd := m.toast("first")
	if _, ok := cmd().(tuiToastExpiredMsg); !ok {
		t.Fatal("toast must schedule an expiry tick")
	}
	m.toast("second") // supersedes the first

	// The stale tick (seq 1) must not clear the current toast.
	m.Update(tuiToastExpiredMsg{seq: 1})
	if m.statusLine != "second" {
		t.Fatalf("stale tick cleared the line: %q", m.statusLine)
	}
	m.Update(tuiToastExpiredMsg{seq: m.toastSeq})
	if m.statusLine != "" {
		t.Fatalf("matching tick left %q, want cleared", m.statusLine)
	}
}

func TestTUICancelConfirmFlow(t *testing.T) {
	m := testModel(t)

	// ctrl+x is inert unless an action is running.
	m.handleKey(key("ctrl+x"))
	if m.dialog != nil {
		t.Fatal("ctrl+x while idle must not open a dialog")
	}

	m.execBusy = true
	m.execTitle = "aqt sync /tmp/vault"
	m.handleKey(key("ctrl+x"))
	c, ok := m.dialog.(*tuiConfirm)
	if !ok {
		t.Fatalf("ctrl+x while busy opened %T, want confirm", m.dialog)
	}
	if !strings.Contains(c.title, "Cancel") {
		t.Fatalf("confirm title = %q, want a cancel prompt", c.title)
	}
	// Confirming resolves to a cancel command.
	_, cmd := m.handleKey(key("y"))
	if cmd == nil {
		t.Fatal("y should produce the cancel command")
	}
	if _, ok := cmd().(tuiCancelExecMsg); !ok {
		t.Fatalf("cancel produced %T, want tuiCancelExecMsg", cmd())
	}
}

// The quit confirm must not capture the running child's pid: the action can
// finish (and be reaped) while the dialog sits open, and signalling a reaped pid
// can hit an unrelated process once the pid is reused.
func TestTUIQuitConfirmDoesNotCapturePid(t *testing.T) {
	m := testModel(t)
	m.execBusy = true
	m.execTitle = "aqt snapshot restore --in-place"

	m.quitOrConfirm()
	c, ok := m.dialog.(*tuiConfirm)
	if !ok {
		t.Fatalf("quit while busy opened %T, want confirm", m.dialog)
	}
	if _, ok := c.confirm().(tuiKillAndQuitMsg); !ok {
		t.Fatalf("quit confirm resolved to %T, want tuiKillAndQuitMsg", c.confirm())
	}

	// The action completes while the dialog is still open, so the child is gone.
	m.Update(tuiExecDoneMsg{title: m.execTitle, exit: 0})
	if m.execBusy || m.execCmd != nil {
		t.Fatal("done should have cleared the action state")
	}
	// Confirming now must still quit, and must not signal the reaped pid.
	if _, cmd := m.Update(tuiKillAndQuitMsg{}); cmd == nil {
		t.Fatal("kill-and-quit after the action finished should still quit")
	}
	if m.execCanceled {
		t.Fatal("kill-and-quit signalled a child that had already been reaped")
	}
}

func TestTUIAccordionHeights(t *testing.T) {
	m := testModel(t) // 100x30

	sum := func() int {
		h := m.panelHeights()
		total := 0
		for _, v := range h {
			total += v
		}
		return total
	}

	// The heights always tile the left column exactly (bottom bar owns one row).
	if got, want := sum(), m.h-1; got != want {
		t.Fatalf("heights sum = %d, want %d", got, want)
	}

	// The focused list swallows the spare rows; every other panel collapses.
	m.setFocus(tuiPanelResources)
	h := m.panelHeights()
	for id := tuiPanelStatus; id < tuiPanelCount; id++ {
		if id == tuiPanelResources {
			continue
		}
		if h[id] > 6 {
			t.Fatalf("unfocused panel %d = %d outer rows, want it collapsed (<=6)", id, h[id])
		}
		if h[tuiPanelResources] <= h[id] {
			t.Fatalf("focused resources (%d) not larger than panel %d (%d)", h[tuiPanelResources], id, h[id])
		}
	}

	// Focus follows the expansion: switching panels moves the tall box.
	m.setFocus(tuiPanelSnapshots)
	if h := m.panelHeights(); h[tuiPanelSnapshots] <= h[tuiPanelResources] {
		t.Fatalf("after focusing snapshots it (%d) should exceed resources (%d)", h[tuiPanelSnapshots], h[tuiPanelResources])
	}

	// Focus on the main pane hands the spare rows to the mode's primary list
	// (Files here, since the model has a tracked root).
	m.mainFocus = true
	if h := m.panelHeights(); h[tuiPanelFiles] <= h[tuiPanelSnapshots] {
		t.Fatalf("main-focus should grow files (%d) over snapshots (%d)", h[tuiPanelFiles], h[tuiPanelSnapshots])
	}
}

func TestTUIAccordionSmallTerminalFloor(t *testing.T) {
	m := testModel(t)
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 16}) // the documented minimum

	h := m.panelHeights()
	sum := 0
	for id, v := range h {
		if v < 3 {
			t.Fatalf("panel %d floored below the title+row minimum: %d", id, v)
		}
		sum += v
	}
	if sum != m.h-1 {
		t.Fatalf("small-terminal heights sum = %d, want %d", sum, m.h-1)
	}
	if m.View() == "" {
		t.Fatal("empty view at 60x16")
	}
}

func TestTUITitleScrollIndicator(t *testing.T) {
	m := testModel(t)
	// Overflow the resources panel so its box cannot show every row at once.
	var many []lsRow
	for i := 0; i < 50; i++ {
		many = append(many, lsRow{ID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("file%02d", i), Kind: "file", Visibility: "private", Version: 1})
	}
	m.resources = many
	m.rebuildResourcesPanel()
	m.setFocus(tuiPanelResources)

	h := m.panelHeights()
	box := m.panelBox(tuiPanelResources, m.leftWidth(), h[tuiPanelResources])
	if !strings.Contains(box, "‹") {
		t.Fatal("overflowing panel title should carry a ‹cursor/n› scroll indicator")
	}

	// A filter narrows the list and the title reports the match count.
	m.panels[tuiPanelResources].list.setFilter("file0")
	box = m.panelBox(tuiPanelResources, m.leftWidth(), h[tuiPanelResources])
	if !strings.Contains(box, "/file0") {
		t.Fatal("filtered title should echo the query")
	}

	// A filter with no hits says so in the body.
	m.panels[tuiPanelResources].list.setFilter("nomatch-xyz")
	box = m.panelBox(tuiPanelResources, m.leftWidth(), h[tuiPanelResources])
	if !strings.Contains(box, "no matches") {
		t.Fatal("an empty filter result should show a 'no matches' line")
	}
}

func TestTUIPageKeysMoveByHalfPage(t *testing.T) {
	m := testModel(t)
	var many []lsRow
	for i := 0; i < 50; i++ {
		many = append(many, lsRow{ID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("file%02d", i), Kind: "file", Visibility: "private", Version: 1})
	}
	m.resources = many
	m.rebuildResourcesPanel()
	m.setFocus(tuiPanelResources)

	l := &m.panels[tuiPanelResources].list
	l.home()
	if l.cursor != 0 {
		t.Fatalf("home cursor = %d, want 0", l.cursor)
	}
	half := m.halfPage()
	if half < 1 {
		t.Fatalf("halfPage = %d, want >= 1", half)
	}
	m.handleKey(key("ctrl+d"))
	if l.cursor != half {
		t.Fatalf("ctrl+d cursor = %d, want %d", l.cursor, half)
	}
	m.handleKey(key("ctrl+u"))
	if l.cursor != 0 {
		t.Fatalf("ctrl+u cursor = %d, want back to 0", l.cursor)
	}
}

func TestTUIRedactSecrets(t *testing.T) {
	got := joinArgs(redactSecrets([]string{"share", "id1", "-P", "hunter2"}))
	if strings.Contains(got, "hunter2") {
		t.Fatalf("password leaked into title: %q", got)
	}
	if !strings.Contains(got, "•••") {
		t.Fatalf("expected mask in %q", got)
	}
}

func TestTUIStatusVerdict(t *testing.T) {
	m := testModel(t)

	// Conflicts outrank pending local changes.
	m.local = localChanges{added: []string{"a"}}
	m.conflicts = []string{"x.conflict-h-1", "y.conflict-h-1"}
	m.remoteOK = true
	m.remote = tuiRemoteMsg{note: "up to date with the server"}
	txt, style := m.statusVerdict()
	if !strings.Contains(txt, "2 conflict copies") || !strings.Contains(txt, "resolve") {
		t.Fatalf("conflict verdict = %q", txt)
	}
	if style.GetForeground() != tuiStyleConflict.GetForeground() {
		t.Fatal("conflict verdict not conflict-styled")
	}

	// Local + file-level incoming reads as pending in both directions.
	m.conflicts = nil
	m.local = localChanges{added: []string{"a", "b"}}
	m.remote = tuiRemoteMsg{fileLevel: true, incoming: incomingSummary{added: []string{"c"}}}
	txt, style = m.statusVerdict()
	if txt != "● needs sync — 2 up · 1 down" {
		t.Fatalf("needs-sync verdict = %q", txt)
	}
	if style.GetForeground() != tuiStyleMod.GetForeground() {
		t.Fatal("needs-sync verdict not mod-styled")
	}

	// A pack folder only knows the server is ahead, not by which files.
	m.local = localChanges{}
	m.remote = tuiRemoteMsg{note: "server is ahead by 2 version(s)"}
	if txt, _ = m.statusVerdict(); txt != "● needs sync — server ahead" {
		t.Fatalf("coarse-ahead verdict = %q", txt)
	}

	// A server problem with nothing local surfaces the note.
	m.remote = tuiRemoteMsg{err: errors.New("boom"), note: "server check failed"}
	txt, style = m.statusVerdict()
	if txt != "! server check failed" {
		t.Fatalf("error verdict = %q", txt)
	}
	if style.GetForeground() != tuiStyleErr.GetForeground() {
		t.Fatal("error verdict not err-styled")
	}

	// Clean and confirmed.
	m.remote = tuiRemoteMsg{note: "up to date with the server"}
	txt, style = m.statusVerdict()
	if txt != "✓ in sync" {
		t.Fatalf("clean verdict = %q", txt)
	}
	if style.GetForeground() != tuiStyleAdd.GetForeground() {
		t.Fatal("clean verdict not add-styled")
	}

	// Before the first server reply, with nothing local.
	m.remoteOK = false
	m.remote = tuiRemoteMsg{}
	txt, style = m.statusVerdict()
	if txt != "… checking server" {
		t.Fatalf("checking verdict = %q", txt)
	}
	if style.GetForeground() != tuiStyleDim.GetForeground() {
		t.Fatal("checking verdict not dim-styled")
	}

	// Before the reply but with local changes, the local-only verdict still shows.
	m.local = localChanges{modified: []string{"z"}}
	if txt, _ = m.statusVerdict(); txt != "● needs sync — 1 up" {
		t.Fatalf("local-only verdict = %q", txt)
	}
}

func TestTUIBottomBarGating(t *testing.T) {
	// Account mode: the files panel has no tracked folder, so no sync action and
	// no actions menu should be advertised.
	ctx := &tuiCtx{
		prof:     &identity.Profile{Name: "t", Email: "t@example.com", Server: "http://localhost:8080"},
		unlocked: true,
		exe:      "/bin/aqt-test",
	}
	m := newTUIModel(ctx, "fold_1", nil)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m.setFocus(tuiPanelFiles)
	bar := m.bottomBar()
	if strings.Contains(bar, "sync") {
		t.Fatalf("account-mode files bar advertises sync: %q", bar)
	}
	if strings.Contains(bar, "actions") {
		t.Fatalf("account-mode files bar advertises an empty actions menu: %q", bar)
	}

	// Inside a tracked folder the sync hint returns.
	if fm := testModel(t); !strings.Contains(fm.bottomBar(), "sync") {
		t.Fatal("folder-mode files bar should advertise sync")
	}
}

func TestTUIBreadcrumbTitle(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelFiles)
	title := m.detailTitle()
	for _, want := range []string{"Details", "Files", "new.txt"} {
		if !strings.Contains(title, want) {
			t.Fatalf("detail title %q missing %q", title, want)
		}
	}

	// A narrow pane drops trailing segments right-to-left, keeping the head.
	got := tuiBreadcrumb([]string{"Details", "Files", "a-very-long-selection-name"}, 18)
	if lipgloss.Width(got) > 18 {
		t.Fatalf("breadcrumb %q exceeds width 18", got)
	}
	if !strings.Contains(got, "Details") {
		t.Fatalf("breadcrumb dropped the head: %q", got)
	}
}

func TestTUILogFollowPauseResume(t *testing.T) {
	m := testModel(t)
	for i := 0; i < 100; i++ {
		m.appendLog(fmt.Sprintf("line %d", i))
	}
	m.mainTab = tuiTabLog
	m.logFollow = true
	m.refreshMain()
	if !strings.Contains(m.mainBox(), "following") {
		t.Fatal("log title should show 'following' while pinned to the tail")
	}

	// A manual scroll up pauses follow so arriving lines stop yanking the view.
	m.handleKey(key("k"))
	if m.logFollow {
		t.Fatal("scrolling up must pause follow")
	}
	if !strings.Contains(m.mainBox(), "paused") {
		t.Fatal("paused title expected after scrolling up")
	}

	// G re-pins to the tail.
	m.handleKey(key("G"))
	if !m.logFollow {
		t.Fatal("G must resume follow")
	}
	if !strings.Contains(m.mainBox(), "following") {
		t.Fatal("following title expected after G")
	}
}

func TestTUIConflictOriginalAndDetail(t *testing.T) {
	for in, want := range map[string]string{
		"notes.md.conflict-laptop-20260711-120000":   "notes.md",
		"a/b.txt.conflict-desktop-20260711-120000-2": "a/b.txt",
		"plain.txt": "plain.txt",
	} {
		if got := tuiConflictOriginal(in); got != want {
			t.Errorf("tuiConflictOriginal(%q) = %q, want %q", in, got, want)
		}
	}

	out := tuiFileDetail(tuiFileItem{kind: "conflict", path: "notes.md.conflict-host-20260711-120000"}, "/tmp/vault")
	for _, want := range []string{"yours", "notes.md", "kept alongside your version"} {
		if !strings.Contains(out, want) {
			t.Fatalf("conflict detail missing %q:\n%s", want, out)
		}
	}
}

func TestTUISpaceMenuActions(t *testing.T) {
	m := testModel(t)

	// A private file offers copy/share/delete but not make-private.
	m.setFocus(tuiPanelResources)
	m.handleKey(key(" "))
	menu, ok := m.dialog.(*tuiMenu)
	if !ok {
		t.Fatalf("space opened %T, want a menu", m.dialog)
	}
	if !strings.Contains(menu.title, "Resources") {
		t.Fatalf("menu title = %q, want a Resources heading", menu.title)
	}
	if ks := menuKeys(menu); ks != "y,s,x" {
		t.Fatalf("private resource menu keys = %q, want y,s,x", ks)
	}
	m.handleKey(key("esc"))

	// A public resource adds the make-private entry.
	m.panels[tuiPanelResources].list.move(1)
	m.handleKey(key(" "))
	if ks := menuKeys(m.dialog.(*tuiMenu)); ks != "y,s,p,x" {
		t.Fatalf("public resource menu keys = %q, want y,s,p,x", ks)
	}
	m.handleKey(key("esc"))

	// Files: sync, sync options, checkpoint — and selecting sync reuses the exact
	// command the s key dispatches.
	m.setFocus(tuiPanelFiles)
	m.handleKey(key(" "))
	filesMenu := m.dialog.(*tuiMenu)
	if ks := menuKeys(filesMenu); ks != "s,S,c" {
		t.Fatalf("files menu keys = %q, want s,S,c", ks)
	}
	cmd, done := filesMenu.Update(key("s"))
	if !done || cmd == nil {
		t.Fatal("selecting sync should resolve the menu with a command")
	}
	req, ok := cmd().(tuiExecRequestMsg)
	if !ok || strings.Join(req.sub, " ") != "sync /tmp/vault" {
		t.Fatalf("sync entry produced %#v", cmd())
	}
}

func menuKeys(m *tuiMenu) string {
	ks := make([]string, 0, len(m.options))
	for _, o := range m.options {
		ks = append(ks, o.key)
	}
	return strings.Join(ks, ",")
}

func TestTUIConflictCopies(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"a.txt", "b.txt.conflict-host-20260711", "sub/c.conflict-x-1"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := tuiConflictCopies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("conflict copies = %v, want 2 entries", got)
	}
}
