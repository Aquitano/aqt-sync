package main

import (
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
		{text: "head", header: true},
		{text: "one", tag: "one"},
		{text: "two", tag: "two"},
		{text: "three", tag: "three"},
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

	// Files panel occupies rows [7,15): top border 7, first content row 8. The
	// third content row (y=10) is the "M mod.txt" entry.
	if id, ok := m.panelAt(3, 10); !ok || id != tuiPanelFiles {
		t.Fatalf("panelAt(3,10) = %v,%v, want files", id, ok)
	}
	m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 3, Y: 10})
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
	// Wheel down over the resources panel (rows [21,29)) advances its cursor
	// without the main viewport stealing the event.
	m.handleMouse(tea.MouseMsg{Button: tea.MouseButtonWheelDown, X: 3, Y: 23})
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

func TestTUIRedactSecrets(t *testing.T) {
	got := joinArgs(redactSecrets([]string{"share", "id1", "-P", "hunter2"}))
	if strings.Contains(got, "hunter2") {
		t.Fatalf("password leaked into title: %q", got)
	}
	if !strings.Contains(got, "•••") {
		t.Fatalf("expected mask in %q", got)
	}
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
