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
	if cmd != nil {
		t.Fatal("busy model must reject the request without a command")
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
