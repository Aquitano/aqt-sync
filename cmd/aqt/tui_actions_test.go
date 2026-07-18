package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/aquitano/aqt-sync/internal/api"
)

func tuiRequestArgs(t *testing.T, cmd tea.Cmd) []string {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected command")
	}
	req, ok := cmd().(tuiExecRequestMsg)
	if !ok {
		t.Fatalf("command produced %T, want tuiExecRequestMsg", cmd())
	}
	return req.sub
}

func menuCommand(t *testing.T, menu *tuiMenu, want string) tea.Cmd {
	t.Helper()
	for _, option := range menu.options {
		if option.key == want {
			return option.cmd
		}
	}
	t.Fatalf("menu %q has no %q option", menu.title, want)
	return nil
}

func TestTUIIssue92SingleKeyActions(t *testing.T) {
	m := testModel(t)

	m.setFocus(tuiPanelFiles)
	_, cmd := m.handleKey(key("u"))
	if got := strings.Join(tuiRequestArgs(t, cmd), " "); got != "sync /tmp/vault --push-only" {
		t.Fatalf("push-only args = %q", got)
	}
	_, cmd = m.handleKey(key("d"))
	if got := strings.Join(tuiRequestArgs(t, cmd), " "); got != "sync /tmp/vault --pull-only" {
		t.Fatalf("pull-only args = %q", got)
	}

	m.setFocus(tuiPanelStatus)
	m.handleKey(key("u"))
	if _, ok := m.dialog.(*tuiInput); !ok {
		t.Fatalf("status u opened %T, want push path input", m.dialog)
	}

	m.dialog = nil
	m.devices = []api.Device{{ID: "dev-2", Name: "laptop"}, {ID: "dev-1", Name: "current", Current: true}}
	m.handleKey(key("d"))
	devices, ok := m.dialog.(*tuiMenu)
	if !ok || menuKeys(devices) != "1,2" {
		t.Fatalf("device action opened %#v", m.dialog)
	}
	openConfirm := menuCommand(t, devices, "2")().(tuiOpenDialogMsg)
	confirm := openConfirm.dialog.(*tuiConfirm)
	if !strings.Contains(confirm.body, "current device") {
		t.Fatalf("self-revoke warning missing: %q", confirm.body)
	}
	if got := strings.Join(tuiRequestArgs(t, confirm.confirm), " "); got != "devices rm dev-1 --yes" {
		t.Fatalf("device revoke args = %q", got)
	}
}

func TestTUIIssue92ResourceActions(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelResources)
	res := *m.selectedResource()

	grant := grantDialog(res).(*tuiInput)
	grant.input.SetValue("bob@example.com")
	cmd, done := grant.Update(key("enter"))
	if !done {
		t.Fatal("grant input did not close")
	}
	if got := strings.Join(tuiRequestArgs(t, cmd), " "); got != "share r1 --with bob@example.com" {
		t.Fatalf("grant args = %q", got)
	}

	expiryMsg := menuCommand(t, m.shareDialog(res).(*tuiMenu), "e")().(tuiOpenDialogMsg)
	expiry := expiryMsg.dialog.(*tuiInput)
	expiry.input.SetValue("90m")
	cmd, done = expiry.Update(key("enter"))
	if !done {
		t.Fatal("expiry input did not close")
	}
	if got := strings.Join(tuiRequestArgs(t, cmd), " "); got != "share r1 --expire 90m" {
		t.Fatalf("custom expiry args = %q", got)
	}

	cascade := deleteResourceWithSnapshotsDialog(res).(*tuiConfirm)
	if got := strings.Join(tuiRequestArgs(t, cascade.confirm), " "); got != "rm r1 --with-snapshots --yes" {
		t.Fatalf("cascade delete args = %q", got)
	}

	auto := res
	auto.AutoSnapshot = true
	if got := strings.Join(tuiRequestArgs(t, autoSnapshotCmd(auto)), " "); got != "snapshot auto --id r1 --off" {
		t.Fatalf("auto snapshot args = %q", got)
	}

	m.panels[tuiPanelResources].list.end()
	folderMenu := m.resourcesActions()
	keys := make([]string, 0, len(folderMenu))
	for _, option := range folderMenu {
		keys = append(keys, option.key)
	}
	if got := strings.Join(keys, ","); !strings.Contains(got, "c,C") {
		t.Fatalf("folder menu lacks clone/adopt: %q", got)
	}
}

func TestTUIIssue92SnapshotActions(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelSnapshots)
	snap := *m.selectedSnapshot()
	if got := menuKeys(&tuiMenu{options: m.snapshotsActions()}); got != "n,d,a,o,e,k,f,R,x" {
		t.Fatalf("snapshot actions = %q", got)
	}

	restore := snapshotRestoreOutDialog(snap).(*tuiInput)
	restore.input.SetValue("/tmp/restored")
	cmd, done := restore.Update(key("enter"))
	if !done {
		t.Fatal("restore input did not close")
	}
	if got := strings.Join(tuiRequestArgs(t, cmd), " "); got != "restore s1 --out /tmp/restored" {
		t.Fatalf("side-by-side restore args = %q", got)
	}

	filterMenu := snapshotListFiltersDialog(snap).(*tuiMenu)
	if got := menuKeys(filterMenu); got != "l,s,b" {
		t.Fatalf("snapshot filter menu = %q", got)
	}
	retentionMenu := snapshotRetentionDialog(snap).(*tuiMenu)
	if got := menuKeys(retentionMenu); got != "k,o" {
		t.Fatalf("snapshot retention menu = %q", got)
	}
}

func TestTUIIssue92AccountMenu(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelStatus)
	if got := menuKeys(&tuiMenu{options: m.statusActions()}); got != "u,i,c,h,o,U,d" {
		t.Fatalf("account actions = %q", got)
	}

	cloneFirst := m.cloneDialog().(*tuiInput)
	cloneFirst.input.SetValue("aqt://folder")
	cmd, done := cloneFirst.Update(key("enter"))
	if !done {
		t.Fatal("clone ref input did not close")
	}
	next := cmd().(tuiOpenDialogMsg).dialog.(*tuiInput)
	next.input.SetValue("/tmp/clone")
	cmd, done = next.Update(key("enter"))
	if !done {
		t.Fatal("clone destination input did not close")
	}
	if got := strings.Join(tuiRequestArgs(t, cmd), " "); got != "clone aqt://folder /tmp/clone" {
		t.Fatalf("clone args = %q", got)
	}

	adopt := tuiCloneDestinationDialog("aqt://folder", true).(*tuiInput)
	adopt.input.SetValue("/tmp/existing")
	cmd, _ = adopt.Update(key("enter"))
	if got := strings.Join(tuiRequestArgs(t, cmd), " "); got != "clone aqt://folder /tmp/existing --adopt" {
		t.Fatalf("adopt args = %q", got)
	}
}

func TestTUISharePasswordPreservesWhitespaceAndResultPersists(t *testing.T) {
	m := testModel(t)
	res := *m.selectedResource()
	opened := menuCommand(t, m.shareDialog(res).(*tuiMenu), "p")().(tuiOpenDialogMsg)
	secret := opened.dialog.(*tuiInput)
	if secret.trimSpace || secret.input.EchoMode != textinput.EchoPassword {
		t.Fatal("share password input is not exact masked input")
	}
	secret.input.SetValue("  exact password  ")
	cmd, done := secret.Update(key("enter"))
	if !done {
		t.Fatal("password dialog did not close")
	}
	req := cmd().(tuiExecRequestMsg)
	if req.stdin != "  exact password  \n" {
		t.Fatalf("password stdin = %q", req.stdin)
	}
	if got := strings.Join(req.sub, " "); got != "share r1 --password-stdin" {
		t.Fatalf("share args = %q", got)
	}

	retry := func() tea.Msg { return "retried" }
	dialog := &tuiResultDialog{title: "Clipboard unavailable", body: "https://example.test/x/id#key", retry: retry}
	if !strings.Contains(dialog.View(80), "https://example.test/x/id#key") {
		t.Fatal("exact link missing from persistent dialog")
	}
	got, closed := dialog.Update(key("r"))
	if closed || got == nil || got().(string) != "retried" {
		t.Fatal("retry did not keep result dialog open")
	}
}
