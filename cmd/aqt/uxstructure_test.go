package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The block-B restructure: `unshare` replaces `private` and `share --revoke`,
// `share ls` exists, `snapshot restore` folded into `restore` (side-by-side default),
// and the agent tree gained `start`.
func TestCommandSurfaceRestructure(t *testing.T) {
	root := rootCmd()

	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	if !names["unshare"] {
		t.Error("root is missing the unshare command")
	}
	if names["private"] {
		t.Error("root still registers the private command (replaced by unshare)")
	}

	share := subcommand(t, root, "share")
	if share.Flags().Lookup("revoke") != nil {
		t.Error("share still declares --revoke (moved to `unshare --with`)")
	}
	foundShareLs := false
	for _, c := range share.Commands() {
		if c.Name() == "ls" {
			foundShareLs = true
		}
	}
	if !foundShareLs {
		t.Error("share has no ls subcommand")
	}

	unshare := subcommand(t, root, "unshare")
	if unshare.Flags().Lookup("with") == nil || unshare.Flags().Lookup("yes") == nil {
		t.Error("unshare is missing --with/--yes")
	}

	snapshot := subcommand(t, root, "snapshot")
	for _, c := range snapshot.Commands() {
		if c.Name() == "restore" {
			t.Error("snapshot restore still exists; it was unified into `aqt restore`")
		}
	}
	restore := subcommand(t, root, "restore")
	if restore.Flags().Lookup("in-place") == nil {
		t.Error("restore is missing --in-place (side-by-side must be the default)")
	}

	agent := subcommand(t, root, "agent")
	foundStart := false
	for _, c := range agent.Commands() {
		if c.Name() == "start" {
			foundStart = true
			if c.Flags().Lookup("foreground") == nil || c.Flags().Lookup("interval") == nil {
				t.Error("agent start is missing --foreground/--interval")
			}
		}
	}
	if !foundStart {
		t.Error("agent has no start subcommand")
	}
}

// --json on a command that does not implement it must error, not silently print
// prose a script would try to parse.
func TestJSONGateErrorsOnUnsupported(t *testing.T) {
	root := rootCmd()
	root.SetArgs([]string{"cat", "someid", "--json"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "does not support --json") {
		t.Fatalf("cat --json err = %v, want the unsupported-json error", err)
	}

	// A supported command passes the gate (whoami then fails on the missing
	// profile, which proves the gate itself let it through).
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root = rootCmd()
	root.SetArgs([]string{"whoami", "--json"})
	err = root.Execute()
	if err != nil && strings.Contains(err.Error(), "does not support --json") {
		t.Fatalf("whoami --json hit the gate: %v", err)
	}
}

// -q and --progress are global like --json, so a command that implements neither
// must say so instead of accepting a flag that changes nothing.
func TestQuietAndProgressGatesErrorOnUnsupported(t *testing.T) {
	// Both flags live on package globals that cobra sets during parsing; a rejected
	// run leaves them set for whatever runs next.
	previousQuiet, previousProgress := flagQuiet, flagProgress
	defer func() { flagQuiet, flagProgress = previousQuiet, previousProgress }()

	unsupported := []struct {
		args []string
		want string
	}{
		{[]string{"ls", "-q"}, "does not support -q/--quiet"},
		{[]string{"whoami", "--quiet"}, "does not support -q/--quiet"},
		{[]string{"push", "note.txt", "--progress"}, "does not support --progress"},
		{[]string{"ls", "--progress"}, "does not support --progress"},
	}
	for _, tc := range unsupported {
		root := rootCmd()
		root.SetArgs(tc.args)
		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v err = %v, want %q", tc.args, err, tc.want)
		}
	}

	// The commands that implement them pass the gate; each then fails on the missing
	// profile or the untracked directory, which is what proves the gate let it through.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	supported := [][]string{
		{"init", t.TempDir(), "-q"},
		{"sync", t.TempDir(), "--progress"},
		{"push", filepath.Join(t.TempDir(), "note.txt"), "-q"},
		{"pull", "someid", "--progress"},
	}
	for _, args := range supported {
		root := rootCmd()
		root.SetArgs(args)
		if err := root.Execute(); err != nil && strings.Contains(err.Error(), "does not support") {
			t.Errorf("%v hit the gate: %v", args, err)
		}
	}
}

func TestJSONGateRejectsRootWithoutPath(t *testing.T) {
	previous := flagJSON
	flagJSON = false
	defer func() { flagJSON = previous }()

	root := rootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetArgs([]string{"--json"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "does not support --json") {
		t.Fatalf("aqt --json err = %v, want the unsupported-json error", err)
	}
	if out.Len() != 0 {
		t.Fatalf("aqt --json printed prose to stdout:\n%s", out.String())
	}
}

// Destructive commands must abort on a non-terminal stdin without -y, before
// touching the server.
func TestDestructiveConfirmRequiredNonTTY(t *testing.T) {
	cases := [][]string{
		{"rm", "someid"},
		{"devices", "rm", "somedevice"},
		{"unshare", "someid"},
		{"unshare", "someid", "--with", "a@example.com"},
		{"logout", "--all-devices"},
	}
	for _, args := range cases {
		root := rootCmd()
		root.SetArgs(args)
		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), "confirmation required") {
			t.Errorf("%v err = %v, want a confirmation-required abort", args, err)
		}
	}
}

// share ls answers "who has access?": a shared resource shows up with its public
// link, unshare takes it back off the list. Exercised over the real router.
func TestShareLsAndUnshare(t *testing.T) {
	newE2E(t)

	fpath := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(fpath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runPush(fpath, pushOptions{noClip: true, quiet: true}); err != nil {
		t.Fatalf("push: %v", err)
	}
	id := onlyResourceID(t)

	out := captureStdout(t, func() {
		if err := runShareList(""); err != nil {
			t.Fatalf("share ls: %v", err)
		}
	})
	if strings.Contains(out, id) {
		t.Fatalf("share ls lists a private, ungranted resource:\n%s", out)
	}

	if err := runShare(id, "", true, linkPolicy{}); err != nil {
		t.Fatalf("share: %v", err)
	}
	out = captureStdout(t, func() {
		if err := runShareList(""); err != nil {
			t.Fatalf("share ls: %v", err)
		}
	})
	if !strings.Contains(out, id) || !strings.Contains(out, "public link") {
		t.Fatalf("share ls does not list the shared resource:\n%s", out)
	}

	// unshare (bare) rotates the key and takes the resource off the list.
	root := rootCmd()
	root.SetArgs([]string{"unshare", id, "-y"})
	if err := root.Execute(); err != nil {
		t.Fatalf("unshare: %v", err)
	}
	out = captureStdout(t, func() {
		if err := runShareList(""); err != nil {
			t.Fatalf("share ls: %v", err)
		}
	})
	if strings.Contains(out, id) {
		t.Fatalf("share ls still lists the unshared resource:\n%s", out)
	}
}

// share ls surfaces the server-enforced lifecycle policy on a link.
func TestShareLsShowsLinkPolicy(t *testing.T) {
	newE2E(t)

	fpath := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(fpath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runPush(fpath, pushOptions{noClip: true, quiet: true}); err != nil {
		t.Fatalf("push: %v", err)
	}
	id := onlyResourceID(t)
	if err := runShare(id, "", true, linkPolicy{expireSeconds: 3600, maxReads: 5, onExpiry: "retire"}); err != nil {
		t.Fatalf("share: %v", err)
	}

	withJSON(t, func() {
		out := captureStdout(t, func() {
			if err := runShareList(id); err != nil {
				t.Fatalf("share ls --json: %v", err)
			}
		})
		var rows []shareListRow
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatalf("share ls --json is not valid JSON: %v\n%s", err, out)
		}
		if len(rows) != 1 || !rows[0].Public {
			t.Fatalf("share ls --json rows = %+v", rows)
		}
		if !strings.Contains(rows[0].Policy, "expires") || !strings.Contains(rows[0].Policy, "/5 reads") {
			t.Errorf("policy summary = %q, want expiry and read cap", rows[0].Policy)
		}
	})
}

// status --json and sync's JSON summary are machine-parseable.
func TestStatusAndSyncJSON(t *testing.T) {
	h := newE2E(t)
	dir := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(dir)
	writeTree(t, dir, "a.txt", "hello")

	withJSON(t, func() {
		out := captureStdout(t, func() {
			if err := runStatus(dir, statusOptions{}); err != nil {
				t.Fatalf("status --json: %v", err)
			}
		})
		var st struct {
			Clean    bool     `json:"clean"`
			Added    []string `json:"added"`
			Incoming *struct {
				State string `json:"state"`
			} `json:"incoming"`
		}
		if err := json.Unmarshal([]byte(out), &st); err != nil {
			t.Fatalf("status --json is not valid JSON: %v\n%s", err, out)
		}
		// The starter .aqtignore is also new, so assert membership, not an exact list.
		if st.Clean || !contains(st.Added, "a.txt") {
			t.Fatalf("status --json = %+v", st)
		}

		out = captureStdout(t, func() {
			if err := runSync(dir, syncOptions{}); err != nil {
				t.Fatalf("sync --json: %v", err)
			}
		})
		var sum struct {
			Uploaded   int `json:"uploaded"`
			Downloaded int `json:"downloaded"`
		}
		if err := json.Unmarshal([]byte(out), &sum); err != nil {
			t.Fatalf("sync --json is not valid JSON: %v\n%s", err, out)
		}
		// a.txt plus the starter .aqtignore go up.
		if sum.Uploaded != 2 || sum.Downloaded != 0 {
			t.Fatalf("sync --json summary = %+v", sum)
		}
	})
}

// -q reduces stdout to the value a script consumes: init prints the ref and nothing
// else, and a sync that had no trouble prints nothing at all.
func TestQuietInitAndSyncOutput(t *testing.T) {
	h := newE2E(t)
	dir := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	withQuiet(t, func() {
		out := captureStdout(t, func() {
			if err := runInit(dir); err != nil {
				t.Fatalf("init -q: %v", err)
			}
		})
		if got, want := strings.TrimSpace(out), "aqt://"+h.folderID(dir); got != want {
			t.Errorf("init -q printed %q, want %q", got, want)
		}

		writeTree(t, dir, "a.txt", "hello")
		out = captureStdout(t, func() {
			if err := runSync(dir, syncOptions{}); err != nil {
				t.Fatalf("sync -q: %v", err)
			}
		})
		if out != "" {
			t.Errorf("sync -q printed %q, want nothing", out)
		}
	})
}

// withQuiet runs fn with the global -q flag set, restoring it afterwards.
func withQuiet(t *testing.T, fn func()) {
	t.Helper()
	flagQuiet = true
	defer func() { flagQuiet = false }()
	fn()
}

// withJSON runs fn with the global --json flag set, restoring it afterwards.
func withJSON(t *testing.T, fn func()) {
	t.Helper()
	flagJSON = true
	defer func() { flagJSON = false }()
	fn()
}

// onlyResourceID returns the id of the account's single resource.
func onlyResourceID(t *testing.T) string {
	t.Helper()
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	items, err := cl.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected exactly one resource, got %d", len(items))
	}
	return items[0].ID
}
