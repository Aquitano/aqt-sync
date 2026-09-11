// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func doctorCheckNamed(t *testing.T, report doctorReport, name string) doctorCheck {
	t.Helper()
	for _, c := range report.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q missing", name)
	return doctorCheck{}
}

func TestDoctorChecksTrackedFolderWithoutChangingBinding(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	st, err := folderstate.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Sync would update these fields. Doctor must only inspect them.
	st.Server = "https://previous.example"
	st.Fingerprint = "previous-key"
	if err := folderstate.SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(folderstate.StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	prof, err := identity.Load("")
	if err != nil {
		t.Fatal(err)
	}
	report := diagnose(context.Background(), dir, true, doctorOptions{timeout: time.Second})
	if !report.OK || report.Server != h.url || report.SchemaVersion != 1 {
		t.Fatalf("healthy doctor report = %+v", report)
	}
	for _, c := range report.Checks {
		if c.Status != "ok" {
			t.Errorf("check failed: %+v", c)
		}
	}
	var out bytes.Buffer
	for _, asJSON := range []bool{false, true} {
		out.Reset()
		if err := printDoctor(&out, report, asJSON); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), prof.Token) || strings.Contains(out.String(), "correct horse battery staple") {
			t.Fatal("doctor printed credentials")
		}
	}
	after, err := os.ReadFile(folderstate.StatePath(dir))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("doctor rewrote folder binding")
	}
}

func TestDoctorUsesFolderProfileWithoutChangingFlags(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	prof, err := identity.Load("")
	if err != nil {
		t.Fatal(err)
	}
	prof.Name = "work"
	if err := identity.Save(prof); err != nil {
		t.Fatal(err)
	}
	st, err := folderstate.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Profile = "work"
	if err := folderstate.SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	previous := flagProfile
	flagProfile = ""
	t.Cleanup(func() { flagProfile = previous })
	report := diagnose(context.Background(), dir, true, doctorOptions{offline: true})
	if report.Profile != "work" || flagProfile != "" {
		t.Fatalf("selected profile = %q, flag = %q", report.Profile, flagProfile)
	}
	if check := doctorCheckNamed(t, report, "folder"); check.Code != "folder_bound" {
		t.Fatalf("folder check = %+v", check)
	}
	if check := doctorCheckNamed(t, report, "session"); check.Code != "session_missing" {
		t.Fatalf("doctor used another profile's session: %+v", check)
	}
}

func TestDoctorOfflineNeverContactsServer(t *testing.T) {
	newE2E(t)
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	previous := flagServer
	flagServer = ts.URL
	t.Cleanup(func() { flagServer = previous })
	report := diagnose(context.Background(), t.TempDir(), false, doctorOptions{offline: true})
	if !report.OK || requests.Load() != 0 {
		t.Fatalf("offline report = %+v; requests = %d", report, requests.Load())
	}
	for _, name := range []string{"server", "authentication"} {
		if c := doctorCheckNamed(t, report, name); c.Status != "skipped" {
			t.Fatalf("%s was not skipped: %+v", name, c)
		}
	}
}

func TestDoctorServerOverrideDoesNotReceiveToken(t *testing.T) {
	newE2E(t)
	var credentials, authRequests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			credentials.Add(1)
		}
		if r.URL.Path != "/readyz" {
			authRequests.Add(1)
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}))
	defer ts.Close()
	previous := flagServer
	flagServer = ts.URL
	t.Cleanup(func() { flagServer = previous })
	report := diagnose(context.Background(), t.TempDir(), false, doctorOptions{timeout: time.Second})
	if c := doctorCheckNamed(t, report, "authentication"); c.Code != "server_profile_mismatch" || report.OK {
		t.Fatalf("authentication check = %+v", c)
	}
	if credentials.Load() != 0 || authRequests.Load() != 0 {
		t.Fatal("doctor sent credentials or authenticated requests to the override")
	}
}

func TestDoctorFailedChecksReturnJSONAndNonzeroExit(t *testing.T) {
	isolateConfigEnv(t, t.TempDir())
	root := rootCmd()
	previousJSON := flagJSON
	t.Cleanup(func() { flagJSON = previousJSON })
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"doctor", t.TempDir(), "--offline", "--json"})
	err := root.Execute()
	if !errors.Is(err, errDoctorIssues) || exitCode(err) != 1 {
		t.Fatalf("doctor error = %v, exit = %d", err, exitCode(err))
	}
	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("doctor printed invalid JSON: %v", err)
	}
	if report.OK || doctorCheckNamed(t, report, "profile").Code != "profile_missing" || doctorCheckNamed(t, report, "folder").Code != "folder_untracked" {
		t.Fatalf("missing-profile report = %+v", report)
	}
}

func TestDoctorRejectsCorruptFolderAndWrongAccount(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	st, err := folderstate.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Account = "another-account"
	if err := folderstate.SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	report := diagnose(context.Background(), dir, true, doctorOptions{offline: true})
	if c := doctorCheckNamed(t, report, "folder"); c.Code != "folder_account_mismatch" {
		t.Fatalf("wrong-account check = %+v", c)
	}
	path := folderstate.StatePath(dir)
	if err := os.WriteFile(path, []byte("broken state with sensitive text"), 0o600); err != nil {
		t.Fatal(err)
	}
	report = diagnose(context.Background(), filepath.Join(dir, "."), true, doctorOptions{offline: true})
	if c := doctorCheckNamed(t, report, "folder"); c.Code != "folder_unreadable" {
		t.Fatalf("corrupt-folder check = %+v", c)
	}
	var out bytes.Buffer
	if err := printDoctor(&out, report, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "sensitive text") {
		t.Fatal("doctor echoed malformed local state")
	}
}

func TestDoctorNetworkFailuresAreBoundedAndRedacted(t *testing.T) {
	for _, kind := range []string{"not-ready", "wrong-json", "unauthorized", "hostile-error", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			newE2E(t)
			var mutations atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					mutations.Add(1)
				}
				if kind == "timeout" {
					<-r.Context().Done()
					return
				}
				if r.URL.Path == "/readyz" {
					switch kind {
					case "not-ready":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "wrong-json":
						_, _ = w.Write([]byte(`{"status":"wrong"}`))
					default:
						_, _ = w.Write([]byte(`{"status":"ready"}`))
					}
					return
				}
				if kind == "unauthorized" {
					w.WriteHeader(http.StatusUnauthorized)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
				_, _ = w.Write([]byte(`{"error":"LEAK-ME \u001b[2J"}`))
			}))
			defer ts.Close()
			prof, err := identity.Load("")
			if err != nil {
				t.Fatal(err)
			}
			prof.Server = ts.URL
			if err := identity.Save(prof); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			report := diagnose(context.Background(), t.TempDir(), false, doctorOptions{timeout: 100 * time.Millisecond})
			if report.OK || time.Since(start) > 2*time.Second || mutations.Load() != 0 {
				t.Fatalf("invalid network diagnosis: %+v", report)
			}
			if kind == "timeout" && doctorCheckNamed(t, report, "server").Code != "server_timeout" {
				t.Fatalf("missing timeout diagnosis: %+v", report)
			}
			if kind == "unauthorized" && doctorCheckNamed(t, report, "authentication").Code != "device_unauthorized" {
				t.Fatalf("missing revoked-device diagnosis: %+v", report)
			}
			var out bytes.Buffer
			if err := printDoctor(&out, report, true); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "LEAK-ME") || strings.Contains(out.String(), prof.Token) {
				t.Fatal("doctor echoed credentials or a hostile error")
			}
		})
	}
}

func TestDoctorRedactsInvalidServerURL(t *testing.T) {
	isolateConfigEnv(t, t.TempDir())
	previous := flagServer
	flagServer = "https://user:SECRET@example.invalid/?token=SECRET#SECRET"
	t.Cleanup(func() { flagServer = previous })
	report := diagnose(context.Background(), t.TempDir(), false, doctorOptions{offline: true})
	var out bytes.Buffer
	if err := printDoctor(&out, report, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SECRET") || doctorCheckNamed(t, report, "server").Code != "server_url_invalid" {
		t.Fatalf("unsafe URL report: %s", out.String())
	}
}

func TestDoctorBinaryOfflineReportsWithoutCreatingFiles(t *testing.T) {
	exe, err := sharedAqtBinary()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	isolateConfigEnv(t, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "doctor", "--offline", "--json")
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 1 {
		t.Fatalf("doctor exit = %v, stderr = %s", err, stderr.String())
	}
	var report doctorReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("invalid stdout JSON: %v", err)
	}
	if report.OK || report.Profile != identity.DefaultProfile || doctorCheckNamed(t, report, "profile").Code != "profile_missing" {
		t.Fatalf("fresh-install report = %+v", report)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("doctor created config or tracking files: %v, %v", entries, err)
	}
}
