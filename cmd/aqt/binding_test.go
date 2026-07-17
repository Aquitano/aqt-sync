package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// A tracked folder records its owning profile and account fingerprint at init.
func TestInitRecordsIdentityBinding(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Profile != identity.DefaultProfile {
		t.Fatalf("state profile = %q, want %q", st.Profile, identity.DefaultProfile)
	}
	if st.Server != h.url {
		t.Fatalf("state server = %q, want %q", st.Server, h.url)
	}
}

func TestBindingRejectsConflictingProfile(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	flagProfile = "other"
	t.Cleanup(func() { flagProfile = "" })
	err := runSync(dir, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "belongs to profile") {
		t.Fatalf("sync with a conflicting --profile = %v, want a binding error", err)
	}
}

func TestBindingRejectsConflictingServer(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	flagServer = "http://elsewhere.invalid"
	t.Cleanup(func() { flagServer = "" })
	err := runSync(dir, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "--server") {
		t.Fatalf("sync with a conflicting --server = %v, want a binding error", err)
	}
}

// Legacy state (written before the binding fields existed) is adopted by the
// active profile when that profile talks to the folder's recorded server, and the
// adoption is written back.
func TestBindingMigratesLegacyState(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	writeTree(t, dir, "a.txt", "hi")
	h.sync(dir)

	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Profile, st.Fingerprint = "", ""
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}

	h.sync(dir)
	st, err = loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Profile != identity.DefaultProfile {
		t.Fatalf("legacy state not migrated: profile = %q", st.Profile)
	}
}

// Legacy state recorded against a different server must not silently bind to the
// active profile's account.
func TestBindingRefusesLegacyStateFromOtherServer(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Profile, st.Fingerprint = "", ""
	st.Server = "http://elsewhere.invalid"
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}

	err = runSync(dir, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "predates profile binding") {
		t.Fatalf("sync of a foreign-server legacy folder = %v, want a binding error", err)
	}
}

// A profile that was re-logged into a different account (new key fingerprint) must
// not sync a folder the old account owns.
func TestBindingRefusesFingerprintMismatch(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Fingerprint = "recorded-owner-key"
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}
	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	prof.Fingerprint = "different-account-key"
	if err := identity.Save(prof); err != nil {
		t.Fatal(err)
	}

	err = runSync(dir, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "different account") {
		t.Fatalf("sync under a swapped account = %v, want a binding error", err)
	}
}

// The recorded owner following its profile to a moved server updates the state,
// covered end-to-end by the rollback tests (restoreServer moves the URL); here the
// state write-back itself is asserted.
func TestBindingFollowsProfileServerMove(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	moved := prof.Server + "/" // same server, canonically equal
	prof.Server = moved
	if err := identity.Save(prof); err != nil {
		t.Fatal(err)
	}
	if err := bindTrackedRoot(dir); err != nil {
		t.Fatalf("bind after a canonical-equal server change: %v", err)
	}
}

// A failed local commit during init deletes the just-created remote resource, so a
// failed init has no side effects at all.
func TestInitCleansUpRemoteOnLocalFailure(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()

	orig := commitInitState
	commitInitState = func(string, *identity.Profile, api.PutResourceResponse, syncengine.Manifest) error {
		return errors.New("injected local-commit failure")
	}
	t.Cleanup(func() { commitInitState = orig })

	err := runInit(dir)
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("init = %v, want the injected failure", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".aqt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed init left .aqt behind (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".aqtignore")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed init left .aqtignore behind (stat err=%v)", err)
	}
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	resources, err := cl.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 0 {
		t.Fatalf("failed init left %d remote resource(s) behind", len(resources))
	}
	_ = h
}

// An unwritable destination fails init before anything is created on the server.
func TestInitPermissionFailureCreatesNoRemote(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits do not apply")
	}
	h := newE2E(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	if err := runInit(dir); err == nil {
		t.Fatal("init into an unwritable directory succeeded")
	}
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	resources, err := cl.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 0 {
		t.Fatalf("failed init created %d remote resource(s)", len(resources))
	}
	_ = h
}
