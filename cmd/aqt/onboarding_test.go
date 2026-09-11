// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/identity"
)

func TestLoginUsesSavedEmailWithoutCreatingDevice(t *testing.T) {
	newE2E(t)
	before, err := identity.Load(flagProfile)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ClearSession(flagProfile); err != nil {
		t.Fatal(err)
	}
	withStdin(t, "correct horse battery staple\n")
	if err := runLogin("", defaultSessionTTL); err != nil {
		t.Fatalf("login using saved email: %v", err)
	}
	after, err := identity.Load(flagProfile)
	if err != nil {
		t.Fatal(err)
	}
	if after.Email != before.Email || after.DeviceID != before.DeviceID || after.Token != before.Token {
		t.Fatal("login changed the saved account or created a device")
	}
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	devices, err := cl.ListDevices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices after login = %v, err = %v", devices, err)
	}
}

func TestLoginDoesNotReuseEmailOnAnotherServer(t *testing.T) {
	newE2E(t)
	var requests atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer other.Close()
	previous := flagServer
	flagServer = other.URL
	t.Cleanup(func() { flagServer = previous })
	withStdin(t, "")
	if err := runLogin("", defaultSessionTTL); err == nil || err.Error() != "email is required" {
		t.Fatalf("login on another server = %v, want an email prompt", err)
	}
	if requests.Load() != 0 {
		t.Fatal("login sent a saved email to another server")
	}
}

func TestLoginFreshProfileReadsEmailAndPassphrase(t *testing.T) {
	h := newE2E(t)
	previousProfile, previousServer := flagProfile, flagServer
	flagProfile, flagServer = "second-device", h.url
	t.Cleanup(func() { flagProfile, flagServer = previousProfile, previousServer })
	withStdin(t, "e2e@example.com\ncorrect horse battery staple\n")
	if err := runLogin("", defaultSessionTTL); err != nil {
		t.Fatalf("login on a fresh profile: %v", err)
	}
	prof, err := identity.Load("second-device")
	if err != nil {
		t.Fatal(err)
	}
	if prof.Email != "e2e@example.com" || prof.Server != h.url {
		t.Fatalf("saved wrong account: email=%q server=%q", prof.Email, prof.Server)
	}
}

func TestBarePathRejectsExtraArgumentsBeforeUpload(t *testing.T) {
	root := rootCmd()
	root.SetArgs([]string{"./first.txt", "./second.txt"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "accepts at most 1 arg") {
		t.Fatalf("multiple bare paths = %v, want argument validation before upload", err)
	}
}
