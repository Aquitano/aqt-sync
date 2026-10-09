// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/client"
)

func TestRecoveryRefusesBeforeReadingSecrets(t *testing.T) {
	notAqt := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notAqt.Close)
	for _, tc := range []struct {
		name    string
		server  string
		wantErr error
		want    string
	}{
		{name: "missing server", wantErr: errNoServer},
		{name: "insecure server", server: "http://aqt.example.com", wantErr: client.ErrInsecureScheme},
		{name: "wrong server", server: notAqt.URL, want: "does not answer like an aqt server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfigEnv(t, t.TempDir())
			t.Setenv("AQT_SERVER", "")
			withStdin(t, "unread recovery key\n")
			app := &application{ctx: context.Background(), server: tc.server}
			err := app.runRecover("recover@example.com", time.Hour, kdfChoice{})
			if err == nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) || tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("recover = %v, want %v %q", err, tc.wantErr, tc.want)
			}
			if line, _ := stdinReader().ReadString('\n'); line != "unread recovery key\n" {
				t.Fatalf("recovery consumed input before refusing: %q", line)
			}
		})
	}
}

// The recovery key alone gets an account back: a fresh machine that never knew the
// passphrase sets a new one, reads data pushed before, and the old passphrase stops
// unlocking.
func TestRecoveryKeyRestoresForgottenPassphrase(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	const email = "e2e@example.com"
	source := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(source, []byte("written before the passphrase was lost"), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimSpace(captureStdout(t, func() {
		if err := app.runPush(source, pushOptions{noClip: true}); err != nil {
			t.Fatal(err)
		}
	}))
	withStdin(t, "correct horse battery staple\n")
	key := strings.TrimSpace(captureStdout(t, func() {
		if err := app.runRecoveryKey(); err != nil {
			t.Fatal(err)
		}
	}))

	app.server = ""
	t.Setenv("AQT_SERVER", h.url)
	cheap := kdfChoice{timeCost: 1, memoryMiB: 1, threads: 1}
	isolateConfigEnv(t, t.TempDir())
	withStdin(t, key+"\nnew passphrase\n")
	if err := app.runRecover(email, time.Hour, cheap); err != nil {
		t.Fatalf("recover: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "note.txt")
	if err := app.runPull(ref, dest, "", false, false); err != nil {
		t.Fatalf("pull after recovery: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "written before the passphrase was lost" {
		t.Fatalf("pulled %q after recovery", got)
	}

	isolateConfigEnv(t, t.TempDir())
	withStdin(t, "correct horse battery staple\n")
	if err := app.runLogin(email, time.Hour); !errors.Is(err, errNoUnlock) {
		t.Fatalf("login with the forgotten passphrase = %v, want errNoUnlock", err)
	}
	withStdin(t, "new passphrase\n")
	if err := app.runLogin(email, time.Hour); err != nil {
		t.Fatalf("login with the new passphrase: %v", err)
	}
}
