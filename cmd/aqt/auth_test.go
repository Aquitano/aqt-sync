// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/server"
)

// Everything signup can learn without the user is checked before the passphrase
// prompt: a refusal after it wastes the typing, and for a plain-http remote the
// verifier would already have crossed the wire in the clear.
func TestSignupRefusesBeforeAskingForAPassphrase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store, err := server.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	inviteOnly := httptest.NewServer(server.NewWithConfig(store, server.Config{
		Registration: server.RegistrationInvite, InviteTokens: []string{"tok"},
	}).Router())
	t.Cleanup(inviteOnly.Close)
	notAqt := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notAqt.Close)

	cases := []struct {
		name    string
		server  string
		wantErr error
		want    string
	}{
		{name: "no server configured", wantErr: errNoServer},
		{name: "plain http to a remote host", server: "http://aqt.example.com", wantErr: client.ErrInsecureScheme},
		{name: "not an aqt server", server: notAqt.URL, want: "does not answer like an aqt server"},
		{name: "invite-only without a token", server: inviteOnly.URL, want: "only accepts signups with an invite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfigEnv(t, t.TempDir())
			t.Setenv("AQT_SERVER", "")
			withStdin(t, "unread passphrase\n")
			app := &application{ctx: context.Background(), server: tc.server}
			err := app.runSignup("new@example.com", "", 0, kdfChoice{preset: "interactive"}, false)
			if err == nil {
				t.Fatal("signup succeeded")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("signup error = %v, want %v", err, tc.wantErr)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("signup error = %v, want it to say %q", err, tc.want)
			}
			if line, _ := stdinReader().ReadString('\n'); line != "unread passphrase\n" {
				t.Fatalf("signup read %q from stdin before refusing", line)
			}
		})
	}
}

// A server that predates /v1/info still works: its liveness probe vouches for it.
func TestLoginAcceptsServerWithoutInfoEndpoint(t *testing.T) {
	app := &application{ctx: context.Background()}
	app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if r.URL.Path == "/v1/info" {
			http.NotFound(w, r)
			return
		}
		pass(w, r)
	})
	withStdin(t, "correct horse battery staple\n")
	if err := app.runLogin("e2e@example.com", time.Hour); err != nil {
		t.Fatalf("login against a server without /v1/info: %v", err)
	}
}
