// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

var errDoctorIssues = errors.New("doctor found problems; see the report for next steps")

type doctorOptions struct {
	offline bool
	timeout time.Duration
}

type doctorCheck struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Action    string `json:"action,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
}

type doctorReport struct {
	SchemaVersion int           `json:"schemaVersion"`
	OK            bool          `json:"ok"`
	Profile       string        `json:"profile"`
	Server        string        `json:"server"`
	Checks        []doctorCheck `json:"checks"`
}

func doctorCmd() *cobra.Command {
	var opts doctorOptions
	cmd := &cobra.Command{
		Use:   "doctor [dir]",
		Short: "Check setup and explain what needs attention",
		Long: "Check the profile, cached session, folder binding, server readiness, and device\n" +
			"authentication. Checks do not change local state or upload files. No passphrase\n" +
			"is requested; the OS keychain may ask to allow reading existing credentials.\n" +
			"Inside a tracked folder, its profile is used unless --profile is supplied.\n" +
			"Use --offline to skip network checks. --json prints the same report as JSON.\n" +
			"Exit 0 means all performed checks passed; exit 1 means a problem was found.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.timeout <= 0 {
				return errors.New("--timeout must be positive")
			}
			report := diagnose(rootCtx, dirArg(args), len(args) > 0, opts)
			if err := printDoctor(cmd.OutOrStdout(), report, flagJSON); err != nil {
				return err
			}
			if err := rootCtx.Err(); err != nil {
				return err
			}
			if !report.OK {
				return errDoctorIssues
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.offline, "offline", false, "check local state only")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 5*time.Second, "total time allowed for network checks")
	markJSONSupported(cmd)
	return cmd
}

func (r *doctorReport) add(name, status, code, message, action string) {
	r.Checks = append(r.Checks, doctorCheck{Name: name, Status: status, Code: code, Message: message, Action: action})
	if status == "error" {
		r.OK = false
	}
}

func diagnose(ctx context.Context, dir string, explicitDir bool, opts doctorOptions) doctorReport {
	r := doctorReport{SchemaVersion: 1, OK: true, Profile: flagProfile}
	st, folderErr := doctorFolder(dir)
	if r.Profile == "" && st != nil {
		r.Profile = st.Profile
	}
	r.Profile = firstNonEmpty(r.Profile, identity.DefaultProfile)
	prof, profileErr := identity.Load(r.Profile)
	if profileErr != nil {
		code, message := "profile_unreadable", "The selected profile cannot be read."
		action := "Check the profile file's permissions and contents; use a different --profile to sign in without replacing it."
		if errors.Is(profileErr, identity.ErrNoProfile) {
			code, message = "profile_missing", "No account is configured for this profile."
			action = "Use `aqt --server <url> signup` for a new account or `aqt --server <url> login` for an existing one; include --profile if needed."
		}
		r.add("profile", "error", code, message, action)
	} else {
		r.add("profile", "ok", "profile_loaded", "The selected profile is readable.", "")
	}

	server := flagServer
	if server == "" && prof != nil {
		server = prof.Server
	}
	if server == "" && st != nil {
		server = st.Server
	}
	server = firstNonEmpty(server, defaultServer)
	var serverErr error
	r.Server, serverErr = doctorServerURL(server)

	if prof == nil {
		r.add("session", "skipped", "profile_unavailable", "Session check needs a readable profile.", "")
	} else {
		r.checkSession()
	}
	r.checkFolder(st, folderErr, explicitDir, prof, server)

	switch {
	case serverErr != nil:
		r.add("server", "error", "server_url_invalid", "The server URL is invalid.", "Use an http:// or https:// server URL without credentials, a query, or a fragment.")
	case opts.offline:
		r.add("server", "skipped", "offline", "Network checks were disabled by --offline.", "")
	default:
		networkCtx, cancel := context.WithTimeout(ctx, opts.timeout)
		defer cancel()
		r.checkNetwork(networkCtx, server, prof)
		return r
	}
	r.add("authentication", "skipped", "server_not_checked", "Authentication needs a successful network check.", "")
	return r
}

func (r *doctorReport) checkSession() {
	info, err := identity.InspectSession(r.Profile)
	status, code, message, action := "error", "session_unreadable", "The session cache cannot be read.", "Run `aqt login` with the selected --profile to unlock this device."
	if err == nil {
		switch info.State {
		case identity.SessionMissing:
			code, message = "session_missing", "No unlocked session is cached."
		case identity.SessionExpired:
			code, message = "session_expired", "The cached session has expired."
		case identity.SessionInvalid:
			code, message = "session_invalid", "The cached key cannot be decrypted on this device."
		case identity.SessionUnlocked:
			status, code, message, action = "ok", "session_unlocked", "The cached key is readable and unexpired.", ""
			if info.ExpiresAt == 0 {
				message = "The cached key is readable; it has no expiry."
			}
		}
	}
	r.add("session", status, code, message, action)
	r.Checks[len(r.Checks)-1].ExpiresAt = info.ExpiresAt
}

// doctorFolder inspects binding state without bindTrackedRoot's migration writes.
func doctorFolder(dir string) (*folderstate.State, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("not a directory")
	}
	for {
		_, err := os.Stat(filepath.Join(abs, syncengine.ControlDir))
		if err == nil {
			st, err := folderstate.LoadState(abs)
			if err != nil {
				return nil, err
			}
			if st.ID == "" || st.Server == "" {
				return nil, errors.New("incomplete folder binding")
			}
			return &st, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return nil, nil
		}
		abs = parent
	}
}

func (r *doctorReport) checkFolder(st *folderstate.State, err error, explicitDir bool, prof *identity.Profile, server string) {
	switch {
	case err != nil:
		r.add("folder", "error", "folder_unreadable", "The directory or its tracking state cannot be read.", "Check the directory and .aqt/state.json. Recover damaged tracking from backup or clone to a new directory.")
	case st == nil:
		status := "skipped"
		if explicitDir {
			status = "error"
		}
		r.add("folder", status, "folder_untracked", "This directory is not inside a tracked folder.", "Use `aqt init <folder>` for a new folder or `aqt clone` for an existing remote folder.")
	case prof == nil:
		r.add("folder", "skipped", "profile_unavailable", "Folder binding needs its owning profile.", "Sign in with the folder's account and profile.")
	case !sameAccount(*st, prof):
		r.add("folder", "error", "folder_account_mismatch", "The selected profile does not own this folder.", "Drop --profile to use the folder's saved profile, or sign in with its original account.")
	case flagServer != "" && !sameServer(server, st.Server):
		r.add("folder", "error", "folder_server_mismatch", "The server override differs from this folder's saved server.", "Drop --server. To move servers, update the owning profile and run sync.")
	default:
		r.add("folder", "ok", "folder_bound", "The folder belongs to the selected account.", "")
	}
}

// Do not render URL credentials or query strings into a shareable report.
func doctorServerURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "(invalid URL)", errors.New("invalid server URL")
	}
	safe := u.Scheme + "://" + u.Host + u.EscapedPath()
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return foreignText(safe), errors.New("server URL contains credentials, query, or fragment")
	}
	return foreignText(safe), nil
}

func (r *doctorReport) checkNetwork(ctx context.Context, server string, prof *identity.Profile) {
	probe, err := client.New(server, "")
	if err == nil {
		err = probe.WithContext(ctx).Ready()
	}
	if err != nil {
		code, message, action := "server_unavailable", "The server did not return a valid readiness response.", "Check the server URL, network connection, TLS certificate, and server logs."
		if errors.Is(err, context.DeadlineExceeded) {
			code, message = "server_timeout", "The server check exceeded --timeout."
		}
		r.add("server", "error", code, message, action)
		r.add("authentication", "skipped", "server_unavailable", "Authentication was not checked because readiness failed.", "")
		return
	}
	r.add("server", "ok", "server_ready", "The server is reachable and ready.", "")
	if prof == nil || prof.Token == "" {
		r.add("authentication", "error", "device_token_missing", "No device credential is available.", "Run `aqt login` with the selected profile and server.")
		return
	}
	if !sameServer(server, prof.Server) {
		r.add("authentication", "error", "server_profile_mismatch", "The selected server differs from the profile's server; its token was not sent.", "Drop --server, or use a profile configured for the intended server.")
		return
	}
	cl, err := client.New(server, prof.Token)
	if err == nil {
		err = validateAttachedDevice(cl.WithContext(ctx), prof.DeviceID)
	}
	if err != nil {
		code, message, action := "authentication_failed", "The saved device could not be verified.", "Check the account with your server operator, then run `aqt login` with the selected profile."
		switch {
		case errors.Is(err, client.ErrUnauthorized):
			code, message = "device_unauthorized", "The server rejected this device's credential."
		case errors.Is(err, client.ErrInsecureScheme):
			code, message, action = "server_insecure", "The device token cannot be sent over this HTTP connection.", "Configure HTTPS on the server and use its https:// URL."
		case errors.Is(err, context.DeadlineExceeded):
			code, message = "authentication_timeout", "The authentication check exceeded --timeout."
		}
		r.add("authentication", "error", code, message, action)
		return
	}
	r.add("authentication", "ok", "device_authenticated", "The server recognizes this device.", "")
}

func printDoctor(w io.Writer, report doctorReport, asJSON bool) error {
	if asJSON {
		return printJSONTo(w, report)
	}
	if _, err := fmt.Fprintf(w, "Profile: %s\nServer:  %s\n\n", foreignText(report.Profile), report.Server); err != nil {
		return err
	}
	for _, check := range report.Checks {
		if _, err := fmt.Fprintf(w, "[%s] %s: %s\n", check.Status, check.Name, check.Message); err != nil {
			return err
		}
		if check.ExpiresAt != 0 {
			if _, err := fmt.Fprintf(w, "  Expires: %s\n", time.Unix(check.ExpiresAt, 0).UTC().Format(time.RFC3339)); err != nil {
				return err
			}
		}
		if check.Action != "" {
			if _, err := fmt.Fprintf(w, "  Next: %s\n", check.Action); err != nil {
				return err
			}
		}
	}
	return nil
}
