package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aquitano/aqt-sync/internal/api"
)

// The TUI mutates through the CLI itself: every action re-executes this binary
// (`aqt sync`, `aqt share`, …) and streams its output into the log pane. That
// keeps one tested code path per operation, keeps the CLI's exit-code contract,
// and — like lazygit's command log — shows the user the exact command they could
// have typed. The subprocess never prompts: the TUI unlocked the session first,
// and stdin is closed so a lost session fails fast (exit 3) instead of hanging.

// tuiExecRequestMsg asks the model to start an action. Routing every action
// through the model (instead of spawning from the key handler) makes the
// one-action-at-a-time guard race-free: the guard flag is set synchronously in
// Update before the subprocess Cmd ever runs, so a double-tapped key cannot
// launch two subprocesses.
type tuiExecRequestMsg struct {
	sub []string
	// stdin is fed to the child instead of /dev/null. It carries the share password,
	// which is the whole point: an argv password is world-readable in ps for as long
	// as the command runs.
	stdin string
}

// tuiRequestExec is what action keys and dialogs resolve to.
func tuiRequestExec(sub ...string) tea.Cmd {
	return func() tea.Msg { return tuiExecRequestMsg{sub: sub} }
}

// tuiRequestExecStdin is tuiRequestExec for an action whose secret must stay out of
// the process table.
func tuiRequestExecStdin(stdin string, sub ...string) tea.Cmd {
	return func() tea.Msg { return tuiExecRequestMsg{sub: sub, stdin: stdin} }
}

type tuiExecStartedMsg struct {
	title string
	ch    chan tea.Msg
	// cmd is the running subprocess, kept so the model can signal it (cancel,
	// or a confirmed quit tearing the action down cleanly).
	cmd *exec.Cmd
}

// tuiCancelExecMsg is resolved by the cancel confirm dialog; the model turns it
// into a SIGTERM to the running action and records that the stop was deliberate.
type tuiCancelExecMsg struct{}

func tuiCancelExec() tea.Cmd {
	return func() tea.Msg { return tuiCancelExecMsg{} }
}

// tuiKillAndQuitMsg asks the model to stop any running action and then quit.
// Like tuiCancelExecMsg it carries no pid: the action can finish (and be reaped)
// while the quit confirm sits open, so the liveness check has to happen in Update
// against the live execBusy/execCmd, never against a pid captured when the dialog
// was built — signalling a reaped pid can hit an unrelated process after reuse.
type tuiKillAndQuitMsg struct{}

func tuiKillAndQuit() tea.Cmd {
	return func() tea.Msg { return tuiKillAndQuitMsg{} }
}

type tuiExecOutMsg struct {
	line string
	ch   chan tea.Msg
}

type tuiExecDoneMsg struct {
	title string
	exit  int
	err   error
}

// tuiExecArgs finalizes a subcommand's argv with the session-wide flag overrides,
// so an action targets the same server/profile the TUI itself talks to.
func tuiExecArgs(sub []string) []string {
	args := append([]string(nil), sub...)
	if flagServer != "" {
		args = append(args, "--server", flagServer)
	}
	if flagProfile != "" {
		args = append(args, "--profile", flagProfile)
	}
	return args
}

// tuiExecCmd starts `exe args...` and returns the started message; output lines
// and the final result arrive on the channel via tuiExecListen.
func tuiExecCmd(exe string, sub []string, stdin string) tea.Cmd {
	args := tuiExecArgs(sub)
	title := "aqt " + joinArgs(redactSecrets(args))
	return func() tea.Msg {
		ch := make(chan tea.Msg, 64)
		cmd := exec.Command(exe, args...)
		// Without a payload stdin stays nil (/dev/null), so a child that would
		// otherwise prompt fails fast (exit 3) rather than hanging on a terminal
		// the TUI owns.
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return tuiExecDoneMsg{title: title, exit: 1, err: err}
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return tuiExecDoneMsg{title: title, exit: 1, err: err}
		}
		if err := cmd.Start(); err != nil {
			return tuiExecDoneMsg{title: title, exit: 1, err: err}
		}
		var wg sync.WaitGroup
		for _, r := range []io.Reader{stdout, stderr} {
			wg.Add(1)
			go func(r io.Reader) {
				defer wg.Done()
				sc := bufio.NewScanner(r)
				sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
				for sc.Scan() {
					ch <- tuiExecOutMsg{line: sc.Text(), ch: ch}
				}
				// A scanner error (e.g. a line over the buffer cap) must not
				// wedge the action: keep draining so the child never blocks on
				// a full pipe and cmd.Wait() can return.
				if serr := sc.Err(); serr != nil {
					ch <- tuiExecOutMsg{line: "[output dropped: " + serr.Error() + "]", ch: ch}
					_, _ = io.Copy(io.Discard, r)
				}
			}(r)
		}
		go func() {
			wg.Wait()
			err := cmd.Wait()
			exit := 0
			if ee, ok := err.(*exec.ExitError); ok {
				exit = ee.ExitCode()
			} else if err != nil {
				exit = 1
			}
			ch <- tuiExecDoneMsg{title: title, exit: exit, err: err}
			close(ch)
		}()
		return tuiExecStartedMsg{title: title, ch: ch, cmd: cmd}
	}
}

// redactSecrets masks the value following a password flag so it never appears
// in the command log.
func redactSecrets(args []string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		if (a == "-P" || a == "--password") && i+1 < len(out) {
			out[i+1] = "•••"
		}
	}
	return out
}

// tuiExecListen delivers the next line (or the completion) from a running action.
func tuiExecListen(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

// tuiExitNote maps the CLI's documented exit codes to a short verdict for the
// status line; the raw output is already in the log.
func tuiExitNote(exit int) string {
	switch exit {
	case 0:
		return "done"
	case 3:
		return "session locked — run `aqt login` and reopen the TUI"
	case 4:
		return "conflicts remain — resolve them or sync with conflicts=copy"
	case 5:
		return "network error or rate limit — server unreachable, retry shortly"
	case 6:
		return fmt.Sprintf("upgrade required — this build reads capability %d; run `aqt update`", api.ClientCapability)
	case 7:
		return "link gone — expired or read limit reached"
	default:
		return fmt.Sprintf("failed (exit %d)", exit)
	}
}

// joinArgs renders an argv for display, quoting arguments with spaces.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		if a == "" || strings.ContainsAny(a, " \t") {
			out += fmt.Sprintf("%q", a)
		} else {
			out += a
		}
	}
	return out
}
