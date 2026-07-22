//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// detachedProcess is the DETACHED_PROCESS creation flag (not exported by the
// syscall package). It starts the watcher without inheriting this console, so it
// keeps running after the launching shell exits — the Windows analogue of a new
// Unix session.
const detachedProcess = 0x00000008

// detachAgent starts the watcher detached from this console and in its own process
// group, so a Ctrl-C or the shell closing does not take it down with it.
func detachAgent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}

// terminateAgent stops the watcher. Windows cannot deliver SIGTERM to an unrelated
// process, so terminate it directly; the watcher keeps no in-flight on-disk state
// an abrupt stop would corrupt (writes are atomic temp+rename, and the pid file is
// reclaimed on the next start).
func terminateAgent(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// processAlive reports whether pid is a live process. Windows has no signal-0
// liveness probe, so open the process and check it has not exited. (A process that
// deliberately exited with code 259 = STILL_ACTIVE would read as alive, an accepted
// caveat that never applies to our own watcher.)
func processAlive(pid int) bool {
	const processQueryLimitedInformation = 0x1000
	const stillActive = 259
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false // no such process, or inaccessible: treat as gone
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// currentUmask reports no umask: Windows has none, and directory modes are not
// meaningful there.
func currentUmask() os.FileMode { return 0 }
