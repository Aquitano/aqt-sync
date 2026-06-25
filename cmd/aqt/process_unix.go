//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// detachAgent puts the spawned watcher in its own session, so it survives the
// launching shell exiting and is not killed by a terminal hangup.
func detachAgent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// terminateAgent asks the watcher to stop gracefully; its signal handler turns the
// SIGTERM into a clean shutdown.
func terminateAgent(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// processAlive reports whether pid is a live process. Signal 0 probes liveness
// without affecting the target, so a stale lock from a crashed process is reclaimed
// rather than left wedging the folder.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
