// Command git-remote-aqt is the standalone executable Git used to discover for
// aqt:: URLs. It is deprecated: aqt answers to this name itself, and `aqt git
// setup` links it, so nothing has to be upgraded separately. This shim stays
// published for a release or two so installs that already carry it keep working.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	aqt := siblingAQT()
	args := append([]string{"git-remote-helper"}, os.Args[1:]...)
	cmd := exec.Command(aqt, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if code := exit.ExitCode(); code >= 0 {
				os.Exit(code)
			}
			// A signal killed aqt: ExitCode is -1, which would surface as 255 and
			// hide the cause from Git. Report the signal and exit with a real status.
			fmt.Fprintln(os.Stderr, "git-remote-aqt: aqt terminated:", exit.ProcessState)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "git-remote-aqt:", err)
		os.Exit(1)
	}
}

func siblingAQT() string {
	name := "aqt"
	if runtime.GOOS == "windows" {
		name = "aqt.exe"
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return "aqt"
}
