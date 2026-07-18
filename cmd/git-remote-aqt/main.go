// Command git-remote-aqt is the executable Git discovers for aqt:: URLs. All
// protocol and crypto logic stays in aqt itself so both binaries ship one behavior.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	aqt := siblingAQT()
	args := append([]string{"git-remote-helper"}, os.Args[1:]...)
	cmd := exec.Command(aqt, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "git-remote-aqt:", err)
		os.Exit(1)
	}
}

func siblingAQT() string {
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "aqt")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return "aqt"
}
