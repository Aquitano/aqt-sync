// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runFzf prints the selected row's hidden final column. Escape and no match
// return successfully without output.
func runFzf(fzfPath, input string, args []string) error {
	cmd := exec.Command(fzfPath, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		// fzf exits 130 when interrupted (Esc/Ctrl-C) and 1 when nothing matched;
		// both mean "no selection", not a failure.
		if errors.As(err, &ee) && (ee.ExitCode() == 130 || ee.ExitCode() == 1) {
			return nil
		}
		return fmt.Errorf("fzf: %w", err)
	}
	line := strings.TrimRight(out.String(), "\r\n")
	if line == "" {
		return nil
	}
	fields := strings.Split(line, "\t")
	fmt.Println(fields[len(fields)-1])
	return nil
}
