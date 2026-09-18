// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	return captureOutput(t, &os.Stdout, fn)
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	return captureOutput(t, &os.Stderr, fn)
}

// captureOutput drains concurrently so output larger than the pipe buffer cannot
// block the callback. Cleanup also runs when the callback calls t.Fatal or panics.
func captureOutput(t *testing.T, output **os.File, fn func()) string {
	t.Helper()
	orig := *output
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	*output = w
	defer func() {
		*output = orig
		_ = w.Close()
		_ = r.Close()
	}()
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	return <-done
}

func TestCaptureOutputRestoresAfterAbort(t *testing.T) {
	for _, abort := range []struct {
		name string
		fn   func()
	}{
		{"panic", func() { panic("callback aborted") }},
		{"fatal", runtime.Goexit},
	} {
		t.Run(abort.name, func(t *testing.T) {
			orig := os.Stdout
			var pipe *os.File
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				captureStdout(t, func() { pipe = os.Stdout; abort.fn() })
			}()
			<-done
			if os.Stdout != orig {
				t.Fatal("stdout was not restored")
			}
			if _, err := pipe.Write([]byte("closed")); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("write to closed capture pipe: %v", err)
			}
			if got := captureStdout(t, func() { fmt.Print("next output") }); got != "next output" {
				t.Fatalf("subsequent capture = %q", got)
			}
		})
	}
}
