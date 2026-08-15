// SPDX-License-Identifier: AGPL-3.0-or-later

package merge

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnified(t *testing.T) {
	t.Parallel()
	got := string(Unified("a/file.txt", "b/file.txt",
		[]byte("one\ntwo\nthree\nfour\nfive\n"),
		[]byte("one\nTWO\nthree\nfour\nFIVE\n")))
	wants := []string{
		"--- a/file.txt\n+++ b/file.txt\n",
		"@@ -1,5 +1,5 @@\n",
		"-two\n+TWO\n",
		"-five\n+FIVE\n",
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("unified diff missing %q:\n%s", want, got)
		}
	}
}

func TestUnifiedAdditionAndRemovalHeaders(t *testing.T) {
	t.Parallel()
	if got := string(Unified("/dev/null", "b/new.txt", nil, []byte("new\n"))); !strings.Contains(got, "@@ -0,0 +1 @@") {
		t.Fatalf("addition header:\n%s", got)
	}
	if got := string(Unified("a/old.txt", "/dev/null", []byte("old\n"), nil)); !strings.Contains(got, "@@ -1 +0,0 @@") {
		t.Fatalf("removal header:\n%s", got)
	}
}

func TestUnifiedNoTrailingNewline(t *testing.T) {
	t.Parallel()
	got := string(Unified("a/f", "b/f", []byte("old"), []byte("new")))
	if strings.Count(got, "\\ No newline at end of file") != 2 {
		t.Fatalf("missing newline markers:\n%s", got)
	}
}

// Changes more than twice the context apart must produce two hunks, exercising
// the second range's start offsets from prefixPositions/rangeStart.
func TestUnifiedTwoSeparatedHunks(t *testing.T) {
	t.Parallel()
	oldData := []byte("l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\n")
	newData := []byte("L1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nL12\n")
	got := string(Unified("a/f.txt", "b/f.txt", oldData, newData))
	if n := strings.Count(got, "@@"); n != 4 { // two hunks, two markers each
		t.Fatalf("hunk header count = %d, want 4:\n%s", n, got)
	}
	for _, want := range []string{"@@ -1,4 +1,4 @@\n", "@@ -9,4 +9,4 @@\n", "-l1\n+L1\n", "-l12\n+L12\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("two-hunk diff missing %q:\n%s", want, got)
		}
	}
}

func TestUnifiedEqualIsEmpty(t *testing.T) {
	t.Parallel()
	if got := Unified("a/f", "b/f", []byte("same\n"), []byte("same\n")); got != nil {
		t.Fatalf("equal diff = %q, want nil", got)
	}
}

func TestUnifiedComplexDiffFallsBackToBinary(t *testing.T) {
	t.Parallel()
	oldData := bytes.Repeat([]byte("old\n"), maxEditDistance/2+1)
	newData := bytes.Repeat([]byte("new\n"), maxEditDistance/2+1)
	got := string(Unified("a/generated.csv", "b/generated.csv", oldData, newData))
	want := "Binary files a/generated.csv and b/generated.csv differ\n"
	if got != want {
		t.Fatalf("complex diff fallback = %q, want %q", got, want)
	}
}
