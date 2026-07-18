package merge

import (
	"bytes"
	"testing"
)

func TestThreeWay(t *testing.T) {
	tests := []struct {
		name         string
		base, local  string
		remote, want string
		clean        bool
	}{
		{
			name: "non-overlapping edits",
			base: "one\ntwo\nthree\nfour\n", local: "ONE\ntwo\nthree\nfour\n",
			remote: "one\ntwo\nthree\nFOUR\n", want: "ONE\ntwo\nthree\nFOUR\n", clean: true,
		},
		{
			name: "adjacent hunks",
			base: "one\ntwo\nthree\n", local: "ONE\ntwo\nthree\n",
			remote: "one\nTWO\nthree\n", want: "ONE\nTWO\nthree\n", clean: true,
		},
		{
			name: "same line overlap",
			base: "one\ntwo\n", local: "local\ntwo\n", remote: "remote\ntwo\n", clean: false,
		},
		{
			name: "identical overlapping edit",
			base: "one\ntwo\n", local: "same\ntwo\n", remote: "same\ntwo\n",
			want: "same\ntwo\n", clean: true,
		},
		{
			name: "local only sanity",
			base: "one\ntwo\n", local: "one\nlocal\n", remote: "one\ntwo\n",
			want: "one\nlocal\n", clean: true,
		},
		{
			name: "remote only sanity",
			base: "one\ntwo\n", local: "one\ntwo\n", remote: "one\nremote\n",
			want: "one\nremote\n", clean: true,
		},
		{
			name: "crlf preserved",
			base: "one\r\ntwo\r\nthree\r\n", local: "ONE\r\ntwo\r\nthree\r\n",
			remote: "one\r\ntwo\r\nTHREE\r\n", want: "ONE\r\ntwo\r\nTHREE\r\n", clean: true,
		},
		{
			name: "trailing newline removed beside edit",
			base: "one\ntwo\nthree\n", local: "ONE\ntwo\nthree\n",
			remote: "one\ntwo\nthree", want: "ONE\ntwo\nthree", clean: true,
		},
		{
			name: "independent insertions",
			base: "one\ntwo\nthree\n", local: "local\none\ntwo\nthree\n",
			remote: "one\ntwo\nthree\nremote\n", want: "local\none\ntwo\nthree\nremote\n", clean: true,
		},
		{
			name: "same point insertions overlap",
			base: "one\n", local: "local\none\n", remote: "remote\none\n", clean: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, clean := ThreeWay([]byte(tt.base), []byte(tt.local), []byte(tt.remote))
			if clean != tt.clean {
				t.Fatalf("clean = %v, want %v; result %q", clean, tt.clean, got)
			}
			if clean && string(got) != tt.want {
				t.Fatalf("result = %q, want %q", got, tt.want)
			}
			if !clean && got != nil {
				t.Fatalf("conflicted result = %q, want nil", got)
			}
		})
	}
}

func TestChangesReconstructsTarget(t *testing.T) {
	cases := [][2]string{
		{"", "new\n"},
		{"old\n", ""},
		{"a\nb\nc\n", "a\nB\nc\nD\n"},
		{"a\nb", "x\na\nb\n"},
		{"same\n", "same\n"},
	}
	for _, tc := range cases {
		base, target := []byte(tc[0]), []byte(tc[1])
		if got := apply(base, Changes(base, target)); !bytes.Equal(got, target) {
			t.Errorf("apply(%q) = %q, want %q", base, got, target)
		}
	}
}

func TestIsText(t *testing.T) {
	if !IsText([]byte("plain\ntext\n")) {
		t.Fatal("plain text rejected")
	}
	if IsText([]byte("binary\x00data")) {
		t.Fatal("NUL-bearing data accepted")
	}
	if IsText(make([]byte, MaxTextSize+1)) {
		t.Fatal("oversized data accepted")
	}
	lateNUL := append(bytes.Repeat([]byte{'x'}, binarySniff), 0)
	if !IsText(lateNUL) {
		t.Fatal("NUL after sniff window should not classify the file as binary")
	}
}

func apply(base []byte, hunks []Hunk) []byte {
	lines := splitLines(base)
	var out bytes.Buffer
	pos := 0
	for _, h := range hunks {
		for _, line := range lines[pos:h.Start] {
			out.Write(line)
		}
		for _, line := range h.Lines {
			out.Write(line)
		}
		pos = h.End
	}
	for _, line := range lines[pos:] {
		out.Write(line)
	}
	return out.Bytes()
}
