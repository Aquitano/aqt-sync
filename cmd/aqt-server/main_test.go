// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net"
	"testing"
)

// A server that never came up must exit non-zero. It used to log the serve error and
// return from main, exiting 0: systemd with Restart=on-failure then read a port
// conflict or a lost CAP_NET_BIND_SERVICE as a clean stop, left the unit inactive
// with result `success`, and never restarted it.
func TestRunExitsNonZeroWhenItCannotListen(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()

	t.Setenv("AQT_DATA_DIR", t.TempDir())
	t.Setenv("AQT_ADDR", busy.Addr().String())
	t.Setenv("AQT_ALLOW_INSECURE_HTTP", "1")
	// The background jobs are irrelevant here and would otherwise tick for the
	// lifetime of the test binary.
	t.Setenv("AQT_SNAPSHOT_INTERVAL", "0")
	t.Setenv("AQT_GC_INTERVAL", "0")

	if code := run(); code == 0 {
		t.Fatal("run returned 0 after failing to bind its listen address")
	}
}

// A misconfiguration caught before the listener is opened is just as invisible to a
// supervisor if it exits 0.
func TestRunExitsNonZeroOnBadConfig(t *testing.T) {
	t.Setenv("AQT_DATA_DIR", t.TempDir())
	t.Setenv("AQT_SNAPSHOT_KEEP", "not-a-number")

	if code := run(); code == 0 {
		t.Fatal("run returned 0 with an unparseable AQT_SNAPSHOT_KEEP")
	}
}

// The release workflow stamps every shipped binary with -X main.version, but the
// linker silently ignores that for a package declaring no such variable, which is how
// aqt-server shipped without one. The variables have to stay in package main for the
// flag to land; this pins the reporting around them, including that a build which is
// not a tagged release cannot present itself as one.
func TestVersionStringMarksNonReleaseBuilds(t *testing.T) {
	origVersion, origKind := version, buildKind
	t.Cleanup(func() { version, buildKind = origVersion, origKind })

	version, buildKind = "v0.9.0", "release"
	if got := versionString(); got != "v0.9.0" {
		t.Fatalf("release build: versionString() = %q, want %q", got, "v0.9.0")
	}

	// What `git describe` produces off a tag, which reads like a release at a glance.
	version, buildKind = "v0.9.0-3-gabc1234", "dev"
	if got := versionString(); got != "v0.9.0-3-gabc1234 (dev build)" {
		t.Fatalf("source build: versionString() = %q, want %q", got, "v0.9.0-3-gabc1234 (dev build)")
	}
}
