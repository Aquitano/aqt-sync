// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fsatomic replaces a file in one step: write a sibling temp file, fsync it,
// then rename it over the destination. A crash or error mid-write leaves any existing
// destination intact rather than a torn file.
//
// The temp files are named .aqt-tmp-*, which the sync scanner ignores, so an
// in-flight write inside a synced folder is never picked up as content.
package fsatomic

import (
	"os"
	"path/filepath"
)

// WriteStream hands fn an open temp file next to path, then fsyncs and renames it
// over path. fn may stream into the file without holding the whole payload in memory.
func WriteStream(path string, perm os.FileMode, fn func(*os.File) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".aqt-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once renamed; cleans up every failure path
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// WriteFile atomically replaces path with data.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	return WriteStream(path, perm, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}
