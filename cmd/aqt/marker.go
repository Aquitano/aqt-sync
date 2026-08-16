// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/aquitano/aqt-sync/internal/fsatomic"
)

// marker is a control file recording that a destructive operation started in this
// folder and has not finished, so the working tree may be half-written. Present is
// what the guards read: a marker that will not parse still counts, because it was
// written by an operation that started. Payload carries whatever that operation
// recorded, and is only used for the message.
type marker[T any] struct {
	Payload T
	Present bool
}

// interruptedPull is .aqt/pull-in-progress: a pack-and-seal pull left the working
// tree part remote, part stale. Pack-and-seal itself was removed, so nothing writes
// this marker anymore — but a folder last touched by an older build may still carry
// one, and its torn tree must not be misread as local edits.
type interruptedPull struct {
	Version int `json:"version"`
}

// interruptedRestore is .aqt/restore-in-progress: written before swapTree moves the
// live tree aside, removed once the swap completed. While present, the working tree
// may be half-emptied, so syncs refuse instead of reading it as local deletions.
type interruptedRestore struct {
	SnapshotID string `json:"snapshotId"`
}

const (
	pullMarkerFile    = "pull-in-progress"
	restoreMarkerFile = "restore-in-progress"
)

func writeMarker[T any](root, name string, payload T) error {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(controlPath(root, name), b, 0o600)
}

func clearMarker(root, name string) error {
	if err := os.Remove(controlPath(root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func loadMarker[T any](root, name string) (marker[T], error) {
	b, err := os.ReadFile(controlPath(root, name))
	if errors.Is(err, os.ErrNotExist) {
		return marker[T]{}, nil
	}
	if err != nil {
		return marker[T]{}, err
	}
	m := marker[T]{Present: true}
	_ = json.Unmarshal(b, &m.Payload)
	return m, nil
}
