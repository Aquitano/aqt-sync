// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"os"
)

// pullMarker is .aqt/pull-in-progress: the record that a pack-and-seal pull
// started and has not finished, so the working tree may hold half the remote
// version and half the old one. Pack-and-seal itself was removed, so nothing
// writes this marker anymore — but a folder last touched by an older build may
// still carry one, and its torn tree must not be misread as local edits.
type pullMarker struct {
	Version int `json:"version"`
	present bool
}

const pullMarkerFile = "pull-in-progress"

func clearPullMarker(root string) error {
	if err := os.Remove(controlPath(root, pullMarkerFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// loadPullMarker reports whether a pull was interrupted here. A marker that will
// not parse still counts as present: it was written by a pull that started, and
// the version it names is only used for the message.
func loadPullMarker(root string) (pullMarker, error) {
	b, err := os.ReadFile(controlPath(root, pullMarkerFile))
	if errors.Is(err, os.ErrNotExist) {
		return pullMarker{}, nil
	}
	if err != nil {
		return pullMarker{}, err
	}
	m := pullMarker{present: true}
	_ = json.Unmarshal(b, &m)
	return m, nil
}
