package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// conflictMode is how a two-sided change is resolved during a chunked sync.
type conflictMode string

const (
	conflictBlock conflictMode = "block" // report the conflict and refuse (exit 4)
	conflictCopy  conflictMode = "copy"  // keep local, preserve remote as a conflict-copy
)

// effectiveConflictMode resolves the mode from the flag (when set) falling back to
// .aqtconfig, else block. The flag's empty default doubles as "unset", so a value
// present in either place wins over the block default; an explicit --conflicts=block
// overrides a config that selects copy.
func effectiveConflictMode(opts syncOptions, cfg syncengine.Config) (conflictMode, error) {
	v := opts.conflicts
	if v == "" {
		v = cfg.Conflicts
	}
	switch v {
	case "", "block":
		return conflictBlock, nil
	case "copy":
		return conflictCopy, nil
	default:
		return "", fmt.Errorf("invalid --conflicts value %q (want \"block\" or \"copy\")", v)
	}
}

// validateCopyMode rejects flag combinations for which copy resolution is undefined.
// Copy keeps local and preserves remote, so --force (remote discarded) contradicts it;
// a baseless reconcile already treats every one-sided diff as a conflict, so there is
// no three-way both-sides change to copy; and a copy needs both a disk write and a
// remote mutation, which a one-directional sync cannot do coherently.
func validateCopyMode(opts syncOptions) error {
	switch {
	case opts.force:
		return errors.New("--conflicts=copy and --force are contradictory: --force discards the remote version, --conflicts=copy keeps it")
	case opts.reconcile || opts.acceptRollback:
		return errors.New("--conflicts=copy requires a three-way sync; --reconcile and --accept-rollback reconcile without a base, where every one-sided difference is already a conflict")
	case opts.pushOnly || opts.pullOnly:
		return errors.New("--conflicts=copy requires a full two-way sync and cannot be combined with --push-only or --pull-only")
	}
	return nil
}

// conflictCopyItem pairs a conflicting path with the remote entry rewritten to the
// copy path its bytes will be materialized at.
type conflictCopyItem struct {
	orig  string
	entry syncengine.Entry
}

// conflictCopyMemo records, per original path, the copy already materialized in an
// earlier retry attempt and the remote hash it captured. A push conflict re-plans the
// same standing conflict; without the memo, conflictCopyPath sees the earlier attempt's
// copy on disk and bumps a fresh suffix each pass, so up to maxSyncAttempts byte-identical
// duplicates accumulate. The memo makes re-planning reuse the prior copy instead.
type conflictCopyMemo map[string]conflictCopyRecord

type conflictCopyRecord struct {
	copyPath   string
	remoteHash string
}

// planConflictCopies turns each content conflict that has remote bytes into a copy:
// the remote entry rewritten to a fresh <path>.conflict-<host>-<ts> path. A conflict
// with no remote entry (local edit vs remote delete) has nothing to preserve and is
// skipped; the caller still resolves its primary path local-wins.
//
// The memo carries copies materialized by earlier retry attempts. A path already copied
// for the same remote hash reuses that copy: if it still exists on disk it is skipped
// entirely, and if it was lost it is rewritten at the same name rather than a bumped one.
// Only a remote hash that changed since the last attempt (the racing device re-edited the
// file) plans a fresh, collision-checked copy.
func planConflictCopies(root string, actions []syncengine.Action, remoteByPath map[string]syncengine.Entry, host string, now time.Time, memo conflictCopyMemo) []conflictCopyItem {
	var copies []conflictCopyItem
	for _, a := range actions {
		if a.Kind != syncengine.Conflict {
			continue
		}
		re, ok := remoteByPath[a.Path]
		if !ok {
			continue
		}
		e := re
		if rec, ok := memo[a.Path]; ok && rec.remoteHash == re.Hash {
			if pathExists(root, rec.copyPath) {
				continue // the earlier attempt's copy is already correct on disk
			}
			e.Path = rec.copyPath
		} else {
			e.Path = conflictCopyPath(root, a.Path, host, now)
		}
		copies = append(copies, conflictCopyItem{orig: a.Path, entry: e})
	}
	return copies
}

func copyEntries(copies []conflictCopyItem) []syncengine.Entry {
	out := make([]syncengine.Entry, len(copies))
	for i, c := range copies {
		out[i] = c.entry
	}
	return out
}

// conflictCopyPath returns the relative path for the remote side of a conflict:
// <path>.conflict-<host>-<ts>, appended to the whole name (no extension splitting).
// A numeric suffix is bumped until nothing exists at that path under root, so an
// existing file is never overwritten (materialize would clobber it).
func conflictCopyPath(root, path, host string, now time.Time) string {
	base := fmt.Sprintf("%s.conflict-%s-%s", path, host, now.UTC().Format("20060102-150405"))
	candidate := base
	for i := 1; pathExists(root, candidate); i++ {
		candidate = fmt.Sprintf("%s-%d", base, i)
	}
	return candidate
}

func pathExists(root, rel string) bool {
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

// conflictHost is the sanitized hostname stamped into a conflict-copy name, so a copy
// made on one machine reads as "the version from <host>".
func conflictHost() string {
	name, _ := os.Hostname()
	return sanitizeHost(name)
}

// sanitizeHost reduces a hostname to [a-z0-9-]: lowercased, any other rune becomes a
// dash, runs of dashes collapse, and leading/trailing dashes are trimmed. An empty
// result (a hostname with no usable characters) falls back to "device".
func sanitizeHost(raw string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(raw) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "device"
	}
	return out
}
