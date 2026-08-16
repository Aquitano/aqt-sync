// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// A comparison names both of its sides and answers one question: how do these two
// states of the same folder differ, path by path. `aqt diff --name-status` compares
// the working tree with the base, a snapshot, or the current remote; `aqt snapshot
// diff` compares a snapshot with the live resource or a second snapshot. Every one of
// them produces the type below, so the CLI renderers, the TUI, and a JSON consumer
// never have to learn a second result shape.
//
// This is deliberately not what `status` or `sync --dry-run` report. Those answer
// base-relative questions — what changed here, what changed there, what would a
// reconcile do — while a comparison answers only "how do these two states differ",
// with no base, no plan, and no side effects.

// Comparison reason codes. They are part of the --json contract: a caller branches on
// the code, never on the human sentence rendered beside it.
const reasonSessionLocked = "session-locked"

// diffSide labels one side of a comparison. Version is 0 for a side that has none,
// which is how the working tree distinguishes itself from a server version.
type diffSide struct {
	Label   string `json:"label"`
	Version int    `json:"version"`
}

func (s diffSide) String() string {
	if s.Version == 0 {
		return s.Label
	}
	return fmt.Sprintf("%s (v%d)", s.Label, s.Version)
}

type comparison struct {
	Left  diffSide `json:"left"`
	Right diffSide `json:"right"`
	// Complete separates a real file-level comparison from one that could only
	// establish which two states were being compared. Reason names the cause when it
	// is false; both fields are always emitted, so a caller never has to read an empty
	// change list as "no differences" when it means "could not look".
	Complete bool   `json:"complete"`
	Reason   string `json:"reason,omitempty"`

	Added    []string            `json:"added"`
	Removed  []string            `json:"removed"`
	Modified []string            `json:"modified"`
	Renamed  []syncengine.Rename `json:"renamed"`
	// Changes classifies each path the three buckets above flatten: which are
	// directories, and which "modified" entries are mode or type edits.
	Changes []syncengine.Change `json:"changes"`
}

func newComparison(left, right diffSide, d syncengine.Delta) comparison {
	s := newChangeSet(d)
	return comparison{
		Left: left, Right: right, Complete: true,
		Added:    nonNil(s.added),
		Removed:  nonNil(s.deleted),
		Modified: nonNil(s.modified),
		Renamed:  nonNilRenames(s.renamed),
		Changes:  nonNilChanges(s.changes),
	}
}

// unavailableComparison records that both sides were identified but their contents
// could not be compared.
func unavailableComparison(left, right diffSide, reason string) comparison {
	c := newComparison(left, right, syncengine.Delta{})
	c.Complete, c.Reason = false, reason
	return c
}

func (c comparison) total() int { return len(c.Changes) + len(c.Renamed) }

// filter narrows a comparison to the paths the caller named, keeping a rename when
// either of its sides matches so a filtered move still reports as one.
func (c comparison) filter(filters []string) comparison {
	if len(filters) == 0 {
		return c
	}
	var d syncengine.Delta
	for _, ch := range c.Changes {
		if matchesDiffPath(ch.Path, filters) {
			d.Changes = append(d.Changes, ch)
		}
	}
	for _, r := range c.Renamed {
		if matchesDiffPath(r.From, filters) || matchesDiffPath(r.To, filters) {
			d.Renamed = append(d.Renamed, r)
		}
	}
	out := newComparison(c.Left, c.Right, d)
	out.Complete, out.Reason = c.Complete, c.Reason
	return out
}

// --- working tree versus current remote ---

// compareWorkingTreeToRemote compares the working tree with the folder's current
// remote state directly, rather than each against the last-synced base the way
// `status` does. It is strictly read-only: it uploads nothing, writes nothing into
// the tree, and leaves .aqt/base.json and the pinned remote version untouched, so
// running it can never change what a later sync decides to do.
func compareWorkingTreeToRemote(cl *client.Client, prof *identity.Profile, root string) (comparison, error) {
	res, err := folderResource(cl, root)
	if err != nil {
		return comparison{}, err
	}
	mk, unlocked, err := unlockForComparison(prof)
	if err != nil {
		return comparison{}, err
	}
	if !unlocked {
		return unavailableComparison(remoteSide(res), workingTreeSide, reasonSessionLocked), nil
	}
	defer mk.Wipe()
	return computeRemoteComparison(cl, mk, root, res)
}

// computeRemoteComparison needs the already-unlocked master key: it must never
// prompt, because the TUI calls it from inside a raw-mode terminal session.
func computeRemoteComparison(cl *client.Client, mk crypto.MasterKey, root string, res api.GetResourceResponse) (comparison, error) {
	base, err := loadBase(root)
	if err != nil {
		return comparison{}, err
	}
	remote, err := remoteManifest(cl, res, mk, base)
	if err != nil {
		return comparison{}, err
	}
	// Hash every file rather than trusting size+mtime the way `status` does. A
	// comparison exists to answer "do these two states differ", so an edit that
	// preserved the stat signature must not read as identical — and the unified-diff
	// rendering of this same comparison hashes regardless, so taking the shortcut here
	// would let the two renderings disagree.
	local, err := syncengine.ScanReusing(root, &base, true)
	if err != nil {
		return comparison{}, err
	}
	warnSkipped(local.Skipped)
	return newComparison(remoteSide(res), workingTreeSide, syncengine.Diff(remote, local)), nil
}

var workingTreeSide = diffSide{Label: "working tree"}

func remoteSide(res api.GetResourceResponse) diffSide {
	return diffSide{Label: "remote", Version: res.Version}
}

// remoteManifest reconstructs the remote folder's manifest without writing anything
// to disk. A chunked folder is read straight from its Merkle DAG, reusing the base
// tree's node ciphertexts so an unchanged subtree costs no fetch. A pack-and-seal
// folder carries no per-file remote metadata at all — its whole tree is one opaque
// stream — so the only truthful per-entry answer comes from streaming the segments
// back and hashing them in memory: it costs the folder's full download, but still
// touches no disk.
func remoteManifest(cl *client.Client, res api.GetResourceResponse, mk crypto.MasterKey, base syncengine.Manifest) (syncengine.Manifest, error) {
	var zero syncengine.Manifest
	if res.WrappedKey == nil {
		return zero, errors.New("folder resource has no owner key; cannot compare")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return zero, fmt.Errorf("unwrap folder key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck, res.ID)
	if err != nil {
		return zero, err
	}
	if meta.Kind != api.KindFolder {
		return zero, errors.New("remote resource is not a folder")
	}
	if meta.Packed {
		return zero, errPackRemoved
	}
	if !meta.Tree {
		return zero, errors.New("unsupported remote folder format")
	}
	return readRemoteManifest(cl, res, ck, base, mk)
}

// unlockForComparison returns the master key for a read-only comparison, prompting
// only when someone is there to answer: --json and a non-terminal stdin both mean the
// caller is a script, and a passphrase prompt would hang it. A locked session then
// reports itself in the result instead of blocking.
func unlockForComparison(prof *identity.Profile) (crypto.MasterKey, bool, error) {
	if mk, ok := identity.LoadSession(prof.Name); ok {
		return mk, true, nil
	}
	if flagJSON || !interactiveStdin() {
		return crypto.MasterKey{}, false, nil
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return crypto.MasterKey{}, false, err
	}
	return mk, true, nil
}

// --- rendering ---

// printComparison renders a comparison for humans: the two sides, then one line per
// differing path. An incomplete comparison says so rather than printing an empty list
// that would read as "no differences".
func printComparison(c comparison) {
	fmt.Printf("%s  ->  %s\n", c.Left, c.Right)
	if !c.Complete {
		fmt.Println(comparisonUnavailable(c.Reason))
		return
	}
	if c.total() == 0 {
		fmt.Println("no differences")
		return
	}
	for _, ch := range orderedChanges(c.Changes) {
		fmt.Printf("%s  %s\n", nameStatusMark(ch.Kind), changePath(ch))
	}
	for _, r := range c.Renamed {
		fmt.Printf("R  %s\n", renameArrow(r))
	}
	fmt.Printf("%d difference(s)\n", c.total())
}

// comparisonUnavailable turns a reason code into the sentence humans see; the code
// itself stays the machine-readable form in --json.
func comparisonUnavailable(reason string) string {
	switch reason {
	case reasonSessionLocked:
		return "cannot compare files: the session is locked. Re-run on a terminal to be prompted, or `aqt login` to cache a session."
	default:
		return "cannot compare files: " + reason
	}
}
