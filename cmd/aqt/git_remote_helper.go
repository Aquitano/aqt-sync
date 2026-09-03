// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/gitremote"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/packio"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func gitRemoteHelperCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "git-remote-helper <remote> <url>",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			h := &remoteHelper{
				remoteName: args[0], rawURL: args[1],
				in: os.Stdin, out: bufio.NewWriter(os.Stdout), errOut: os.Stderr,
			}
			return h.run()
		},
	}
}

type remoteHelper struct {
	remoteName   string
	rawURL       string
	in           io.Reader
	out          *bufio.Writer
	errOut       io.Writer
	verbosity    int
	progress     bool
	objectFormat bool
}

type openedGitRemote struct {
	client *client.Client
	item   api.ResourceListItem
	res    api.GetResourceResponse
	meta   api.Metadata
	root   gitremote.RefsRoot
	key    crypto.ContentKey
}

func (r *openedGitRemote) close() { r.key.Wipe() }

type helperFetch struct {
	oid string
	ref string
}

type helperPush struct {
	raw          string
	src          string
	dst          string
	force        bool
	delete       bool
	localOID     string
	annotatedTag bool
}

func (h *remoteHelper) run() error {
	scanner := bufio.NewScanner(h.in)
	// Protocol lines contain hashes/ref names, but keep a generous bound so an
	// adversarial invoking process gets a clean error rather than Scanner's tiny default.
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var fetches []helperFetch
	var pushes []helperPush
	flushFetches := func() error {
		if len(fetches) == 0 {
			return nil
		}
		err := h.fetch(fetches)
		fetches = nil
		if err != nil {
			return err
		}
		return h.respond("")
	}
	flushPushes := func() error {
		if len(pushes) == 0 {
			return nil
		}
		err := h.push(pushes)
		pushes = nil
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flushFetches(); err != nil {
				return err
			}
			if err := flushPushes(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, "fetch ") {
			parts := strings.Fields(line)
			if len(parts) != 3 {
				return fmt.Errorf("invalid remote-helper fetch command %q", line)
			}
			if !validGitOID(parts[1]) {
				return fmt.Errorf("invalid object id in remote-helper fetch command %q", line)
			}
			fetches = append(fetches, helperFetch{oid: parts[1], ref: parts[2]})
			continue
		}
		if strings.HasPrefix(line, "push ") {
			push, err := parsePushRefspec(strings.TrimPrefix(line, "push "))
			if err != nil {
				return err
			}
			pushes = append(pushes, push)
			continue
		}
		if err := flushFetches(); err != nil {
			return err
		}
		if err := flushPushes(); err != nil {
			return err
		}
		switch {
		case line == "capabilities":
			if err := h.respond("fetch", "push", "option", "object-format", ""); err != nil {
				return err
			}
		case line == "list" || line == "list for-push":
			if err := h.list(); err != nil {
				return err
			}
		case strings.HasPrefix(line, "option "):
			if err := h.option(strings.TrimPrefix(line, "option ")); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported remote-helper command %q", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := flushFetches(); err != nil {
		return err
	}
	return flushPushes()
}

func (h *remoteHelper) respond(lines ...string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(h.out, line); err != nil {
			return err
		}
	}
	return h.out.Flush()
}

func (h *remoteHelper) option(value string) error {
	name, setting, ok := strings.Cut(value, " ")
	if !ok {
		return h.respond("unsupported")
	}
	switch name {
	case "verbosity":
		if _, err := fmt.Sscan(setting, &h.verbosity); err != nil {
			return h.respond("unsupported")
		}
		return h.respond("ok")
	case "progress":
		h.progress = setting == "true"
		return h.respond("ok")
	case "object-format":
		if setting != "true" {
			return h.respond("unsupported")
		}
		h.objectFormat = true
		return h.respond("ok")
	default:
		return h.respond("unsupported")
	}
}

func (h *remoteHelper) list() error {
	remote, err := h.openRemote()
	if err != nil {
		return err
	}
	defer remote.close()
	names := make([]string, 0, len(remote.root.Refs))
	for name := range remote.root.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := make([]string, 0, len(names)+2)
	if h.objectFormat && remote.root.ObjectFormat != "" {
		lines = append(lines, ":object-format "+remote.root.ObjectFormat)
	}
	for _, name := range names {
		lines = append(lines, remote.root.Refs[name]+" "+name)
	}
	if remote.root.Head != "" {
		lines = append(lines, "@"+remote.root.Head+" HEAD")
	}
	if len(remote.root.Refs) == 0 {
		fmt.Fprintln(h.errOut, "aqt: remote repository is empty; push a branch to initialize it")
	}
	lines = append(lines, "")
	return h.respond(lines...)
}

func (h *remoteHelper) fetch(requests []helperFetch) error {
	remote, err := h.openRemote()
	if err != nil {
		return err
	}
	defer remote.close()
	localFormat, err := commandOutput("git", "rev-parse", "--show-object-format")
	if err != nil {
		return fmt.Errorf("detect local git object format: %w", err)
	}
	if remote.root.ObjectFormat != "" && remote.root.ObjectFormat != localFormat {
		return fmt.Errorf("git object format mismatch: remote is %s, local repository is %s; use a matching repository format", remote.root.ObjectFormat, localFormat)
	}

	// One presence pass for the whole chain. Applying a bundle can only add objects,
	// and a bundle whose tips are already here is skipped either way, so answering up
	// front costs nothing in accuracy and saves a process per tip.
	var chainTips []string
	for _, bundle := range remote.root.Bundles {
		chainTips = append(chainTips, bundle.Tips...)
	}
	presentTips, err := presentObjects(chainTips)
	if err != nil {
		return err
	}
	var needed []gitremote.BundleRef
	for _, bundle := range remote.root.Bundles {
		if !allObjectsPresent(bundle.Tips, presentTips) {
			needed = append(needed, bundle)
		}
	}
	ids := make([]string, 0)
	for _, bundle := range needed {
		for _, segment := range bundle.Segments {
			ids = append(ids, segment.ID)
		}
	}
	source, err := packio.NewSource(remote.client, ids)
	if err != nil {
		return err
	}
	for _, bundle := range needed {
		for _, base := range bundle.Bases {
			if !gitObjectPresent(base) {
				return fmt.Errorf("git bundle chain broken at %s (missing prerequisite %s) — run `aqt repo gc` on a healthy clone", bundle.ID, base)
			}
		}
		if h.progress || h.verbosity > 0 {
			fmt.Fprintf(h.errOut, "aqt: applying bundle %s\n", bundle.ID)
		}
		if err := applyBundle(bundle, remote.key, source.Get); err != nil {
			return err
		}
	}
	for _, request := range requests {
		if !gitObjectPresent(request.oid) {
			return fmt.Errorf("remote bundle chain does not contain requested object %s for %s", request.oid, request.ref)
		}
	}
	return nil
}

func parsePushRefspec(refspec string) (helperPush, error) {
	p := helperPush{raw: refspec}
	if strings.HasPrefix(refspec, "+") {
		p.force = true
		refspec = strings.TrimPrefix(refspec, "+")
	}
	src, dst, ok := strings.Cut(refspec, ":")
	if !ok || dst == "" || !strings.HasPrefix(dst, "refs/") {
		return helperPush{}, fmt.Errorf("invalid push refspec %q", p.raw)
	}
	p.src, p.dst, p.delete = src, dst, src == ""
	return p, nil
}

func (h *remoteHelper) push(pushes []helperPush) error {
	objectFormat, err := commandOutput("git", "rev-parse", "--show-object-format")
	if err != nil {
		return err
	}
	for i := range pushes {
		if pushes[i].delete {
			continue
		}
		oid, err := commandOutput("git", "rev-parse", "--verify", pushes[i].src+"^{object}")
		if err != nil {
			return fmt.Errorf("resolve push source %s: %w", pushes[i].src, err)
		}
		pushes[i].localOID = oid
		objectType, err := commandOutput("git", "cat-file", "-t", oid)
		if err != nil {
			return fmt.Errorf("inspect push source %s: %w", pushes[i].src, err)
		}
		pushes[i].annotatedTag = objectType == "tag"
	}

	for attempt := 0; attempt < maxSyncAttempts; attempt++ {
		remote, err := h.openRemote()
		if err != nil {
			return err
		}
		if remote.root.ObjectFormat != "" && remote.root.ObjectFormat != objectFormat {
			remote.close()
			return fmt.Errorf("git object format mismatch: local is %s, remote is %s", objectFormat, remote.root.ObjectFormat)
		}
		nonFF := nonFastForwardPushes(pushes, remote.root.Refs)
		if len(nonFF) > 0 {
			remote.close()
			return h.rejectPushBatch(pushes, nonFF)
		}

		bundle, err := buildAndUploadPushBundle(remote.client, remote.key, remote.root, pushes)
		if err != nil {
			remote.close()
			return err
		}
		if bundle != nil && os.Getenv("AQT_TEST_GITREMOTE_EXIT_AFTER_UPLOAD") == "1" {
			// Test-only crash boundary: the segments are durable but the root still
			// points at the prior version. A real SIGKILL here has the same storage shape.
			os.Exit(99)
		}
		next := applyPushes(remote.root, pushes, objectFormat)
		if bundle != nil {
			next.Bundles = append(next.Bundles, *bundle)
		}
		blob, err := gitremote.SealRefsRoot(next, remote.key, remote.res.ID)
		if err != nil {
			remote.close()
			return err
		}
		meta, err := verifiedMetaBound(remote.res.EncryptedMeta, remote.key, remote.res.ID)
		if err != nil {
			remote.close()
			return err
		}
		compactAt := remote.res.CompactAt
		_, err = remote.client.PutResource(api.PutResourceRequest{
			ID: remote.res.ID, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: remote.res.WrappedKey, ChunkRefs: next.SegmentIDs(),
			ExpectedVersion: remote.res.Version, MinClient: api.CapabilityGitRemote,
			CompactAt: compactAt,
		})
		remote.close()
		if errors.Is(err, client.ErrConflict) {
			continue
		}
		if err != nil {
			return err
		}
		lines := make([]string, 0, len(pushes)+1)
		for _, push := range pushes {
			lines = append(lines, "ok "+push.dst)
		}
		lines = append(lines, "")
		if err := h.respond(lines...); err != nil {
			return err
		}
		if compactAt > 0 && len(next.Bundles) >= compactAt {
			if _, _, _, compactErr := h.compact(false); compactErr != nil {
				// The push already committed. Never report failure to Git at this point:
				// a retry would misleadingly look like a failed ref update.
				fmt.Fprintf(h.errOut, "warning: aqt git remote compaction skipped: %v\n", compactErr)
			}
		}
		return nil
	}
	return errors.New("remote busy, pull and retry")
}

// compact replaces a remote's delta chain with one full bundle. explicit controls
// whether a not-even local clone is an error (`aqt repo gc`) or a silent auto-skip.
func (h *remoteHelper) compact(explicit bool) (compacted bool, before, generation int, err error) {
	var prepared struct {
		version  int
		full     gitremote.BundleRef
		snapshot string
		ok       bool
	}
	for attempt := 0; attempt < maxSyncAttempts; attempt++ {
		remote, err := h.openRemote()
		if err != nil {
			return false, 0, 0, err
		}
		if len(remote.root.Bundles) == 1 && remote.root.Bundles[0].Full {
			before, generation = 1, remote.root.Generation
			remote.close()
			return false, before, generation, nil
		}
		local, err := localGitRefs(h.remoteName, remote.item.ID, remote.meta.Name)
		if err != nil {
			remote.close()
			return false, 0, 0, err
		}
		if !local.contains(remote.root.Refs) {
			if !explicit && remote.res.CompactAt > 0 && len(remote.root.Bundles) >= 2*remote.res.CompactAt {
				fmt.Fprintf(h.errOut, "warning: aqt git remote has %d bundles because compaction needs every remote branch and tag locally; fetch all refs or run `aqt repo gc` from a complete clone\n", len(remote.root.Bundles))
			}
			remote.close()
			if explicit {
				return false, 0, 0, errors.New("local clone does not contain every remote branch and tag; fetch all refs before `aqt repo gc`")
			}
			return false, 0, 0, nil
		}
		if len(remote.root.Refs) == 0 {
			remote.close()
			if explicit {
				return false, 0, 0, errors.New("empty git remote has nothing to compact")
			}
			return false, 0, 0, nil
		}

		if !prepared.ok || prepared.version != remote.res.Version {
			full, err := buildAndUploadFullBundle(remote.client, remote.key, remote.root, local.bundleRefs(remote.root.Refs))
			if err != nil {
				remote.close()
				return false, 0, 0, err
			}
			snap, err := remote.client.CreateAutoSnapshot(remote.res.ID)
			if err != nil {
				remote.close()
				return false, 0, 0, fmt.Errorf("create pre-compaction snapshot: %w", err)
			}
			prepared.version, prepared.full, prepared.snapshot, prepared.ok = remote.res.Version, full, snap.ID, true
		}
		next := remote.root
		next.Bundles = []gitremote.BundleRef{prepared.full}
		next.Generation++
		blob, err := gitremote.SealRefsRoot(next, remote.key, remote.res.ID)
		if err != nil {
			remote.close()
			return false, 0, 0, err
		}
		meta, err := verifiedMetaBound(remote.res.EncryptedMeta, remote.key, remote.res.ID)
		if err != nil {
			remote.close()
			return false, 0, 0, err
		}
		_, err = remote.client.PutResource(api.PutResourceRequest{
			ID: remote.res.ID, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: remote.res.WrappedKey, ChunkRefs: next.SegmentIDs(),
			ExpectedVersion: remote.res.Version, MinClient: api.CapabilityGitRemote,
			CompactAt: remote.res.CompactAt,
		})
		before = len(remote.root.Bundles)
		generation = next.Generation
		cl, resourceID := remote.client, remote.res.ID
		remote.close()
		if errors.Is(err, client.ErrConflict) {
			continue
		}
		if err != nil {
			return false, 0, 0, err
		}
		releaseSupersededCheckpoints(cl, resourceID, prepared.snapshot)
		return true, before, generation, nil
	}
	return false, 0, 0, errors.New("remote busy, pull and retry")
}

// releaseSupersededCheckpoints unanchors every automatic checkpoint on a remote but
// the one this compaction created, once its PUT commits. Keeping is by id rather than
// by recency: a CAS retry that rebuilt against a newer version leaves the abandoned
// attempt's checkpoint behind, and snapshot timestamps are whole seconds, so "newest"
// is not always decidable.
//
// The sweep has to look the checkpoints up server-side. They outlive the process that
// made them — one compaction cannot see an earlier one's — and an anchor is exempt
// from every retention path, so a checkpoint nothing releases pins a full copy of the
// repository forever. Anchors are only released here, never deleted: retention decides
// when the snapshot itself goes. A failure leaves the anchor in place, which costs
// storage but never loses a rollback.
func releaseSupersededCheckpoints(cl *client.Client, resourceID, keep string) {
	snaps, err := cl.ListSnapshots(resourceID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not list pre-compaction checkpoints to release: %v\n", err)
		return
	}
	for _, snap := range snaps {
		// Automatic and anchored is exactly the checkpoint shape CreateAutoSnapshot
		// makes. A user's `aqt checkpoint` is anchored but not automatic, and a
		// scheduled snapshot is automatic but not anchored; neither is ours to release.
		if snap.ID == keep || !snap.Automatic || !snap.Anchored {
			continue
		}
		if _, err := cl.SetSnapshotAnchor(snap.ID, false); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not release superseded pre-compaction snapshot %s: %v\n", snap.ID, err)
		}
	}
}

type localRefSet struct {
	refs map[string][]localRef
}

type localRef struct{ oid, source string }

func (s localRefSet) contains(remote map[string]string) bool {
	for name, oid := range remote {
		if !slices.ContainsFunc(s.refs[name], func(ref localRef) bool { return ref.oid == oid }) {
			return false
		}
	}
	return true
}

func (s localRefSet) bundleRefs(remote map[string]string) []string {
	refs := make([]string, 0, len(remote))
	for name, oid := range remote {
		for _, ref := range s.refs[name] {
			if ref.oid == oid {
				refs = append(refs, ref.source)
				break
			}
		}
	}
	sort.Strings(refs)
	return refs
}

func localGitRefs(remoteName string, remoteTargets ...string) (localRefSet, error) {
	output, err := commandOutput("git", "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags", "refs/remotes")
	if err != nil {
		return localRefSet{}, err
	}
	set := localRefSet{refs: make(map[string][]localRef)}
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		name, oid, ok := strings.Cut(line, " ")
		if !ok || name == "" || oid == "" {
			return localRefSet{}, fmt.Errorf("unexpected git ref record %q", line)
		}
		if strings.HasPrefix(name, "refs/heads/") || strings.HasPrefix(name, "refs/tags/") {
			set.refs[name] = append(set.refs[name], localRef{oid: oid, source: name})
			continue
		}
		rest := strings.TrimPrefix(name, "refs/remotes/")
		trackingRemote, branch, ok := strings.Cut(rest, "/")
		if !ok || branch == "HEAD" || !gitRemoteMatches(trackingRemote, remoteName, remoteTargets) {
			continue
		}
		canonical := "refs/heads/" + branch
		set.refs[canonical] = append(set.refs[canonical], localRef{oid: oid, source: name})
	}
	return set, nil
}

func gitRemoteMatches(name, hintedName string, targets []string) bool {
	if name == hintedName {
		return true
	}
	rawURL, err := commandOutput("git", "remote", "get-url", name)
	if err != nil {
		return false
	}
	target, err := gitRemoteTarget(rawURL)
	if err != nil {
		return false
	}
	return slices.Contains(targets, target)
}

func buildAndUploadFullBundle(cl *client.Client, key crypto.ContentKey, root gitremote.RefsRoot, refs []string) (gitremote.BundleRef, error) {
	path, cleanup, err := newBundlePath("aqt-full-bundle-")
	if err != nil {
		return gitremote.BundleRef{}, err
	}
	defer cleanup()
	args := []string{"bundle", "create", "--version=3", path}
	args = append(args, refs...)
	cmd := exec.Command("git", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return gitremote.BundleRef{}, fmt.Errorf("create full git bundle: %w: %s", err, strings.TrimSpace(string(output)))
	}
	f, err := os.Open(path)
	if err != nil {
		return gitremote.BundleRef{}, err
	}
	uploader := &gitObjectUploader{cl: cl}
	bundle, sealErr := gitremote.SealBundle(f, key, uploader)
	closeErr := f.Close()
	if sealErr != nil {
		return gitremote.BundleRef{}, sealErr
	}
	if closeErr != nil {
		return gitremote.BundleRef{}, closeErr
	}
	if err := uploader.Flush(); err != nil {
		return gitremote.BundleRef{}, err
	}
	bundle.Full = true
	seen := make(map[string]bool)
	for _, oid := range root.Refs {
		if !seen[oid] {
			bundle.Tips = append(bundle.Tips, oid)
			seen[oid] = true
		}
	}
	sort.Strings(bundle.Tips)
	return bundle, nil
}

func nonFastForwardPushes(pushes []helperPush, remoteRefs map[string]string) map[string]bool {
	rejected := make(map[string]bool)
	for _, push := range pushes {
		remoteOID := remoteRefs[push.dst]
		if push.delete || push.force || remoteOID == "" || remoteOID == push.localOID {
			continue
		}
		cmd := exec.Command("git", "merge-base", "--is-ancestor", remoteOID, push.localOID)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if cmd.Run() != nil {
			rejected[push.dst] = true
		}
	}
	return rejected
}

func (h *remoteHelper) rejectPushBatch(pushes []helperPush, nonFF map[string]bool) error {
	lines := make([]string, 0, len(pushes)+1)
	for _, push := range pushes {
		if nonFF[push.dst] {
			lines = append(lines, "error "+push.dst+" non-fast-forward")
		} else {
			lines = append(lines, "error "+push.dst+" atomic push failed")
		}
	}
	lines = append(lines, "")
	return h.respond(lines...)
}

func applyPushes(root gitremote.RefsRoot, pushes []helperPush, objectFormat string) gitremote.RefsRoot {
	next := root
	next.Refs = make(map[string]string, len(root.Refs))
	for name, oid := range root.Refs {
		next.Refs[name] = oid
	}
	if next.ObjectFormat == "" {
		next.ObjectFormat = objectFormat
	}
	for _, push := range pushes {
		if push.delete {
			delete(next.Refs, push.dst)
			continue
		}
		next.Refs[push.dst] = push.localOID
		if next.Head == "" && strings.HasPrefix(push.dst, "refs/heads/") {
			next.Head = push.dst
		}
	}
	if next.Head != "" {
		if _, ok := next.Refs[next.Head]; !ok {
			next.Head = firstBranch(next.Refs)
		}
	}
	return next
}

func firstBranch(refs map[string]string) string {
	branches := make([]string, 0)
	for name := range refs {
		if strings.HasPrefix(name, "refs/heads/") {
			branches = append(branches, name)
		}
	}
	sort.Strings(branches)
	if len(branches) == 0 {
		return ""
	}
	return branches[0]
}

func buildAndUploadPushBundle(cl *client.Client, key crypto.ContentKey, root gitremote.RefsRoot, pushes []helperPush) (*gitremote.BundleRef, error) {
	// The remote frontier is needed twice — as the bundle's exclusion set, and as the
	// set a pushed tip is tested against — so establish it once, in one git call.
	present, err := presentObjects(distinctRefOIDs(root.Refs))
	if err != nil {
		return nil, err
	}
	bases := make([]string, 0, len(present))
	for oid := range present {
		bases = append(bases, oid)
	}
	sort.Strings(bases)

	var tips []string
	seenTip := make(map[string]bool)
	for _, push := range pushes {
		if push.delete || seenTip[push.localOID] {
			continue
		}
		tips = append(tips, push.localOID)
		seenTip[push.localOID] = true
	}
	contained, err := remoteReaches(tips, root.Refs, bases)
	if err != nil {
		return nil, err
	}

	var positives []string
	seenPositive := make(map[string]bool)
	for _, push := range pushes {
		if push.delete {
			continue
		}
		needsObject := push.annotatedTag && !remoteContainsObject(root.Refs, push.localOID)
		if (needsObject || !contained[push.localOID]) && !seenPositive[push.src] {
			positives = append(positives, push.src)
			seenPositive[push.src] = true
		}
	}
	if len(positives) == 0 {
		return nil, nil
	}

	path, cleanup, err := newBundlePath("aqt-push-bundle-")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	args := []string{"bundle", "create", "--version=3", path}
	for _, base := range bases {
		args = append(args, "^"+base)
	}
	args = append(args, positives...)
	cmd := exec.Command("git", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("create git push bundle: %w: %s", err, strings.TrimSpace(string(output)))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	uploader := &gitObjectUploader{cl: cl}
	bundle, sealErr := gitremote.SealBundle(f, key, uploader)
	closeErr := f.Close()
	if sealErr != nil {
		return nil, sealErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := uploader.Flush(); err != nil {
		return nil, err
	}
	bundle.Tips, bundle.Bases = tips, bases
	return &bundle, nil
}

func distinctRefOIDs(refs map[string]string) []string {
	seen := make(map[string]bool, len(refs))
	oids := make([]string, 0, len(refs))
	for _, oid := range refs {
		if !seen[oid] {
			oids = append(oids, oid)
			seen[oid] = true
		}
	}
	sort.Strings(oids)
	return oids
}

// remoteReaches reports, per tip, whether the remote's refs already reach it — the
// question that decides whether a push has to ship the tip's history at all.
//
// frontier is the subset of the remote's refs this repository actually has; a tip is
// answered against that whole set at once. Asking it pairwise (one `git merge-base
// --is-ancestor` per tip and remote ref) made a push cost O(pushed x remote)
// subprocesses: pushing 80 unrelated branches to a remote holding 60 took 10s, against
// 121ms for 20 to an empty one.
func remoteReaches(tips []string, refs map[string]string, frontier []string) (map[string]bool, error) {
	reached := make(map[string]bool, len(tips))
	for _, tip := range tips {
		// An exact ref match settles it without a walk, and settles it even when the
		// object is missing locally — which is what the pairwise check did first too.
		if remoteContainsObject(refs, tip) {
			reached[tip] = true
			continue
		}
		if len(frontier) == 0 {
			continue
		}
		ok, err := reachableFrom(tip, frontier)
		if err != nil {
			return nil, err
		}
		reached[tip] = ok
	}
	return reached, nil
}

// reachableFrom reports whether oid is reachable from any of frontier. `rev-list oid
// --not frontier...` emits the commits reachable from oid and from nothing in
// frontier, so no output means the remote already has it; --max-count=1 stops at the
// first counterexample. A tip git cannot walk (a non-commit-ish ref) counts as not
// reached, exactly as a failing merge-base did.
func reachableFrom(oid string, frontier []string) (bool, error) {
	args := append([]string{"rev-list", "--max-count=1", oid, "--not"}, frontier...)
	cmd := exec.Command("git", args...)
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return false, nil
	}
	return len(strings.TrimSpace(string(out))) == 0, nil
}

// presentObjects returns the subset of oids this repository holds, in one
// `git cat-file --batch-check` pass rather than a process per id. Ids that are not
// well-formed never reach git (see validGitOID) and are reported absent.
func presentObjects(oids []string) (map[string]bool, error) {
	present := make(map[string]bool, len(oids))
	var query []string
	var stdin strings.Builder
	for _, oid := range oids {
		if !validGitOID(oid) {
			continue
		}
		query = append(query, oid)
		stdin.WriteString(oid + "^{object}\n")
	}
	if len(query) == 0 {
		return present, nil
	}
	cmd := exec.Command("git", "cat-file", "--batch-check")
	cmd.Stdin = strings.NewReader(stdin.String())
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("check local git objects: %w", err)
	}
	records := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(records) != len(query) {
		return nil, fmt.Errorf("git cat-file returned %d records for %d objects", len(records), len(query))
	}
	for i, record := range records {
		// git answers a resolvable id with "<objectname> <type> <size>" and an
		// unresolvable one by echoing the query and a reason ("missing", "ambiguous").
		// Matching on the shape rather than on the echo matters for an annotated tag,
		// whose peeled objectname is not the id that was asked about.
		if fields := strings.Fields(record); len(fields) == 3 && validGitOID(fields[0]) {
			present[query[i]] = true
		}
	}
	return present, nil
}

func remoteContainsObject(refs map[string]string, oid string) bool {
	for _, remoteOID := range refs {
		if remoteOID == oid {
			return true
		}
	}
	return false
}

type gitObjectUploader struct {
	cl         *client.Client
	candidates []gitObjectCandidate
	size       int
}

type gitObjectCandidate struct {
	id     string
	object []byte
}

func (u *gitObjectUploader) Add(id string, object []byte) error {
	u.candidates = append(u.candidates, gitObjectCandidate{id: id, object: append([]byte(nil), object...)})
	u.size += len(object)
	if u.size >= syncengine.DefaultPackTarget {
		return u.flush()
	}
	return nil
}

func (u *gitObjectUploader) Flush() error { return u.flush() }

func (u *gitObjectUploader) flush() error {
	if len(u.candidates) == 0 {
		return nil
	}
	builder := syncengine.NewPackBuilder()
	for _, candidate := range u.candidates {
		builder.Add(candidate.id, candidate.object)
	}
	u.candidates, u.size = nil, 0
	packID, pack := builder.Finish()
	return u.cl.PutPack(packID, pack)
}

func (h *remoteHelper) openRemote() (*openedGitRemote, error) {
	cl, prof, err := authedClient()
	if err != nil {
		return nil, err
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		return nil, errSessionRequired
	}
	defer mk.Wipe()
	target, err := gitRemoteTarget(h.rawURL)
	if err != nil {
		return nil, err
	}
	items, err := cl.ListResources()
	if err != nil {
		return nil, err
	}
	var matches []api.ResourceListItem
	var metas []api.Metadata
	for _, item := range gitRemoteItems(items) {
		meta, ok := openMetadata(item, mk)
		if !ok || meta.Kind != api.KindGitRemote {
			continue
		}
		if item.ID == target || meta.Name == target {
			matches = append(matches, item)
			metas = append(metas, meta)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("git remote %q not found", target)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("git remote name %q is ambiguous; use aqt::%s", target, matches[0].ID)
	}
	item := matches[0]
	res, err := cl.GetResource(item.ID)
	if err != nil {
		return nil, err
	}
	if item.WrappedKey == nil {
		return nil, errors.New("git remote has no owner key")
	}
	key, err := crypto.UnwrapKey(*item.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return nil, err
	}
	root, err := gitremote.OpenRefsRoot(res.Blob, key, item.ID)
	if err != nil {
		key.Wipe()
		return nil, fmt.Errorf("open git remote root: %w", err)
	}
	return &openedGitRemote{client: cl, item: item, res: res, meta: metas[0], root: root, key: key}, nil
}

func gitRemoteTarget(rawURL string) (string, error) {
	// Git strips the "aqt::" transport prefix before invoking git-remote-aqt;
	// direct invocations of the hidden command may still carry the full spelling.
	target := strings.TrimPrefix(rawURL, "aqt::")
	if target == "" || strings.Contains(target, "://") {
		return "", fmt.Errorf("invalid aqt git remote target %q (want aqt::<name-or-id>)", rawURL)
	}
	return target, nil
}

// allObjectsPresent reports whether every tip is in present. A bundle with no tips
// predates tip recording, so it is never assumed applied.
func allObjectsPresent(oids []string, present map[string]bool) bool {
	if len(oids) == 0 {
		return false
	}
	for _, oid := range oids {
		if !present[oid] {
			return false
		}
	}
	return true
}

// validGitOID gates every object id that reaches a git subprocess. Ids arrive
// from Git's own protocol lines or a decrypted root, but a value git could parse
// as an option (a leading dash) must never become an argv entry.
func validGitOID(oid string) bool {
	if len(oid) != 40 && len(oid) != 64 {
		return false
	}
	for _, c := range oid {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func gitObjectPresent(oid string) bool {
	if !validGitOID(oid) {
		return false
	}
	cmd := exec.Command("git", "cat-file", "-e", oid+"^{object}")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run() == nil
}

// newBundlePath returns a path for a plaintext Git bundle, inside a directory only
// this process can enter, plus its cleanup.
//
// `git bundle create` insists on creating the file itself, so the path handed to it
// must not exist. Reserving a name in the shared temp directory and deleting it again
// leaves a window in which a local attacker — the name is disclosed the moment it is
// created — can plant a symlink there and capture the bundle, which is the repository
// in plaintext. A 0700 directory nobody else can traverse closes the window instead of
// racing it. Bundles this process writes for Git to read go here for the same reason.
func newBundlePath(prefix string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(dir, "git.bundle"), func() { os.RemoveAll(dir) }, nil
}

func applyBundle(bundle gitremote.BundleRef, key crypto.ContentKey, get func(string) ([]byte, error)) error {
	name, cleanup, err := newBundlePath("aqt-apply-bundle-")
	if err != nil {
		return err
	}
	defer cleanup()
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := gitremote.OpenBundle(bundle, key, get, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	cmd := exec.Command("git", "bundle", "unbundle", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git rejected bundle %s: %w: %s", bundle.ID, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func commandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(output)), nil
}
