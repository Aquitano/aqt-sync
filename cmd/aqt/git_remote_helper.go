package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/gitremote"
	"github.com/aquitano/aqt-sync/internal/identity"
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
	remoteName string
	rawURL     string
	in         io.Reader
	out        *bufio.Writer
	errOut     io.Writer
	verbosity  int
	progress   bool
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
	raw      string
	src      string
	dst      string
	force    bool
	delete   bool
	localOID string
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
			if err := h.respond("fetch", "push", "option", ""); err != nil {
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

	statePath, state, err := loadHelperState(h.remoteName)
	if err != nil {
		return err
	}
	if state.Generation != remote.root.Generation {
		state.AppliedBundles = nil
	}
	state.Generation = remote.root.Generation

	var needed []gitremote.BundleRef
	for _, bundle := range remote.root.Bundles {
		if !allObjectsPresent(bundle.Tips) {
			needed = append(needed, bundle)
		}
	}
	ids := make([]string, 0)
	for _, bundle := range needed {
		for _, segment := range bundle.Segments {
			ids = append(ids, segment.ID)
		}
	}
	source, err := newPackSource(remote.client, ids)
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
		if err := applyBundle(bundle, remote.key, source.get); err != nil {
			return err
		}
		state.AppliedBundles = appendUnique(state.AppliedBundles, bundle.ID)
	}
	for _, request := range requests {
		if !gitObjectPresent(request.oid) {
			return fmt.Errorf("remote bundle chain does not contain requested object %s for %s", request.oid, request.ref)
		}
	}
	state.RemoteVersion = remote.res.Version
	return saveHelperState(statePath, state)
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
		next := applyPushes(remote.root, pushes, objectFormat)
		if bundle != nil {
			next.Bundles = append(next.Bundles, *bundle)
		}
		blob, err := gitremote.SealRefsRoot(next, remote.key, remote.res.ID)
		if err != nil {
			remote.close()
			return err
		}
		meta, err := resealMetaBound(remote.res.EncryptedMeta, remote.key, remote.res.ID)
		if err != nil {
			remote.close()
			return err
		}
		compactAt := remote.res.CompactAt
		_, err = remote.client.PutResource(api.PutResourceRequest{
			ID: remote.res.ID, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: remote.res.WrappedKey, ChunkRefs: next.SegmentIDs(),
			ExpectedVersion: remote.res.Version, MinClient: api.CapabilityGitRemote,
			CompactAt: remote.res.CompactAt,
		})
		remote.close()
		if errors.Is(err, client.ErrConflict) {
			continue
		}
		if err != nil {
			return err
		}
		if compactAt > 0 && len(next.Bundles) >= compactAt {
			if _, _, _, compactErr := h.compact(false); compactErr != nil {
				// The push already committed. Never report failure to Git at this point:
				// a retry would misleadingly look like a failed ref update.
				fmt.Fprintf(h.errOut, "warning: aqt git remote compaction skipped: %v\n", compactErr)
			}
		}
		lines := make([]string, 0, len(pushes)+1)
		for _, push := range pushes {
			lines = append(lines, "ok "+push.dst)
		}
		lines = append(lines, "")
		return h.respond(lines...)
	}
	return errors.New("remote busy, pull and retry")
}

// compact replaces a remote's delta chain with one full bundle. explicit controls
// whether a not-even local clone is an error (`aqt repo gc`) or a silent auto-skip.
func (h *remoteHelper) compact(explicit bool) (compacted bool, before, generation int, err error) {
	for attempt := 0; attempt < maxSyncAttempts; attempt++ {
		remote, err := h.openRemote()
		if err != nil {
			return false, 0, 0, err
		}
		local, err := localGitRefs()
		if err != nil {
			remote.close()
			return false, 0, 0, err
		}
		if !maps.Equal(local, remote.root.Refs) {
			remote.close()
			if explicit {
				return false, 0, 0, errors.New("local refs are not even with the remote; fetch/reconcile every branch and tag before `aqt repo gc`")
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

		full, err := buildAndUploadFullBundle(remote.client, remote.key, remote.root)
		if err != nil {
			remote.close()
			return false, 0, 0, err
		}
		snapshot, err := remote.client.CreateAutoSnapshot(remote.res.ID)
		if err != nil {
			remote.close()
			return false, 0, 0, fmt.Errorf("create pre-compaction snapshot: %w", err)
		}
		if !snapshot.Automatic {
			remote.close()
			return false, 0, 0, errors.New("server did not mark the pre-compaction snapshot automatic")
		}
		next := remote.root
		next.Bundles = []gitremote.BundleRef{full}
		next.Generation++
		blob, err := gitremote.SealRefsRoot(next, remote.key, remote.res.ID)
		if err != nil {
			remote.close()
			return false, 0, 0, err
		}
		meta, err := resealMetaBound(remote.res.EncryptedMeta, remote.key, remote.res.ID)
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
		remote.close()
		if errors.Is(err, client.ErrConflict) {
			continue
		}
		if err != nil {
			return false, 0, 0, err
		}
		return true, before, generation, nil
	}
	return false, 0, 0, errors.New("remote busy, pull and retry")
}

func localGitRefs() (map[string]string, error) {
	output, err := commandOutput("git", "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags")
	if err != nil {
		return nil, err
	}
	refs := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		name, oid, ok := strings.Cut(line, " ")
		if !ok || name == "" || oid == "" {
			return nil, fmt.Errorf("unexpected git ref record %q", line)
		}
		refs[name] = oid
	}
	return refs, nil
}

func buildAndUploadFullBundle(cl *client.Client, key crypto.ContentKey, root gitremote.RefsRoot) (gitremote.BundleRef, error) {
	tmp, err := os.CreateTemp("", "aqt-full-*.bundle")
	if err != nil {
		return gitremote.BundleRef{}, err
	}
	path := tmp.Name()
	defer os.Remove(path)
	if err := tmp.Close(); err != nil {
		return gitremote.BundleRef{}, err
	}
	if err := os.Remove(path); err != nil {
		return gitremote.BundleRef{}, err
	}
	cmd := exec.Command("git", "bundle", "create", "--version=3", path, "--all")
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
	var positives, tips []string
	seenPositive := make(map[string]bool)
	seenTip := make(map[string]bool)
	for _, push := range pushes {
		if push.delete {
			continue
		}
		if !seenTip[push.localOID] {
			tips = append(tips, push.localOID)
			seenTip[push.localOID] = true
		}
		if !remoteContainsCommit(root.Refs, push.localOID) && !seenPositive[push.src] {
			positives = append(positives, push.src)
			seenPositive[push.src] = true
		}
	}
	if len(positives) == 0 {
		return nil, nil
	}

	var bases []string
	seenBase := make(map[string]bool)
	for _, oid := range root.Refs {
		if !seenBase[oid] && gitObjectPresent(oid) {
			bases = append(bases, oid)
			seenBase[oid] = true
		}
	}
	sort.Strings(bases)

	tmp, err := os.CreateTemp("", "aqt-push-*.bundle")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	defer os.Remove(path)
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

func remoteContainsCommit(refs map[string]string, oid string) bool {
	for _, remoteOID := range refs {
		if remoteOID == oid {
			return true
		}
		cmd := exec.Command("git", "merge-base", "--is-ancestor", oid, remoteOID)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if cmd.Run() == nil {
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
	ids := make([]string, len(u.candidates))
	for i, candidate := range u.candidates {
		ids[i] = candidate.id
	}
	missing, err := u.cl.CheckChunks(ids)
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(missing))
	for _, id := range missing {
		want[id] = true
	}
	builder := syncengine.NewPackBuilder()
	for _, candidate := range u.candidates {
		if want[candidate.id] {
			builder.Add(candidate.id, candidate.object)
		}
	}
	u.candidates, u.size = nil, 0
	if builder.Empty() {
		return nil
	}
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
	for _, item := range items {
		if item.CompactAt == 0 {
			continue
		}
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

func allObjectsPresent(oids []string) bool {
	if len(oids) == 0 {
		return false
	}
	for _, oid := range oids {
		if !gitObjectPresent(oid) {
			return false
		}
	}
	return true
}

func gitObjectPresent(oid string) bool {
	if oid == "" {
		return false
	}
	cmd := exec.Command("git", "cat-file", "-e", oid+"^{object}")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run() == nil
}

func applyBundle(bundle gitremote.BundleRef, key crypto.ContentKey, get func(string) ([]byte, error)) error {
	f, err := os.CreateTemp("", "aqt-git-bundle-*.bundle")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
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

type helperState struct {
	RemoteVersion  int      `json:"remoteVersion"`
	Generation     int      `json:"generation"`
	AppliedBundles []string `json:"appliedBundles"`
}

func loadHelperState(remoteName string) (string, helperState, error) {
	gitDir, err := commandOutput("git", "rev-parse", "--git-dir")
	if err != nil {
		return "", helperState{}, fmt.Errorf("locate git directory: %w", err)
	}
	abs, err := filepath.Abs(gitDir)
	if err != nil {
		return "", helperState{}, err
	}
	path := filepath.Join(abs, "aqt", safeRemoteName(remoteName), "state.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, helperState{}, nil
	}
	if err != nil {
		return "", helperState{}, err
	}
	var state helperState
	if json.Unmarshal(b, &state) != nil {
		// The cache is disposable; treat corruption exactly like cache loss.
		return path, helperState{}, nil
	}
	return path, state, nil
}

func saveHelperState(path string, state helperState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

func safeRemoteName(name string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r) {
			return r
		}
		return '_'
	}, name)
	if clean == "" || clean == "." || clean == ".." {
		return "remote"
	}
	return clean
}

func commandOutput(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
