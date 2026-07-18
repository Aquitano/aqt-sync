package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func (h *remoteHelper) run() error {
	scanner := bufio.NewScanner(h.in)
	// Protocol lines contain hashes/ref names, but keep a generous bound so an
	// adversarial invoking process gets a clean error rather than Scanner's tiny default.
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var fetches []helperFetch
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
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flushFetches(); err != nil {
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
		if err := flushFetches(); err != nil {
			return err
		}
		switch {
		case line == "capabilities":
			if err := h.respond("fetch", "option", ""); err != nil {
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
	return flushFetches()
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
	target, ok := strings.CutPrefix(rawURL, "aqt::")
	if !ok || target == "" {
		return "", fmt.Errorf("invalid aqt git remote URL %q (want aqt::<name-or-id>)", rawURL)
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
