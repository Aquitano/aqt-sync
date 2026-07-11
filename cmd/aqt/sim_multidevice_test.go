package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/server"
)

// TestMultiDeviceSim is a seeded, deterministic state-machine simulation: three
// in-process devices of one account randomly interleave local edits, syncs, and
// mid-sync crashes against one shared server, then quiesce. It asserts convergence,
// keep-both for concurrent edits, and no data loss.
//
// The devices are driven one operation at a time (interleaving is operation order,
// not goroutine parallelism) and transfers run serially (AQT_SYNC_SERIAL, set in
// startServer), so a seed and host mode fully determine the run and any failure is
// replayable. Override the seed set with AQT_SIM_SEED=<n> to reproduce one failure.
//
// Each seed runs in two host modes: distinct-host, where every device stamps its own
// conflict-copy hostname (the common case), and shared-host, where all devices share
// one hostname and colliding copy names must be resolved by the suffix bump (see
// hostModes).
//
// It complements the example-based conflict-copy tests by exercising operation
// orderings no hand-written case enumerates.
func TestMultiDeviceSim(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the multi-device sync simulation under -short")
	}
	for _, seed := range simSeeds(t) {
		for _, mode := range hostModes {
			t.Run(fmt.Sprintf("seed-%d/%s", seed, mode.name), func(t *testing.T) {
				runSim(t, seed, mode)
			})
		}
	}
}

// hostMode selects the conflict-copy hostname each device stamps. distinct-host gives
// every device a unique name (the common case); shared-host gives them all one name, so
// devices mint the same <path>.conflict-<host>-<ts> candidate for the same concurrently
// edited path within the same second, exercising the copy-name collision avoidance in
// conflictCopyPath (bumping past disk files, remote paths, and already-planned copies).
type hostMode struct {
	name string
	host func(devID int) string
}

var hostModes = []hostMode{
	{name: "distinct-host", host: func(id int) string { return fmt.Sprintf("dev%d", id) }},
	{name: "shared-host", host: func(int) string { return "samehost" }},
}

const (
	simDevices   = 3
	simSteps     = 40
	simQuiesce   = 8 // convergence must be reached within this many all-sync rounds
	simMaxCrashK = 3 // a crash aborts the connection on the 1st..Kth request of a sync
)

// simSeeds returns the fixed seed set, or the single AQT_SIM_SEED override.
func simSeeds(t *testing.T) []int64 {
	if v := os.Getenv("AQT_SIM_SEED"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("AQT_SIM_SEED=%q: %v", v, err)
		}
		return []int64{n}
	}
	return []int64{1, 2, 3, 4}
}

// simPaths is the fixed pool of file paths operations draw from. A small pool forces
// frequent same-path collisions, which is what produces conflicts to resolve. Kept
// sorted so path choice never depends on map iteration order.
var simPaths = []string{
	"a.txt",
	"b.txt",
	"docs/c.txt",
	"docs/d.txt",
	"docs/sub/e.txt",
	"f.txt",
	"g.txt",
}

type opKind int

const (
	opCreate opKind = iota
	opModify
	opDelete
	opRename
	opSync
	opCrashSync
)

func (o opKind) String() string {
	switch o {
	case opCreate:
		return "create"
	case opModify:
		return "modify"
	case opDelete:
		return "delete"
	case opRename:
		return "rename"
	case opSync:
		return "sync"
	case opCrashSync:
		return "crash-sync"
	}
	return "?"
}

// simOps is the weighted operation deck. Syncs dominate so edits actually propagate;
// crashes are rarer. rng.Intn(len) picks one, so weights are just repetition counts.
var simOps = buildDeck(map[opKind]int{
	opCreate:    4,
	opModify:    4,
	opDelete:    2,
	opRename:    2,
	opSync:      6,
	opCrashSync: 2,
})

func buildDeck(w map[opKind]int) []opKind {
	kinds := make([]opKind, 0, len(w))
	for k := range w {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	var deck []opKind
	for _, k := range kinds {
		for i := 0; i < w[k]; i++ {
			deck = append(deck, k)
		}
	}
	return deck
}

// contentMap models a tree as path -> content. A missing key means the path is
// absent. Content strings are globally unique, so a value doubles as a data token
// the oracle can track through syncs and conflict copies.
type contentMap map[string]string

func (m contentMap) clone() contentMap {
	out := make(contentMap, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (m contentMap) values() map[string]bool {
	out := make(map[string]bool, len(m))
	for _, v := range m {
		out[v] = true
	}
	return out
}

type simDevice struct {
	id   int
	home string     // config dir (isolated identity per device)
	dir  string     // working tree
	tree contentMap // model of on-disk files
	base contentMap // model of the last-synced state (three-way base)
}

// conflictRec records a concurrent same-path change the model detected, with the two
// contents copy-mode is expected to keep (either side may be a delete, i.e. absent).
type conflictRec struct {
	step     int
	path     string
	local    string
	localOK  bool
	remote   string
	remoteOK bool
}

type sim struct {
	t     *testing.T
	seed  int64
	mode  hostMode
	rng   *rand.Rand
	fault *faultInjector

	devs   []*simDevice
	server contentMap // model of the server's current converged content

	nextContent int
	nextCopy    int

	conflicts []conflictRec
	trace     []string
}

func runSim(t *testing.T, seed int64, mode hostMode) {
	s := &sim{t: t, seed: seed, mode: mode, rng: rand.New(rand.NewSource(seed)), server: contentMap{}}
	s.setup()

	for step := 0; step < simSteps; step++ {
		d := s.devs[s.rng.Intn(simDevices)]
		op := simOps[s.rng.Intn(len(simOps))]
		s.use(d)
		s.exec(step, d, op)
	}

	s.quiesce()
	s.verify()
}

// --- setup ---

func (s *sim) setup() {
	t := s.t
	s.startServer()

	email := fmt.Sprintf("sim-%d@example.com", s.seed)
	const pass = "correct horse battery staple sim"

	s.devs = make([]*simDevice, simDevices)
	for i := range s.devs {
		s.devs[i] = &simDevice{id: i, home: t.TempDir(), dir: t.TempDir(), tree: contentMap{}, base: contentMap{}}
	}

	// Device 0 owns the account and creates the folder; the others recover the account
	// and clone it, exactly as a second machine does in the two-device tests.
	url := s.fault.url
	s.use(s.devs[0])
	signupAt(t, url, email, pass)
	if err := runInit(s.devs[0].dir); err != nil {
		t.Fatalf("init device 0: %v", err)
	}
	seed := s.freshContent()
	writeTree(t, s.devs[0].dir, "a.txt", seed)
	s.devs[0].tree["a.txt"] = seed
	if err := runSync(s.devs[0].dir, syncOptions{}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	folderID := folderIDOf(t, s.devs[0].dir)
	s.server = s.devs[0].tree.clone()
	s.devs[0].base = s.devs[0].tree.clone()

	for i := 1; i < simDevices; i++ {
		s.use(s.devs[i])
		reattach(t, url, email, pass)
		if err := runClone(folderID, s.devs[i].dir, false, ""); err != nil {
			t.Fatalf("clone device %d: %v", i, err)
		}
		s.devs[i].tree = s.server.clone()
		s.devs[i].base = s.server.clone()
	}
}

// startServer stands up one shared store behind the fault injector and points the
// config env somewhere safe. AQT_NO_KEYCHAIN keeps every device's token and session
// in its own config dir, so swapping HOME fully swaps identity (the OS keychain would
// otherwise share one entry across all three devices in-process).
func (s *sim) startServer() {
	t := s.t
	gin.SetMode(gin.TestMode)
	t.Setenv("AQT_NO_KEYCHAIN", "1")
	// Serialize transfers so crash-fault injection is seed-deterministic: the fault
	// injector aborts the k-th request, and with a concurrent upload/download pipeline
	// which request is k-th depends on goroutine scheduling.
	t.Setenv("AQT_SYNC_SERIAL", "1")

	t.Setenv("AQT_CONFLICT_HOST", "") // restored by t.Setenv; use() sets it per device
	origHome, origXDG := os.Getenv("HOME"), os.Getenv("XDG_CONFIG_HOME")
	t.Cleanup(func() {
		os.Setenv("HOME", origHome)
		os.Setenv("XDG_CONFIG_HOME", origXDG)
	})

	store, err := server.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	s.fault = &faultInjector{h: server.New(store).Router()}
	ts := httptest.NewServer(s.fault)
	t.Cleanup(ts.Close)
	s.fault.url = ts.URL
}

// use points the identity config env at device d, so the next run* call authenticates
// and unlocks as that device. Operations are sequential, so a plain env swap is enough.
func (s *sim) use(d *simDevice) {
	os.Setenv("HOME", d.home)                                      // darwin config dir
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(d.home, ".config")) // linux config dir
	// Conflict-copy host per the run's mode: distinct-host disambiguates copy names by
	// device (the common case); shared-host makes every device stamp one name, so copy
	// names collide and must be resolved by the suffix bump instead of the hostname.
	os.Setenv("AQT_CONFLICT_HOST", s.mode.host(d.id))
}

func (s *sim) freshContent() string {
	s.nextContent++
	return fmt.Sprintf("v%d", s.nextContent)
}

// --- operations ---

func (s *sim) exec(step int, d *simDevice, op opKind) {
	switch op {
	case opCreate:
		s.doWrite(step, d, s.absentPaths(d), op)
	case opModify:
		s.doWrite(step, d, s.presentPaths(d), op)
	case opDelete:
		s.doDelete(step, d)
	case opRename:
		s.doRename(step, d)
	case opSync:
		s.doSync(step, d)
	case opCrashSync:
		s.doCrashSync(step, d)
	}
}

func (s *sim) doWrite(step int, d *simDevice, targets []string, op opKind) {
	if len(targets) == 0 {
		s.tracef("step %2d dev %d %-10s (no target, skipped)", step, d.id, op)
		return
	}
	p := targets[s.rng.Intn(len(targets))]
	c := s.freshContent()
	writeTree(s.t, d.dir, p, c)
	d.tree[p] = c
	s.tracef("step %2d dev %d %-10s %s = %s", step, d.id, op, p, c)
}

func (s *sim) doDelete(step int, d *simDevice) {
	present := s.presentPaths(d)
	if len(present) == 0 {
		s.tracef("step %2d dev %d %-10s (no target, skipped)", step, d.id, opDelete)
		return
	}
	p := present[s.rng.Intn(len(present))]
	removeTree(s.t, d.dir, p)
	delete(d.tree, p)
	s.tracef("step %2d dev %d %-10s %s", step, d.id, opDelete, p)
}

func (s *sim) doRename(step int, d *simDevice) {
	present := s.presentPaths(d)
	absent := s.absentPaths(d)
	if len(present) == 0 || len(absent) == 0 {
		s.tracef("step %2d dev %d %-10s (no target, skipped)", step, d.id, opRename)
		return
	}
	from := present[s.rng.Intn(len(present))]
	to := absent[s.rng.Intn(len(absent))]
	content := readTree(s.t, d.dir, from)
	writeTree(s.t, d.dir, to, content)
	removeTree(s.t, d.dir, from)
	delete(d.tree, from)
	d.tree[to] = content
	s.tracef("step %2d dev %d %-10s %s -> %s", step, d.id, opRename, from, to)
}

func (s *sim) doSync(step int, d *simDevice) {
	if err := runSync(d.dir, copyOpts()); err != nil {
		s.fatalf(step, "dev %d sync returned an unexpected error: %v", d.id, err)
	}
	s.applyMerge(step, d)
	s.tracef("step %2d dev %d %-10s", step, d.id, opSync)
	s.checkModelMatchesDisk(step, d)
}

// doCrashSync arms the fault injector to abort the connection mid-sync, tolerates the
// resulting error, then drives the recovery sync a later run would perform. Crash and
// recovery collapse to a single successful merge in the model: the recovery reconciles
// the device's unchanged local edits against the server regardless of how far the
// aborted attempt got, so the converged result is the same either way.
func (s *sim) doCrashSync(step int, d *simDevice) {
	k := s.rng.Intn(simMaxCrashK) + 1
	s.fault.arm(k)
	crashErr := runSync(d.dir, copyOpts())
	s.fault.disarm()

	recovered := crashErr == nil
	var lastErr error
	for attempt := 0; attempt < 4 && !recovered; attempt++ {
		if err := runSync(d.dir, copyOpts()); err == nil {
			recovered = true
		} else {
			lastErr = err
		}
	}
	if !recovered {
		s.fatalf(step, "dev %d could not recover after a mid-sync crash: %v", d.id, lastErr)
	}
	s.applyMerge(step, d)
	s.tracef("step %2d dev %d %-10s k=%d fired=%v", step, d.id, opCrashSync, k, crashErr != nil)
	s.checkModelMatchesDisk(step, d)
}

// --- model merge (three-way, copy mode) ---

// applyMerge advances the model exactly as a successful copy-mode sync of device d
// does: a three-way merge of the device's base, its local tree, and the server.
//
// The primary merge (pushed) is committed to the server and becomes the device's new
// base. Conflict copies are different: the implementation writes them to the device's
// disk but does NOT include them in the pushed manifest, so they stay local until the
// device's next sync uploads them as ordinary new files. The model mirrors that — a
// copy lands in the device's tree but not in the server or base — otherwise it would
// predict a copy on other devices a round before it can actually propagate.
func (s *sim) applyMerge(step int, d *simDevice) {
	pushed := contentMap{}
	copies := contentMap{}
	var conflicts []conflictRec

	for _, p := range unionKeys(d.base, d.tree, s.server) {
		bc, bok := d.base[p]
		lc, lok := d.tree[p]
		sc, sok := s.server[p]
		localChanged := lok != bok || lc != bc
		remoteChanged := sok != bok || sc != bc

		switch {
		case !localChanged && !remoteChanged:
			if bok {
				pushed[p] = bc
			}
		case localChanged && !remoteChanged:
			if lok {
				pushed[p] = lc
			}
		case !localChanged && remoteChanged:
			if sok {
				pushed[p] = sc
			}
		default: // both sides changed since the base
			switch {
			case !lok && !sok:
				// Both deleted the file: they agree, nothing survives. Not a conflict.
			case lok && sok && lc == sc:
				// Both made the same change: converged.
				pushed[p] = lc
			default:
				// Genuine conflict. Copy mode keeps local at the primary path and, when
				// the remote side has bytes, preserves them as a local-only conflict
				// copy. A remote delete has nothing to copy.
				if lok {
					pushed[p] = lc
				}
				if sok {
					copies[s.copyPath()] = sc
				}
				conflicts = append(conflicts, conflictRec{
					step: step, path: p,
					local: lc, localOK: lok,
					remote: sc, remoteOK: sok,
				})
			}
		}
	}

	s.server = pushed
	d.base = pushed.clone()
	d.tree = pushed.clone()
	for p, c := range copies {
		d.tree[p] = c
	}
	s.conflicts = append(s.conflicts, conflicts...)
	for _, c := range conflicts {
		s.tracef("       conflict at %s: local=%s(%v) remote=%s(%v)", c.path, c.local, c.localOK, c.remote, c.remoteOK)
	}
}

// copyPath returns a fresh synthetic path for a model conflict copy. The real name
// (<path>.conflict-<host>-<ts>) is irrelevant to the oracle, which tracks content
// tokens, not paths, across the copy.
func (s *sim) copyPath() string {
	s.nextCopy++
	return fmt.Sprintf("__conflict_%d", s.nextCopy)
}

// checkModelMatchesDisk asserts every content token the model believes device d holds
// is physically present on disk. It compares by content, not path, because a conflict
// copy lands at a model-synthetic path but a real, differently-named one on disk. A
// crash-recovered sync may leave an extra stray copy on disk, so disk is allowed a
// superset; only a model token missing from disk is a failure.
func (s *sim) checkModelMatchesDisk(step int, d *simDevice) {
	disk := treeStrings(collectTree(s.t, d.dir)).valuesSet()
	for path, c := range d.tree {
		if !disk[c] {
			s.fatalf(step, "dev %d model/disk drift: content %q (model path %s) not on disk", d.id, c, path)
		}
	}
}

// --- quiesce and oracle ---

// quiesce disarms fault injection and runs whole rounds of every-device-syncs until
// all working trees are byte-identical. Multiple rounds are needed because a conflict
// copy created when one device syncs only reaches the others on their next pull, and a
// copy made in the last active round needs a further round to propagate.
func (s *sim) quiesce() {
	s.fault.disarm()
	for round := 0; round < simQuiesce; round++ {
		for _, d := range s.devs {
			s.use(d)
			if err := runSync(d.dir, copyOpts()); err != nil {
				s.fatalf(-1, "quiesce round %d dev %d sync error: %v", round, d.id, err)
			}
			s.applyMerge(-1, d)
		}
		if s.treesConverged() {
			s.tracef("converged after %d quiesce round(s)", round+1)
			return
		}
	}
	s.fatalf(-1, "did not converge after %d quiesce rounds", simQuiesce)
}

// treesConverged reports whether every device's working tree is identical in paths and
// bytes. Only regular files are ever created, so equal paths+bytes also means equal
// file type.
func (s *sim) treesConverged() bool {
	ref := treeStrings(collectTree(s.t, s.devs[0].dir))
	for _, d := range s.devs[1:] {
		if !treesEqual(ref, treeStrings(collectTree(s.t, d.dir))) {
			return false
		}
	}
	return true
}

// verify runs the invariants after convergence. treesConverged already established
// convergence (invariant 1); here it is asserted with a hard failure and dump, then
// no-data-loss and keep-both are checked against the converged content.
func (s *sim) verify() {
	if !s.treesConverged() {
		s.fatalf(-1, "trees diverged after quiesce reported convergence")
	}
	tree := collectTree(s.t, s.devs[0].dir)
	final := treeStrings(tree).valuesSet()

	// No data loss: every content the model's converged server state holds — every
	// live edit and preserved conflict copy — must be present in the real tree.
	for path, c := range s.server {
		if !final[c] {
			s.fatalf(-1, "data loss: content %q (model path %s) missing from the converged tree", c, path)
		}
	}

	// Keep-both: for each detected concurrent edit whose two contents the model still
	// considers live, both must be present. This is a subset of the check above but
	// pins the failure to the specific concurrent-edit that lost a side.
	modelLive := s.server.values()
	for _, c := range s.conflicts {
		if c.localOK && modelLive[c.local] && !final[c.local] {
			s.fatalf(-1, "keep-both violated at %s: local content %q lost", c.path, c.local)
		}
		if c.remoteOK && modelLive[c.remote] && !final[c.remote] {
			s.fatalf(-1, "keep-both violated at %s: remote content %q lost", c.path, c.remote)
		}
	}
	s.t.Logf("seed %d (%s): %d steps, %d detected conflicts, converged tree has %d files",
		s.seed, s.mode.name, simSteps, len(s.conflicts), len(tree))
}

// --- helpers ---

func copyOpts() syncOptions { return syncOptions{conflicts: "copy"} }

func (s *sim) presentPaths(d *simDevice) []string {
	var out []string
	for _, p := range simPaths {
		if _, ok := d.tree[p]; ok {
			out = append(out, p)
		}
	}
	return out
}

func (s *sim) absentPaths(d *simDevice) []string {
	var out []string
	for _, p := range simPaths {
		if _, ok := d.tree[p]; !ok {
			out = append(out, p)
		}
	}
	return out
}

func unionKeys(maps ...contentMap) []string {
	set := map[string]bool{}
	for _, m := range maps {
		for k := range m {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out) // deterministic conflict-copy numbering
	return out
}

func (s *sim) tracef(format string, args ...any) {
	s.trace = append(s.trace, fmt.Sprintf(format, args...))
}

// fatalf dumps the seed and full trace so any failure is replayable with
// AQT_SIM_SEED, then fails the test.
func (s *sim) fatalf(step int, format string, args ...any) {
	s.t.Logf("SIM FAILURE: seed=%d step=%d (reproduce with AQT_SIM_SEED=%d)", s.seed, step, s.seed)
	s.t.Logf("--- trace (%d entries) ---", len(s.trace))
	for _, line := range s.trace {
		s.t.Log(line)
	}
	s.t.Fatalf(format, args...)
}

// treeStrings is the string-valued view of a tree used by convergence checks.
type treeStrings map[string]string

func (m treeStrings) valuesSet() map[string]bool {
	out := make(map[string]bool, len(m))
	for _, v := range m {
		out[v] = true
	}
	return out
}

func treesEqual(a, b treeStrings) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// --- fault injection ---

// faultInjector wraps the server handler and, when armed with k, aborts the k-th
// subsequent request by panicking http.ErrAbortHandler before the handler runs — the
// standard way to kill an httptest connection. The abort fires before the real handler
// executes, so an aborted request never mutates the server. It fires once, then
// disarms. Guarded by a mutex because the concurrent upload pipeline issues requests
// from several goroutines at once.
type faultInjector struct {
	h   http.Handler
	url string

	mu        sync.Mutex
	remaining int // >0: abort when it counts down to 0; <=0: disarmed
}

func (f *faultInjector) arm(k int) {
	f.mu.Lock()
	f.remaining = k
	f.mu.Unlock()
}

func (f *faultInjector) disarm() {
	f.mu.Lock()
	f.remaining = 0
	f.mu.Unlock()
}

func (f *faultInjector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	fire := false
	if f.remaining > 0 {
		f.remaining--
		fire = f.remaining == 0
	}
	f.mu.Unlock()
	if fire {
		panic(http.ErrAbortHandler)
	}
	f.h.ServeHTTP(w, r)
}
