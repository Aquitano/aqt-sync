package update

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func runtimeIsPOSIX() bool { return runtime.GOOS != "windows" }

func allAlive(int) bool  { return true }
func noneAlive(int) bool { return false }

func TestRegistryRecordsAndDropsAgents(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	if err := s.RegisterAgent(filepath.Join(t.TempDir(), "one"), 111, now); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if err := s.RegisterAgent(filepath.Join(t.TempDir(), "two"), 222, now); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	agents, err := s.LiveAgents(allAlive)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 {
		t.Fatalf("recorded %d agents, want 2", len(agents))
	}
}

// The registry exists so an update started in one folder can see an agent running
// in another; a lookup that only found the current folder would defeat it.
func TestRegistrySeesAgentsInOtherFolders(t *testing.T) {
	s := testStore(t)
	elsewhere := filepath.Join(t.TempDir(), "some-other-project")
	if err := s.RegisterAgent(elsewhere, 4242, time.Now()); err != nil {
		t.Fatal(err)
	}

	agents, err := s.LiveAgents(allAlive)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].PID != 4242 {
		t.Fatalf("agents = %+v", agents)
	}
}

func TestRegistryUnregisterRemovesOneRoot(t *testing.T) {
	s := testStore(t)
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	if err := s.RegisterAgent(a, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterAgent(b, 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.UnregisterAgent(a); err != nil {
		t.Fatalf("UnregisterAgent: %v", err)
	}

	agents, err := s.LiveAgents(allAlive)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].PID != 2 {
		t.Fatalf("agents = %+v", agents)
	}
}

// Restarting an agent in the same folder replaces its entry instead of stacking a
// second one, so a folder is never counted twice.
func TestRegistryReplacesTheEntryForARoot(t *testing.T) {
	s := testStore(t)
	root := filepath.Join(t.TempDir(), "project")
	if err := s.RegisterAgent(root, 100, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterAgent(root, 200, time.Now()); err != nil {
		t.Fatal(err)
	}

	agents, err := s.LiveAgents(allAlive)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].PID != 200 {
		t.Fatalf("agents = %+v", agents)
	}
}

// An agent that was killed rather than shut down cleanly never gets to
// unregister. Reaping on read is what keeps it from deferring updates forever —
// which matters most on Windows, where stopping an agent terminates it outright.
func TestRegistryReapsDeadAgentsOnRead(t *testing.T) {
	s := testStore(t)
	if err := s.RegisterAgent(filepath.Join(t.TempDir(), "crashed"), 999, time.Now()); err != nil {
		t.Fatal(err)
	}

	agents, err := s.LiveAgents(noneAlive)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Fatalf("a dead agent is still reported: %+v", agents)
	}
	// The reap is persisted, so the next reader does not repeat the work.
	recorded, err := s.Agents()
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 0 {
		t.Fatalf("the dead entry survived on disk: %+v", recorded)
	}
}

// Pids are probed outside the registry lock, so an agent can register between the
// read and the reap. Writing back the probed set would erase it, and an agent
// registers once at startup: it would stay invisible for its whole lifetime, which
// is exactly the case the registry exists to prevent.
func TestRegistryReapKeepsAnAgentThatRegisteredMeanwhile(t *testing.T) {
	s := testStore(t)
	joining := filepath.Join(t.TempDir(), "joining")
	if err := s.RegisterAgent(filepath.Join(t.TempDir(), "crashed"), 999, time.Now()); err != nil {
		t.Fatal(err)
	}

	agents, err := s.LiveAgents(func(int) bool {
		if err := s.RegisterAgent(joining, 4242, time.Now()); err != nil {
			t.Fatal(err)
		}
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Fatalf("the probed set reports a live agent: %+v", agents)
	}

	recorded, err := s.Agents()
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0].PID != 4242 {
		t.Fatalf("agents on disk = %+v, want only the one that registered meanwhile", recorded)
	}
}

// A root that re-registered under a new pid is a live agent, not the dead entry
// that was probed under the old one.
func TestRegistryReapKeepsARootThatRestarted(t *testing.T) {
	s := testStore(t)
	root := filepath.Join(t.TempDir(), "restarting")
	if err := s.RegisterAgent(root, 999, time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, err := s.LiveAgents(func(int) bool {
		if err := s.RegisterAgent(root, 1000, time.Now()); err != nil {
			t.Fatal(err)
		}
		return false
	}); err != nil {
		t.Fatal(err)
	}

	recorded, err := s.Agents()
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0].PID != 1000 {
		t.Fatalf("agents on disk = %+v, want the restarted agent", recorded)
	}
}

func TestRegistryIsEmptyBeforeAnyAgentRuns(t *testing.T) {
	agents, err := testStore(t).LiveAgents(allAlive)
	if err != nil {
		t.Fatalf("LiveAgents: %v", err)
	}
	if len(agents) != 0 {
		t.Fatalf("agents = %+v", agents)
	}
}

func TestRegistryNormalizesRoots(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	if err := s.RegisterAgent(root, 7, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The same folder spelled with a trailing separator and a redundant element is
	// the same agent, not a second one.
	if err := s.RegisterAgent(filepath.Join(root, "sub", ".."), 8, time.Now()); err != nil {
		t.Fatal(err)
	}

	agents, err := s.LiveAgents(allAlive)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].PID != 8 {
		t.Fatalf("agents = %+v", agents)
	}
}
