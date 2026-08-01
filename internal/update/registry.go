package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	agentsFileName = "agents.json"
	agentsLockName = "agents.lock"

	// maxAgents bounds the registry. A user with more tracked folders than this
	// running at once is not a case worth growing an unbounded file for; the oldest
	// entries are dropped and the worst outcome is an auto-update that does not
	// defer for an agent it never recorded.
	maxAgents = 64

	// lockStale is how long a registry lock may exist before it is assumed
	// abandoned. Registration is a read-modify-write of a few hundred bytes, so a
	// lock this old belongs to a process that died holding it.
	lockStale = 5 * time.Second
)

// Agent is one running watch agent, recorded globally so an update started in one
// folder can see agents running in every other. The per-folder .aqt/agent.pid
// remains the authority for that folder; this is the index that makes the set
// visible from outside it.
type Agent struct {
	Root      string `json:"root"`
	PID       int    `json:"pid"`
	StartedAt string `json:"startedAt"`
}

func (s Store) agentsPath() string { return filepath.Join(s.Dir, agentsFileName) }

// Agents returns every recorded agent, without judging whether it still runs.
func (s Store) Agents() ([]Agent, error) {
	b, err := os.ReadFile(s.agentsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var agents []Agent
	if err := json.Unmarshal(b, &agents); err != nil {
		return nil, nil // a corrupt index is not worth failing a command over
	}
	return agents, nil
}

// LiveAgents returns the agents that are still running and drops the rest from
// the file. alive is supplied by the caller because probing a pid is
// platform-specific and already implemented where the agents are managed.
//
// Reaping on read is what keeps a crashed agent from deferring auto updates
// forever: nothing else is guaranteed to run after a process dies.
func (s Store) LiveAgents(alive func(pid int) bool) ([]Agent, error) {
	recorded, err := s.Agents()
	if err != nil || len(recorded) == 0 {
		return nil, err
	}
	live := make([]Agent, 0, len(recorded))
	for _, a := range recorded {
		if alive(a.PID) {
			live = append(live, a)
		}
	}
	if len(live) != len(recorded) {
		// Best effort: the caller asked who is running, not to repair the file.
		_ = s.withAgentLock(func() error { return s.writeAgents(live) })
	}
	return live, nil
}

// RegisterAgent records a running agent, replacing any previous entry for the
// same root.
func (s Store) RegisterAgent(root string, pid int, now time.Time) error {
	root = normalizeRoot(root)
	return s.withAgentLock(func() error {
		agents, err := s.Agents()
		if err != nil {
			return err
		}
		out := make([]Agent, 0, len(agents)+1)
		for _, a := range agents {
			if normalizeRoot(a.Root) != root {
				out = append(out, a)
			}
		}
		out = append(out, Agent{
			Root:      root,
			PID:       pid,
			StartedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
		})
		if len(out) > maxAgents {
			out = out[len(out)-maxAgents:]
		}
		return s.writeAgents(out)
	})
}

// UnregisterAgent drops the entry for a root, on clean agent shutdown.
func (s Store) UnregisterAgent(root string) error {
	root = normalizeRoot(root)
	return s.withAgentLock(func() error {
		agents, err := s.Agents()
		if err != nil {
			return err
		}
		out := make([]Agent, 0, len(agents))
		for _, a := range agents {
			if normalizeRoot(a.Root) != root {
				out = append(out, a)
			}
		}
		if len(out) == len(agents) {
			return nil
		}
		return s.writeAgents(out)
	})
}

func (s Store) writeAgents(agents []Agent) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if len(agents) == 0 {
		err := os.Remove(s.agentsPath())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.MarshalIndent(agents, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.agentsPath(), append(b, '\n'), 0o600)
}

// withAgentLock serializes read-modify-write of the registry across processes.
// Agents in different folders start independently, so without this two starting
// at once could each write back a set missing the other.
func (s Store) withAgentLock(fn func() error) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(s.Dir, agentsLockName)
	deadline := time.Now().Add(2 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			defer os.Remove(path)
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if fi, statErr := os.Stat(path); statErr == nil && time.Since(fi.ModTime()) > lockStale {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("update registry at %s is locked", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// normalizeRoot makes the same folder compare equal however it was spelled. Case
// is folded because the platforms this runs on that have case-insensitive paths
// are the same ones where two spellings of a root are otherwise recorded twice.
func normalizeRoot(root string) string {
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	return strings.ToLower(filepath.Clean(root))
}
