package syncengine

import (
	"testing"

	"pgregory.net/rapid"
)

// Property-based tests for the three-way planner. The safety invariant is the
// same one the multi-device sim enforces end-to-end: a side that changed since
// base is never silently overwritten or deleted — it either wins one-sided or
// surfaces as a Conflict for the caller (block or keep-both copy) to resolve.

// manifestsGen draws three manifests (local, base, remote) over a shared small
// path and hash alphabet, so added/removed/changed/converged cases all occur.
func manifestsGen() *rapid.Generator[[3]Manifest] {
	return rapid.Custom(func(t *rapid.T) [3]Manifest {
		paths := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{
			"a", "b", "c/d", "c/e", "f", "g/h/i",
		}), 0, 6, rapid.ID).Draw(t, "paths")
		var out [3]Manifest
		for i := range out {
			for _, p := range paths {
				if !rapid.Bool().Draw(t, "present") {
					continue
				}
				out[i].Entries = append(out[i].Entries, Entry{
					Path: p,
					Hash: rapid.SampledFrom([]string{"h1", "h2", "h3"}).Draw(t, "hash"),
					Mode: uint32(rapid.SampledFrom([]int{0o644, 0o755}).Draw(t, "mode")),
				})
			}
		}
		return out
	})
}

func TestPlanProps(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ms := manifestsGen().Draw(t, "manifests")
		local, base, remote := ms[0], ms[1], ms[2]
		actions := Plan(local, base, remote)

		lp, bp, rp := local.byPath(), base.byPath(), remote.byPath()
		seen := map[string]bool{}
		for _, a := range actions {
			if seen[a.Path] {
				t.Fatalf("path %q planned twice", a.Path)
			}
			seen[a.Path] = true

			l, lok := lp[a.Path]
			b, bok := bp[a.Path]
			r, rok := rp[a.Path]
			localChanged := changed(l, lok, b, bok)
			remoteChanged := changed(r, rok, b, bok)

			// Never lose a side's bytes: an action that overwrites or deletes the
			// local file is only legal when local is unchanged since base, and an
			// action that rewrites the remote manifest is only legal when remote is
			// unchanged — anything else must be a Conflict.
			switch a.Kind {
			case Download, DeleteLocal:
				if localChanged {
					t.Fatalf("%s planned for %q, which changed locally; local bytes would be lost", a.Kind, a.Path)
				}
			case Upload, DeleteRemote:
				if remoteChanged {
					t.Fatalf("%s planned for %q, which changed remotely; remote bytes would be lost", a.Kind, a.Path)
				}
			case Conflict:
				if !localChanged || !remoteChanged {
					t.Fatalf("Conflict planned for %q, which changed on %v/%v sides", a.Path, localChanged, remoteChanged)
				}
			}
		}

		// Completeness: every divergence produces an action. A path with no action
		// must already agree between local and remote (same presence, hash, mode) —
		// otherwise the plan silently dropped a difference.
		for _, set := range []map[string]Entry{lp, rp} {
			for p := range set {
				if seen[p] {
					continue
				}
				l, lok := lp[p]
				r, rok := rp[p]
				if lok != rok || l.Hash != r.Hash || l.Mode != r.Mode {
					t.Fatalf("no action for %q, but local (%v %+v) and remote (%v %+v) disagree", p, lok, l, rok, r)
				}
			}
		}

		// A fully-synced tree plans nothing.
		if got := Plan(local, local, local); len(got) != 0 {
			t.Fatalf("Plan(x,x,x) = %v, want empty", got)
		}
	})
}

func TestPlanReconcileProps(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ms := manifestsGen().Draw(t, "manifests")
		local, remote := ms[0], ms[2]
		actions := PlanReconcile(local, remote)

		lp, rp := local.byPath(), remote.byPath()
		seen := map[string]bool{}
		for _, a := range actions {
			if seen[a.Path] {
				t.Fatalf("path %q planned twice", a.Path)
			}
			seen[a.Path] = true
			// Baseless reconciliation cannot tell adds from deletes, so nothing may
			// be auto-resolved: every action is a Conflict.
			if a.Kind != Conflict {
				t.Fatalf("baseless reconcile planned %s for %q; only Conflict is safe without a base", a.Kind, a.Path)
			}
		}
		for _, set := range []map[string]Entry{lp, rp} {
			for p := range set {
				l, lok := lp[p]
				r, rok := rp[p]
				if agree := lok && rok && l.Hash == r.Hash && l.Mode == r.Mode; agree == seen[p] {
					t.Fatalf("path %q: agree=%v but action planned=%v", p, agree, seen[p])
				}
			}
		}
	})
}
