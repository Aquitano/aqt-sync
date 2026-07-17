package main

import (
	"fmt"
	"os"

	"github.com/aquitano/aqt-sync/internal/identity"
)

// bindTrackedRoot resolves which identity a tracked folder belongs to and makes
// this invocation use it. With no explicit --profile the recorded profile becomes
// the active one (so a folder initialized under --profile work syncs as "work"
// from any shell); explicit --profile or --server values that contradict the
// recorded identity are rejected with guidance instead of silently talking to the
// wrong account or server. Legacy state that predates the binding fields adopts
// the active profile only when that profile's server matches the folder's
// recorded server, so a machine with several accounts cannot silently rebind a
// folder; the adopted (or backfilled) binding is written back to .aqt/state.json.
//
// Call it before authedClient()/loadProfile() in any command that acts on the
// tracked folder's remote resource: it activates the bound profile by setting the
// global flagProfile, which everything downstream (client auth, base sealing)
// already keys on.
func bindTrackedRoot(root string) error {
	st, err := loadState(root)
	if err != nil || st.ID == "" {
		// No usable state: the command's own load will produce the real error.
		return nil
	}
	if st.Profile != "" && flagProfile != "" && flagProfile != st.Profile {
		return fmt.Errorf("%s belongs to profile %q, but --profile %s was given; drop --profile (the folder's own profile is used automatically), or re-clone the folder under the other profile to move it",
			root, st.Profile, flagProfile)
	}
	if flagServer != "" && st.Server != "" && !sameServer(flagServer, st.Server) {
		return fmt.Errorf("%s tracks a resource on %s, but --server %s was given; drop --server, or `aqt clone` the folder against the other server (its resources do not exist there)",
			root, st.Server, flagServer)
	}
	// Activate the recorded profile. Leaving flagProfile empty when the recorded
	// profile is the default keeps the flag's "unset" reading (and its output)
	// unchanged for the overwhelmingly common single-profile setup.
	if flagProfile == "" && st.Profile != "" && st.Profile != identity.DefaultProfile {
		flagProfile = st.Profile
	}
	prof, err := identity.Load(flagProfile)
	if err != nil {
		if st.Profile != "" {
			return fmt.Errorf("%s belongs to profile %q, which is not configured on this machine: %w", root, st.Profile, err)
		}
		// Never logged in: the command's own auth path reports (or tolerates) it.
		return nil
	}
	if st.Fingerprint != "" && prof.Fingerprint != "" && st.Fingerprint != prof.Fingerprint {
		return fmt.Errorf("%s was synced by a different account: profile %q now holds another account's key (fingerprint %s, folder recorded %s); log back into the original account, or re-clone the folder under this one",
			root, prof.Name, prof.Fingerprint, st.Fingerprint)
	}
	serverMoved := st.Server != "" && !sameServer(prof.Server, st.Server)
	if serverMoved && st.Profile == "" {
		// Legacy state carries no owner: the recorded server is the only evidence,
		// so a profile talking elsewhere cannot be assumed to own this folder.
		return fmt.Errorf("%s tracks a resource on %s, but profile %q talks to %s and this folder predates profile binding; use the profile that is logged into %s (--profile <name>), or re-clone the folder",
			root, st.Server, prof.Name, prof.Server, st.Server)
	}
	// The recorded owner (same profile, same account key) now talks to a different
	// server — the server moved or was restored under a new URL. Follow the profile
	// and record the move; the account identity, not the URL, is what binds.
	if serverMoved {
		fmt.Fprintf(os.Stderr, "note: %s recorded server %s; following profile %q to %s\n", root, st.Server, prof.Name, prof.Server)
	}
	// Backfill legacy state (adopted only when its recorded server matched, checked
	// above) and record a server move. Best-effort — the command can proceed either
	// way, and the next run retries the write.
	if st.Profile == "" || serverMoved || (st.Fingerprint == "" && prof.Fingerprint != "") {
		st.Profile = prof.Name
		st.Server = prof.Server
		if prof.Fingerprint != "" {
			st.Fingerprint = prof.Fingerprint
		}
		if err := saveState(root, st); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not record the folder's profile binding: %v\n", err)
		}
	}
	return nil
}

// bindTrackedDir is bindTrackedRoot for commands whose directory argument may not
// be tracked at all (e.g. snapshot commands driven by --id): not-a-tracked-folder
// is simply nothing to bind.
func bindTrackedDir(dir string) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return nil
	}
	return bindTrackedRoot(root)
}

// stateIdentity returns the folderState identity fields for a freshly written
// state, binding the folder to the profile that created or cloned it.
func stateIdentity(prof *identity.Profile) (profile, fingerprint string) {
	return prof.Name, prof.Fingerprint
}
