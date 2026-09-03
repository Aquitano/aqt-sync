// SPDX-License-Identifier: AGPL-3.0-or-later

// Package folderstate reads and writes the two control files a tracked folder keeps
// under .aqt/: state.json, the plaintext pointer to the resource it tracks, and
// base.json, the last-synced manifest sealed under the profile's base key.
package folderstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquitano/aqt-sync/internal/compress"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/fsatomic"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

const (
	stateFile = "state.json"
	baseFile  = "base.json"
)

// StatePath is where a tracked folder rooted at root keeps its resource pointer.
func StatePath(root string) string { return controlPath(root, stateFile) }

// BasePath is where a tracked folder rooted at root keeps its sealed base manifest.
func BasePath(root string) string { return controlPath(root, baseFile) }

func controlPath(root, name string) string {
	return filepath.Join(root, syncengine.ControlDir, name)
}

// State is the per-folder pointer stored in .aqt/state.json: which resource
// on which server this directory tracks, plus when its packs were last GC'd.
type State struct {
	ID     string `json:"id"`
	Server string `json:"server"`
	// Profile, Account, and Fingerprint bind the folder to the account that owns its
	// remote resource: Profile is the local profile name commands default to, and
	// Account is the server-side owner handle — the account's stable identity, which
	// a root-key rotation preserves and which every identity check keys on.
	// Fingerprint records the account's current signing key; bindTrackedRoot refreshes
	// it after a rotation. Profile and Account are written by init/clone/adopt and
	// required by LoadState.
	Profile     string `json:"profile,omitempty"`
	Account     string `json:"account,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	LastGC      int64  `json:"lastGC,omitempty"` // Unix seconds of the last reclaimPacks GC; throttles the next
	// RemoteVersion is the highest resource version this machine has observed —
	// the freshness pin. A server reporting a lower version has been rolled back
	// (restored from backup, or replaying an old state); syncing against it would
	// read the regression as remote changes and revert local files, so it is
	// refused unless --accept-rollback. Recorded by every init/clone/adopt and by
	// every sync, and required by LoadState: an absent pin would silently disable
	// the guard.
	RemoteVersion int `json:"remoteVersion,omitempty"`
}

// RecordRemoteVersion pins the freshness guard to the version this sync observed or
// just committed — including a lower one after an accepted rollback, so subsequent
// syncs stop tripping the guard. Best-effort (the sync itself succeeded); the
// caller's sync lock makes the read-modify-write race-free.
func RecordRemoteVersion(root string, version int) {
	st, err := LoadState(root)
	if err != nil || st.RemoteVersion == version {
		return
	}
	st.RemoteVersion = version
	if err := SaveState(root, st); err != nil {
		fmt.Fprintf(os.Stderr, "warning: recording synced version failed: %v\n", err)
	}
}

// SaveState replaces the folder pointer at root's state.json.
func SaveState(root string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(StatePath(root), b, 0o600)
}

// LoadState reads the folder pointer and refuses state that is missing the identity
// binding or the freshness pin. Every init/clone/adopt writes both, so an absence
// means state from a build that predates them: the folder cannot be tied to an
// account, and the rollback guard has nothing to compare against. Local state is
// regenerable, so re-tracking the folder is the fix — via `aqt untrack`, since
// `aqt init` refuses a directory that still has a control dir.
func LoadState(root string) (State, error) {
	var st State
	path := StatePath(root)
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	if st.Profile == "" || st.Account == "" {
		return st, fmt.Errorf("%s records no owning profile and account, so this folder cannot be bound to an identity; run `aqt untrack` here, then `aqt init` or `aqt clone`, to track it again (your files are left alone)", path)
	}
	if st.RemoteVersion <= 0 {
		return st, fmt.Errorf("%s records no synced server version, so a rolled-back server would go undetected; run `aqt untrack` here, then `aqt init` or `aqt clone`, to track it again (your files are left alone)", path)
	}
	return st, nil
}

// sealedBase is the legacy JSON at-rest envelope for the local base manifest.
// SaveBase writes the binary form below since #236; decodeBase still opens this
// one so a folder synced by an older build keeps its base across the upgrade.
type sealedBase struct {
	Sealed *crypto.SealedBlob `json:"sealed"`
}

// baseMagic opens the binary base.json envelope: this magic, one compression-alg
// byte, the sealing nonce, then the raw ciphertext. The JSON envelope it replaces
// base64-encoded the whole sealed manifest (4/3 the size, decoded through an
// extra full-size copy), on top of the manifest JSON base64-encoding every inline
// file's bytes — so a tree of small incompressible files produced a base nearly
// twice its own size. The manifest is now also compressed before sealing, which
// wins back most of that inner base64 expansion. base.json holds chunk decryption
// keys and inline file plaintext, so it stays sealed under the profile's sealing
// key exactly as before; only the packaging around the ciphertext changed.
var baseMagic = []byte("aqt-base-v2\n")

const (
	baseAlgNone byte = 0
	baseAlgZstd byte = 1
)

// SaveBase seals m under profile's base key and replaces root's base.json.
func SaveBase(root, profile string, m syncengine.Manifest) error {
	plain, err := json.Marshal(m)
	if err != nil {
		return err
	}
	payload, alg := compress.Encode(plain)
	sealed, err := identity.SealBase(profile, payload)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(baseMagic)+1+len(sealed.Nonce)+len(sealed.Ciphertext))
	buf = append(buf, baseMagic...)
	if alg == compress.Zstd {
		buf = append(buf, baseAlgZstd)
	} else {
		buf = append(buf, baseAlgNone)
	}
	buf = append(buf, sealed.Nonce...)
	buf = append(buf, sealed.Ciphertext...)
	return fsatomic.WriteFile(BasePath(root), buf, 0o600)
}

// decodeBase opens a sealed base.json into m — the binary envelope, or the legacy
// JSON one for a base written before the format change. Anything else is refused
// rather than read as a bare manifest: base.json carries chunk keys and inline
// plaintext, and an unreadable base is not fatal — the sync degrades to
// --reconcile, which rebuilds it.
func decodeBase(b []byte, profile string, m *syncengine.Manifest) error {
	if rest, ok := bytes.CutPrefix(b, baseMagic); ok {
		return decodeBinaryBase(rest, profile, m)
	}
	var env sealedBase
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	if env.Sealed == nil {
		return errors.New("base.json is not a sealed envelope; re-run `aqt sync --reconcile` to rebuild it")
	}
	plain, err := identity.OpenBase(profile, *env.Sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, m)
}

// decodeBinaryBase reads the body after baseMagic. The nonce length is fixed by
// the sealing AEAD, so the layout needs no length fields.
func decodeBinaryBase(b []byte, profile string, m *syncengine.Manifest) error {
	if len(b) < 1+crypto.NonceSize {
		return errors.New("base.json envelope is truncated")
	}
	var alg string
	switch b[0] {
	case baseAlgNone:
	case baseAlgZstd:
		alg = compress.Zstd
	default:
		return fmt.Errorf("base.json envelope declares unknown compression %d", b[0])
	}
	blob := crypto.SealedBlob{Nonce: b[1 : 1+crypto.NonceSize], Ciphertext: b[1+crypto.NonceSize:]}
	payload, err := identity.OpenBase(profile, blob)
	if err != nil {
		return err
	}
	plain, err := compress.DecodeSelfSealed(payload, alg)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, m)
}

// LoadBaseForSync returns the last-synced manifest and whether a usable base
// exists. A missing, corrupt, or unopenable base reports exists=false so the caller
// can refuse the sync — reconciling against an empty base silently resurrects
// deletions — unless the user opts into --reconcile.
func LoadBaseForSync(root, profile string) (syncengine.Manifest, bool, error) {
	var m syncengine.Manifest
	b, err := os.ReadFile(BasePath(root))
	if errors.Is(err, os.ErrNotExist) {
		return m, false, nil
	}
	if err != nil {
		return m, false, err
	}
	if err := decodeBase(b, profile, &m); err != nil {
		fmt.Fprintf(os.Stderr, "warning: .aqt/base.json is unreadable (%v)\n", err)
		return syncengine.Manifest{}, false, nil
	}
	return m, true, nil
}

// LoadBase returns the last-synced manifest, or an empty one if none exists yet.
// Used by the offline `status`, which tolerates a missing base (it shows every
// file as new). `sync` uses LoadBaseForSync, which refuses an absent base.
func LoadBase(root, profile string) (syncengine.Manifest, error) {
	var m syncengine.Manifest
	b, err := os.ReadFile(BasePath(root))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	return m, decodeBase(b, profile, &m)
}
