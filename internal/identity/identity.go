// Package identity manages the local profile: server, account handle, device
// token, and the KDF params needed to re-derive the master key from a passphrase.
//
// The profile holds the device token (for API auth) but never the master key or
// passphrase. The master key is derived on demand and kept only in memory.
// Persisting the token in a 0600 file rather than the OS keychain is a v1
// simplification (DESIGN.md section 5).
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

const DefaultProfile = "default"

// ErrNoProfile signals that no profile is stored yet.
var ErrNoProfile = errors.New("no aqt profile found; run `aqt login` first")

type Profile struct {
	Name        string            `json:"name"`
	Server      string            `json:"server"`
	Email       string            `json:"email"`
	OwnerHandle string            `json:"ownerHandle"`
	DeviceID    string            `json:"deviceId"`
	Token       string            `json:"token"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Kdf         crypto.KdfParams  `json:"kdf"`
	WrappedRoot crypto.SealedBlob `json:"wrappedRoot"`
	// AuthEpoch is the account auth epoch this device's token was issued under. A
	// passphrase change bumps it; the server rejects a token whose epoch is behind.
	AuthEpoch int `json:"authEpoch,omitempty"`
}

// Unlock recovers the account's master (root) key from the passphrase: it derives
// the unlock key from the stored KDF params and uses it to unwrap the locally-cached
// wrapped root, so no server round-trip is needed. A wrong passphrase fails the
// unwrap's AEAD tag rather than yielding a silently-wrong key.
func (p *Profile) Unlock(passphrase string) (crypto.MasterKey, error) {
	uk, err := crypto.DeriveUnlockKey(passphrase, p.Kdf)
	if err != nil {
		return crypto.MasterKey{}, err
	}
	defer uk.Wipe()
	return crypto.UnwrapRoot(p.WrappedRoot, uk)
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "aqt"), nil
}

// writeFileAtomic writes data to a temp file in path's directory, fsyncs it, and
// renames it over path, so a crash mid-write leaves the old profile or session
// cache intact rather than a torn one that breaks auth.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".aqt-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once renamed; cleans up every failure path
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a profile by name (empty means the default).
func Load(name string) (*Profile, error) {
	if name == "" {
		name = DefaultProfile
	}
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Save writes the profile with owner-only (0600) permissions.
func Save(p *Profile) error {
	if p.Name == "" {
		p.Name = DefaultProfile
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, p.Name+".json"), b, 0o600)
}

// --- session cache ---
//
// The session cache holds the derived master key so a working session does not
// re-prompt for the passphrase on every command. The key is encrypted at rest
// under a machine-bound key (see sessionKey) before being written to a 0600 file,
// so a copied or backed-up session file is useless on any other machine — closing
// the home-dir-backup / cloud-sync exposure.
//
// SECURITY TRADE-OFF: this does not defend against another process running as the
// same user on this machine, which can re-derive the same machine key. The full
// fix is the OS keychain / an in-memory agent (DESIGN.md section 5). Exposure is
// otherwise bounded by the TTL and cleared by `aqt logout`.

type session struct {
	Sealed    crypto.SealedBlob `json:"sealed"`
	ExpiresAt int64             `json:"expiresAt"` // unix seconds; 0 means no expiry
}

// sessionAAD domain-separates the at-rest session seal from other ciphertexts.
const sessionAAD = "aqt-session-at-rest-v1"

// machineSecretFn is overridable in tests to simulate a different machine.
var machineSecretFn = machineSecret

// sessionKey derives the at-rest encryption key from a stable per-machine secret,
// so the sealed session can only be opened on the machine that wrote it.
func sessionKey() crypto.ContentKey {
	sum := sha256.Sum256(append([]byte(sessionAAD+"\x00"), machineSecretFn()...))
	return crypto.ContentKey(sum)
}

// machineSecret returns a stable identifier for this machine that does not travel
// in a home-directory backup, so a restored/synced session file cannot be
// decrypted elsewhere. It falls back to the hostname (weaker, but still binds the
// cache to this host rather than leaving the key in cleartext).
func machineSecret() []byte {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return []byte("aqt-machine-id:" + s)
			}
		}
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			if id := parsePlatformUUID(out); id != "" {
				return []byte("aqt-platform-uuid:" + id)
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return []byte("aqt-host:" + h)
	}
	return []byte("aqt-no-machine-binding")
}

// parsePlatformUUID extracts the IOPlatformUUID value from `ioreg` output.
func parsePlatformUUID(out []byte) string {
	const marker = `"IOPlatformUUID" = "`
	s := string(out)
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

func sessionPath(name string) (string, error) {
	if name == "" {
		name = DefaultProfile
	}
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".session"), nil
}

// SaveSession caches the master key for ttl. A non-positive ttl caches it with
// no expiry (until logout).
func SaveSession(name string, mk crypto.MasterKey, ttl time.Duration) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sealed, err := crypto.Seal(mk[:], sessionKey(), []byte(sessionAAD))
	if err != nil {
		return err
	}
	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).Unix()
	}
	b, err := json.Marshal(session{Sealed: sealed, ExpiresAt: exp})
	if err != nil {
		return err
	}
	path, err := sessionPath(name)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

// LoadSession returns the cached master key if present and unexpired. An expired
// or malformed cache is removed and reported as a miss.
func LoadSession(name string) (crypto.MasterKey, bool) {
	var mk crypto.MasterKey
	path, err := sessionPath(name)
	if err != nil {
		return mk, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return mk, false
	}
	var s session
	if err := json.Unmarshal(b, &s); err != nil {
		os.Remove(path)
		return mk, false
	}
	if s.ExpiresAt != 0 && time.Now().Unix() > s.ExpiresAt {
		os.Remove(path)
		return mk, false
	}
	// A failure here means a wrong/absent machine key (the file was copied from
	// another machine) or the legacy plaintext format — treat both as a miss.
	plain, err := crypto.Open(s.Sealed, sessionKey(), []byte(sessionAAD))
	if err != nil || len(plain) != crypto.KeySize {
		os.Remove(path)
		return mk, false
	}
	copy(mk[:], plain)
	return mk, true
}

// ClearSession removes any cached master key.
func ClearSession(name string) error {
	path, err := sessionPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
