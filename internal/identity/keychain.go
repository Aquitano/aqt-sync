package identity

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/zalando/go-keyring"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// keychainService is the service name every aqt secret is filed under in the OS
// secret store (macOS Keychain, Windows Credential Manager, or a Linux Secret
// Service such as gnome-keyring/KWallet).
const keychainService = "aqt"

// keychainDisabled lets a headless or automated environment opt out of the OS
// keychain and use the machine-bound file fallback instead. This avoids a
// keychain access prompt (or, on a locked macOS keychain with no GUI, a blocking
// `security` call) in CI, cron jobs, and other non-interactive contexts.
func keychainDisabled() bool {
	v := os.Getenv("AQT_NO_KEYCHAIN")
	return v != "" && v != "0" && !strings.EqualFold(v, "false")
}

// Indirection over go-keyring so tests can mock the store or simulate a host with
// no backend, and never touch the developer's real keychain.
var (
	keyringGet    = keyring.Get
	keyringSet    = keyring.Set
	keyringDelete = keyring.Delete
)

func sealingKeyID(name string) string { return "session-key:" + name }
func tokenID(name string) string      { return "token:" + name }

// keychainSealingKey returns the per-profile random key that seals the session
// cache, fetching it from the OS keychain. With create set, it mints and stores a
// fresh key when none exists. It returns ok=false when the keychain backend is
// unavailable (e.g. a headless host with no Secret Service), so callers fall back
// to the machine-bound key and keep working.
func keychainSealingKey(name string, create bool) (crypto.ContentKey, bool) {
	var ck crypto.ContentKey
	if keychainDisabled() {
		return ck, false
	}
	v, err := keyringGet(keychainService, sealingKeyID(name))
	switch {
	case err == nil:
		if raw, derr := base64.StdEncoding.DecodeString(v); derr == nil && len(raw) == crypto.KeySize {
			copy(ck[:], raw)
			return ck, true
		}
		// Corrupt entry: re-mint below if allowed, otherwise report unusable.
	case errors.Is(err, keyring.ErrNotFound):
		// No key stored yet; mint one below if allowed.
	default:
		return ck, false // backend unavailable
	}

	if !create {
		return ck, false
	}
	if _, err := rand.Read(ck[:]); err != nil {
		return ck, false
	}
	if err := keyringSet(keychainService, sealingKeyID(name), base64.StdEncoding.EncodeToString(ck[:])); err != nil {
		return ck, false
	}
	return ck, true
}

// saveSealingKey returns the strongest available key to seal the session cache:
// the random keychain key (minting one if needed), or the machine-bound key when
// no keychain backend is present.
func saveSealingKey(name string) crypto.ContentKey {
	if k, ok := keychainSealingKey(name, true); ok {
		return k
	}
	return machineBoundKey()
}

// loadSealingKeys returns the candidate keys to try when opening the session
// cache, strongest first. Trying both lets a cache survive a keychain that came or
// went between save and load, and still opens the pre-keychain machine-bound
// format.
func loadSealingKeys(name string) []crypto.ContentKey {
	var keys []crypto.ContentKey
	if k, ok := keychainSealingKey(name, false); ok {
		keys = append(keys, k)
	}
	return append(keys, machineBoundKey())
}

func keychainDropSealingKey(name string) {
	if keychainDisabled() {
		return
	}
	_ = keyringDelete(keychainService, sealingKeyID(name))
}

// keychainStoreToken stores the device token in the keychain, returning false when
// the keychain is disabled or no backend is available (the caller then keeps the
// token in the 0600 file).
func keychainStoreToken(name, token string) bool {
	if keychainDisabled() {
		return false
	}
	return keyringSet(keychainService, tokenID(name), token) == nil
}

// keychainLoadToken returns the device token from the keychain if present.
func keychainLoadToken(name string) (string, bool) {
	if keychainDisabled() {
		return "", false
	}
	v, err := keyringGet(keychainService, tokenID(name))
	if err != nil {
		return "", false
	}
	return v, true
}

func keychainDropToken(name string) {
	if keychainDisabled() {
		return
	}
	_ = keyringDelete(keychainService, tokenID(name))
}
