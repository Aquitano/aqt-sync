// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestInspectSessionLeavesCacheUntouched(t *testing.T) {
	for _, kind := range []string{"unlocked", "no-expiry", "expired", "invalid-json", "invalid-key", "missing"} {
		t.Run(kind, func(t *testing.T) {
			isolateConfigDir(t)
			mk, err := crypto.GenerateMasterKey()
			if err != nil {
				t.Fatal(err)
			}
			defer mk.Wipe()
			ttl := time.Hour
			if kind == "no-expiry" {
				ttl = 0
			}
			if err := SaveSession("default", mk, ttl); err != nil {
				t.Fatal(err)
			}
			path, err := sessionPath("default")
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var cache session
			if err := json.Unmarshal(data, &cache); err != nil {
				t.Fatal(err)
			}
			want := SessionUnlocked
			switch kind {
			case "expired":
				want = SessionExpired
				cache.ExpiresAt = time.Now().Add(-time.Hour).Unix()
			case "invalid-key":
				want = SessionInvalid
				cache.Sealed.Ciphertext[0] ^= 1
			case "invalid-json":
				want = SessionInvalid
			case "missing":
				want = SessionMissing
			}
			data, err = json.Marshal(cache)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "invalid-json" {
				data = []byte("broken cache")
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			info, err := InspectSession("")
			if (err != nil) != (kind == "invalid-json") || info.State != want {
				t.Fatalf("InspectSession = %+v, %v; want %s", info, err, want)
			}
			if kind != "missing" && kind != "invalid-json" && info.ExpiresAt != cache.ExpiresAt {
				t.Fatalf("expiry = %d, want %d", info.ExpiresAt, cache.ExpiresAt)
			}
			after, err := os.ReadFile(path)
			if kind == "missing" {
				if !os.IsNotExist(err) {
					t.Fatal("inspection created a cache")
				}
			} else if err != nil || !bytes.Equal(after, data) {
				t.Fatal("inspection changed or removed the cache")
			}
			loaded, ok := LoadSession("")
			defer loaded.Wipe()
			if ok != (want == SessionUnlocked) || (ok && loaded != mk) {
				t.Fatal("LoadSession no longer agrees with inspection")
			}
			if want == SessionInvalid || want == SessionExpired {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("LoadSession no longer removes invalid or expired caches")
				}
			}
		})
	}
}
