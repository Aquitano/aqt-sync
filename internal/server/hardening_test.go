package server

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// newHarnessCfg is newHarness with a non-default server config.
func newHarnessCfg(t *testing.T, cfg Config) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &harness{t: t, router: NewWithConfig(store, cfg).Router()}
}

// createReq builds a self-consistent account-creation request for an email/passphrase
// pair (fresh random keys each call, so two calls for the same email are two distinct
// signups).
func createReq(t *testing.T, email, passphrase string) api.CreateAccountRequest {
	t.Helper()
	kdf, err := crypto.NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey(passphrase, kdf)
	if err != nil {
		t.Fatal(err)
	}
	wrappedRoot, err := crypto.WrapRoot(mk, uk)
	if err != nil {
		t.Fatal(err)
	}
	return api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   "test-device",
	}
}

// --- 5.1: decoy bootstrap indistinguishability ---

func TestDecoySaltInDistributionAndDeterministic(t *testing.T) {
	h := newHarness(t)

	b1 := h.bootstrap("ghost@example.com")
	b2 := h.bootstrap("ghost@example.com")
	if b1.Kdf.Time != b2.Kdf.Time || b1.Kdf.Memory != b2.Kdf.Memory || !bytes.Equal(b1.Kdf.Salt, b2.Kdf.Salt) {
		t.Fatal("decoy for the same email is not deterministic")
	}

	const full = uint32(256 * 1024)
	if b1.Kdf.Memory != 64*1024 && b1.Kdf.Memory != 128*1024 && b1.Kdf.Memory != full {
		t.Fatalf("decoy memory %d KiB is off the calibration distribution", b1.Kdf.Memory)
	}
	if b1.Kdf.Time == 0 {
		t.Fatal("decoy time cost is zero")
	}

	// Across different emails the params vary, so a decoy is not a single constant an
	// attacker could match to classify unknown emails.
	seen := map[string]bool{}
	for _, e := range []string{"a@x", "b@x", "c@x", "d@x", "e@x", "f@x", "g@x", "h@x"} {
		bx := h.bootstrap(e)
		seen[fmt.Sprintf("%d/%d", bx.Kdf.Time, bx.Kdf.Memory)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("decoy params constant across emails (%v); still a fingerprint", seen)
	}
}

// --- 5.2: account-creation conflict is not an existence oracle ---

func TestOpenRegistrationConflictIndistinguishable(t *testing.T) {
	h := newHarness(t) // default open registration

	var first api.AuthResponse
	if code := h.do(http.MethodPost, "/v1/account", "", createReq(t, "dup@example.com", "pass one"), &first); code != http.StatusCreated {
		t.Fatalf("first signup: got %d", code)
	}

	// A second signup for the same email (different keys) must look exactly like a
	// fresh one: same 201, same populated body shape.
	var second api.AuthResponse
	code := h.do(http.MethodPost, "/v1/account", "", createReq(t, "dup@example.com", "pass two"), &second)
	if code != http.StatusCreated {
		t.Fatalf("duplicate signup leaked existence: got %d, want 201", code)
	}
	if second.Token == "" || len(second.Token) != len(first.Token) ||
		second.OwnerHandle == "" || second.DeviceID == "" {
		t.Fatalf("duplicate response shape differs from a real one: %+v", second)
	}
	if second.OwnerHandle == first.OwnerHandle {
		t.Fatal("duplicate signup returned the existing account's handle (attached to the victim)")
	}

	// The decoy token grants nothing; the caller's next authed call fails naturally.
	if code := h.do(http.MethodGet, "/v1/resources", second.Token, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("decoy token authenticated: got %d, want 401", code)
	}
	// The real account is untouched: its token still works.
	if code := h.do(http.MethodGet, "/v1/resources", first.Token, nil, nil); code != http.StatusOK {
		t.Fatalf("original account disturbed by duplicate signup: got %d", code)
	}
}

func TestInviteRegistration(t *testing.T) {
	h := newHarnessCfg(t, Config{Registration: RegistrationInvite, InviteTokens: []string{"good-invite"}})

	req := createReq(t, "invite@example.com", "pass")
	if code := h.do(http.MethodPost, "/v1/account", "", req, nil); code != http.StatusForbidden {
		t.Fatalf("signup without an invite: got %d, want 403", code)
	}
	req.InviteToken = "wrong"
	if code := h.do(http.MethodPost, "/v1/account", "", req, nil); code != http.StatusForbidden {
		t.Fatalf("signup with a wrong invite: got %d, want 403", code)
	}

	req.InviteToken = "good-invite"
	var resp api.AuthResponse
	if code := h.do(http.MethodPost, "/v1/account", "", req, &resp); code != http.StatusCreated {
		t.Fatalf("signup with a valid invite: got %d, want 201", code)
	}
	if code := h.do(http.MethodGet, "/v1/resources", resp.Token, nil, nil); code != http.StatusOK {
		t.Fatalf("token from an invited signup does not work: got %d", code)
	}
}

// --- 5.5: authenticated rate limit ---

func TestAuthedRateLimitReturns429(t *testing.T) {
	h := newHarnessCfg(t, Config{AuthedRatePerSec: 0.0001, AuthedBurst: 3})
	token, _ := h.signup("rl@example.com", "pass")

	// The burst allows a few requests, then the bucket is empty and refills far too
	// slowly to matter within the test.
	allowed, limited := 0, false
	for i := 0; i < 12; i++ {
		switch code := h.do(http.MethodGet, "/v1/resources", token, nil, nil); code {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			limited = true
		default:
			t.Fatalf("unexpected status %d", code)
		}
		if limited {
			break
		}
	}
	if !limited {
		t.Fatal("authenticated route never rate-limited")
	}
	if allowed == 0 || allowed > 3 {
		t.Fatalf("allowed %d requests before limiting, want 1..3 (the burst)", allowed)
	}
}

// --- 5.5: per-owner quotas (store level) ---

func TestPackByteQuota(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "quota@example.com")

	packA, dataA, _ := packOf("chunk one", "chunk two")
	quota := int64(len(dataA)) // room for exactly this pack

	if _, err := s.PutPack(owner, packA, dataA, quota); err != nil {
		t.Fatalf("first pack within quota: %v", err)
	}
	if b, _ := s.OwnerPackBytes(owner); b != int64(len(dataA)) {
		t.Fatalf("counter = %d, want %d", b, len(dataA))
	}
	// A re-PUT is idempotent: it does not double-count and does not trip the quota.
	if _, err := s.PutPack(owner, packA, dataA, quota); err != nil {
		t.Fatalf("idempotent re-put: %v", err)
	}
	if b, _ := s.OwnerPackBytes(owner); b != int64(len(dataA)) {
		t.Fatalf("re-put double-counted: %d", b)
	}

	// A second, distinct pack exceeds the quota and is rejected without being stored.
	packB, dataB, _ := packOf("chunk three")
	if _, err := s.PutPack(owner, packB, dataB, quota); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("over-quota pack: err = %v, want ErrQuotaExceeded", err)
	}
	if b, _ := s.OwnerPackBytes(owner); b != int64(len(dataA)) {
		t.Fatalf("rejected pack still counted: %d", b)
	}
	if _, err := os.Stat(s.packPath(owner, packB)); !os.IsNotExist(err) {
		t.Fatalf("rejected pack file was left on disk: %v", err)
	}
}

func TestPackByteCounterAcrossGCAndDelete(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "gc@example.com")

	packA, dataA, idsA := packOf("a1", "a2")
	packB, dataB, _ := packOf("b1")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPack(owner, packB, dataB, 0); err != nil {
		t.Fatal(err)
	}
	total := int64(len(dataA) + len(dataB))
	if b, _ := s.OwnerPackBytes(owner); b != total {
		t.Fatalf("counter after two puts = %d, want %d", b, total)
	}

	// Root only pack A's objects; a sweep reclaims the now-dead pack B.
	res := s.rootResource(t, owner, idsA)
	if _, freed, err := s.GCPacks(owner, forceGC); err != nil || freed != int64(len(dataB)) {
		t.Fatalf("sweep of B: freed=%d err=%v, want %d", freed, err, len(dataB))
	}
	if b, _ := s.OwnerPackBytes(owner); b != int64(len(dataA)) {
		t.Fatalf("counter after sweeping B = %d, want %d", b, len(dataA))
	}

	// Deleting the resource unroots A; the next sweep reclaims it and the counter
	// returns to zero.
	if err := s.DeleteResource(owner, res); err != nil {
		t.Fatal(err)
	}
	if _, freed, err := s.GCPacks(owner, forceGC); err != nil || freed != int64(len(dataA)) {
		t.Fatalf("sweep of A: freed=%d err=%v, want %d", freed, err, len(dataA))
	}
	if b, _ := s.OwnerPackBytes(owner); b != 0 {
		t.Fatalf("counter after sweeping everything = %d, want 0", b)
	}
}

func TestDeviceLimit(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "devs@example.com")

	if _, _, err := s.CreateDevice(owner, "a", 1, 2); err != nil {
		t.Fatalf("first device: %v", err)
	}
	if _, _, err := s.CreateDevice(owner, "b", 1, 2); err != nil {
		t.Fatalf("second device: %v", err)
	}
	if _, _, err := s.CreateDevice(owner, "c", 1, 2); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("third device over the cap: err = %v, want ErrDeviceLimit", err)
	}
	// 0 means unlimited.
	if _, _, err := s.CreateDevice(owner, "d", 1, 0); err != nil {
		t.Fatalf("unlimited cap rejected a device: %v", err)
	}
}

// --- 5.6: trusted-proxy config knob is accepted for every shape ---

func TestTrustedProxyConfigAccepted(t *testing.T) {
	cases := []Config{
		{},                               // default: gin's loopback-only
		Config{}.WithTrustedProxies(nil), // trust none
		Config{}.WithTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1"}), // explicit
		Config{}.WithTrustedProxies([]string{"not-a-cidr"}),              // invalid: logged, not fatal
	}
	for i, cfg := range cases {
		h := newHarnessCfg(t, cfg)
		// The engine still serves requests regardless of the proxy config.
		if rec := h.get("/x/does-not-exist"); rec.Code != http.StatusNotFound {
			t.Fatalf("case %d: share view returned %d, want 404", i, rec.Code)
		}
	}
}
