package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
)

func TestListAdminAccountsReportsUsageAndPolicy(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	alice := s.mustAccount(t, "alice@example.com")
	s.mustAccount(t, "bob@example.com")

	quota := int64(4096)
	if err := s.SetAccountQuota(alice, &quota); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	if err := s.SetAccountDisabled(alice, true); err != nil {
		t.Fatalf("disable: %v", err)
	}

	accounts, err := s.ListAdminAccounts()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("listed %d accounts, want 2", len(accounts))
	}
	byHandle := map[string]AdminAccount{}
	for _, a := range accounts {
		byHandle[a.OwnerHandle] = a
	}
	got := byHandle[alice]
	if got.Email != "alice@example.com" {
		t.Errorf("email = %q", got.Email)
	}
	if !got.QuotaBytes.Valid || got.QuotaBytes.Int64 != quota {
		t.Errorf("quota = %+v, want %d", got.QuotaBytes, quota)
	}
	if !got.Disabled() {
		t.Error("account reports active after being disabled")
	}
	if got.CreatedAt.IsZero() {
		t.Error("createdAt is unset on a freshly created account")
	}
}

// The three quota states must stay distinguishable: an override, an explicit
// exemption, and inheritance. Collapsing "unlimited" into "no override" would
// silently re-cap an exempt account the next time the server default changes.
func TestQuotaOverrideStates(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "quota@example.com")

	q, err := s.AccountQuota(owner)
	if err != nil {
		t.Fatalf("read quota: %v", err)
	}
	if q.Valid {
		t.Fatal("a new account starts with a quota override")
	}

	var unlimited int64
	if err := s.SetAccountQuota(owner, &unlimited); err != nil {
		t.Fatalf("set unlimited: %v", err)
	}
	if q, _ = s.AccountQuota(owner); !q.Valid || q.Int64 != 0 {
		t.Fatalf("explicit unlimited did not persist: %+v", q)
	}
	a, err := s.AdminAccountByRef(owner)
	if err != nil {
		t.Fatalf("by ref: %v", err)
	}
	if got := a.EffectiveQuota(1 << 30); got != 0 {
		t.Errorf("effective quota = %d, want 0 (exempt from the server default)", got)
	}

	if err := s.SetAccountQuota(owner, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if q, _ = s.AccountQuota(owner); q.Valid {
		t.Fatalf("clearing left an override: %+v", q)
	}
	if a, _ = s.AdminAccountByRef(owner); a.EffectiveQuota(1<<30) != 1<<30 {
		t.Error("a cleared override does not inherit the server default")
	}
}

func TestSetAccountQuotaRejectsNegative(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "neg@example.com")
	bad := int64(-1)
	if err := s.SetAccountQuota(owner, &bad); err == nil {
		t.Fatal("a negative quota was accepted")
	}
}

func TestAdminAccountByRefResolvesEmailHandleAndPrefix(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "ref@example.com")

	for name, ref := range map[string]string{
		"email":  "ref@example.com",
		"handle": owner,
		"prefix": owner[:6],
	} {
		t.Run(name, func(t *testing.T) {
			a, err := s.AdminAccountByRef(ref)
			if err != nil {
				t.Fatalf("resolve %q: %v", ref, err)
			}
			if a.OwnerHandle != owner {
				t.Fatalf("resolved to %q, want %q", a.OwnerHandle, owner)
			}
		})
	}

	if _, err := s.AdminAccountByRef("nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown ref = %v, want ErrNotFound", err)
	}
	if _, err := s.AdminAccountByRef(""); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty ref = %v, want ErrNotFound", err)
	}
}

// Every admin verb is destructive or policy-changing, so a prefix matching more
// than one account must refuse rather than pick one.
func TestAdminAccountByRefRefusesAmbiguousPrefix(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	first := s.mustAccount(t, "one@example.com")
	// Handles are random, so find a prefix length that genuinely collides rather
	// than assuming one does.
	var second string
	for i := range 600 {
		h := s.mustAccount(t, fmtEmail(i))
		if h[:1] == first[:1] {
			second = h
			break
		}
	}
	if second == "" {
		t.Skip("no colliding handle prefix generated")
	}
	if _, err := s.AdminAccountByRef(first[:1]); !errors.Is(err, ErrAmbiguousAccount) {
		t.Fatalf("ambiguous prefix = %v, want ErrAmbiguousAccount", err)
	}
}

func TestSuspensionCachePurgesExpiredEntriesAndStaysBounded(t *testing.T) {
	t.Parallel()
	cache := newSuspensionCache()
	cache.entries["expired"] = suspensionEntry{expires: time.Now().Add(-time.Second)}
	cache.put("active", false)
	if _, exists := cache.entries["expired"]; exists {
		t.Fatal("expired entry survived a subsequent cache write")
	}

	for i := range suspensionCacheMaxEntries + 1 {
		cache.put("owner-"+strconv.Itoa(i), false)
	}
	if got := len(cache.entries); got > suspensionCacheMaxEntries {
		t.Fatalf("cache retained %d entries, max is %d", got, suspensionCacheMaxEntries)
	}
}

func fmtEmail(i int) string {
	return "user" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "@example.com"
}

// Suspension must be reversible and touch no stored data: it is the tool for
// "stop this account now", not for erasure.
func TestSuspensionIsReversibleAndKeepsData(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "suspend@example.com")
	id := s.rootResource(t, owner, nil)

	if err := s.SetAccountDisabled(owner, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	disabled, err := s.AccountDisabled(owner)
	if err != nil || !disabled {
		t.Fatalf("AccountDisabled = %v, %v; want true", disabled, err)
	}
	if _, err := s.GetResource(id, owner); err != nil {
		t.Errorf("suspension destroyed data: %v", err)
	}

	if err := s.SetAccountDisabled(owner, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if disabled, _ = s.AccountDisabled(owner); disabled {
		t.Error("account still disabled after enable")
	}
}

// A suspended account's devices must be refused with 403, not 401: the token is
// valid, so telling the user to re-authenticate would loop them.
func TestSuspendedAccountIsForbiddenNotUnauthorized(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("suspended@example.com", "pw-suspended-account")

	if code := h.do(http.MethodGet, "/v1/resources", token, nil, nil); code != http.StatusOK {
		t.Fatalf("pre-suspension list: status %d, want 200", code)
	}

	owner, err := h.store.OwnerByToken(token)
	if err != nil {
		t.Fatalf("resolve owner: %v", err)
	}
	if err := h.store.SetAccountDisabled(owner, true); err != nil {
		t.Fatalf("disable: %v", err)
	}

	rec := h.raw(http.MethodGet, "/v1/resources", token, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("suspended list: status %d, want 403", rec.Code)
	}
	var body api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 403 body: %v", err)
	}
	if body.Code != api.ErrCodeAccountDisabled {
		t.Errorf("code = %q, want %q", body.Code, api.ErrCodeAccountDisabled)
	}

	// Restoring must let the same token straight back in, with no re-login.
	if err := h.store.SetAccountDisabled(owner, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if code := h.do(http.MethodGet, "/v1/resources", token, nil, nil); code != http.StatusOK {
		t.Fatalf("post-restore list: status %d, want 200", code)
	}
}

// A per-account override must win over the server-wide default in both
// directions: capping an account on an uncapped server, and exempting one on a
// capped server.
func TestPerAccountQuotaOverridesServerDefault(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.srv.cfg.QuotaBytes = 0 // server-wide: unlimited
	token, _ := h.signup("capped@example.com", "pw-per-account-quota")
	owner, err := h.store.OwnerByToken(token)
	if err != nil {
		t.Fatalf("resolve owner: %v", err)
	}

	tiny := int64(1)
	if err := h.store.SetAccountQuota(owner, &tiny); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	got, err := h.srv.effectiveQuota(owner)
	if err != nil || got != tiny {
		t.Fatalf("effectiveQuota = %d, %v; want %d", got, err, tiny)
	}
	if err := h.srv.checkAccountLimit(owner, "", 1024); err == nil {
		t.Error("a write past the per-account quota was allowed on an uncapped server")
	}

	// The reverse: exempt this account while the server caps everyone.
	h.srv.cfg.QuotaBytes = 1
	var unlimited int64
	if err := h.store.SetAccountQuota(owner, &unlimited); err != nil {
		t.Fatalf("set unlimited: %v", err)
	}
	if got, _ = h.srv.effectiveQuota(owner); got != 0 {
		t.Fatalf("effectiveQuota = %d, want 0 (exempt)", got)
	}
	if err := h.srv.checkAccountLimit(owner, "", 1<<20); err != nil {
		t.Errorf("an exempt account was refused: %v", err)
	}
}

// Scheduled snapshots are a write path too. They must use the account override,
// not only the server default passed to the background job.
func TestAutoSnapshotsHonorPerAccountQuota(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "auto-quota@example.com")
	s.rootResource(t, owner, nil)

	tiny := int64(1)
	if err := s.SetAccountQuota(owner, &tiny); err != nil {
		t.Fatal(err)
	}
	created, err := s.RunAutoSnapshotsWithLimits(0, 0) // server default: unlimited
	var limit *LimitExceededError
	if created != 0 || !errors.As(err, &limit) || limit.Limit != tiny {
		t.Fatalf("capped auto-snapshot = created %d err %v, want 0 and limit %d", created, err, tiny)
	}

	// The reverse must also hold: an explicit exemption wins over a tiny server cap.
	var unlimited int64
	if err := s.SetAccountQuota(owner, &unlimited); err != nil {
		t.Fatal(err)
	}
	created, err = s.RunAutoSnapshotsWithLimits(0, 1)
	if err != nil || created != 1 {
		t.Fatalf("exempt auto-snapshot = created %d err %v, want 1 nil", created, err)
	}
}

// `aqt usage` must report the cap that actually applies, or an account with an
// override sees a limit it is not subject to.
func TestUsageReportsTheEffectiveQuota(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.srv.cfg.QuotaBytes = 1 << 30
	token, _ := h.signup("usage@example.com", "pw-usage-quota")
	owner, _ := h.store.OwnerByToken(token)

	override := int64(4096)
	if err := h.store.SetAccountQuota(owner, &override); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	var out api.UsageResponse
	if code := h.do(http.MethodGet, "/v1/account/usage", token, nil, &out); code != http.StatusOK {
		t.Fatalf("usage: status %d", code)
	}
	if out.QuotaBytes != override {
		t.Fatalf("quotaBytes = %d, want the per-account %d", out.QuotaBytes, override)
	}
}

// Deletion must remove every row and every file, or a "deleted" account leaves
// real ciphertext behind on a server whose whole premise is that it holds only
// ciphertext it cannot read.
func TestDeleteAccountErasesRowsAndFiles(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "gone@example.com")
	other := s.mustAccount(t, "stays@example.com")
	if _, _, err := s.CreateChallenge("gone@example.com"); err != nil {
		t.Fatalf("create pending challenge: %v", err)
	}

	packID, data, ids := packOf("erasure chunk one", "erasure chunk two")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatalf("put pack: %v", err)
	}
	resID := s.rootResource(t, owner, ids)
	otherRes := s.rootResource(t, other, nil)

	before, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if before.StorageBytes == 0 || before.Objects == 0 {
		t.Fatalf("test setup stored nothing: %+v", before)
	}

	s.suspended.put(owner, true)
	deleted, err := s.DeleteAccount(owner)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted.Email != "gone@example.com" {
		t.Errorf("receipt email = %q", deleted.Email)
	}
	if deleted.Resources == 0 || deleted.Objects == 0 {
		t.Errorf("receipt undercounts what was erased: %+v", deleted)
	}
	if len(deleted.FileErrors) != 0 {
		t.Errorf("file removal errors: %v", deleted.FileErrors)
	}
	if _, cached := s.suspended.get(owner); cached {
		t.Error("deletion retained the owner's suspension cache entry")
	}

	if _, err := s.AdminAccountByRef("gone@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("account still resolves after deletion: %v", err)
	}
	if _, err := s.GetResource(resID, owner); !errors.Is(err, ErrNotFound) {
		t.Errorf("resource survived deletion: %v", err)
	}
	if left := countFiles(t, filepath.Join(s.packsDir, owner)); left != 0 {
		t.Errorf("%d pack file(s) left on disk", left)
	}
	var challenges int
	if err := s.db.QueryRow(`SELECT count(*) FROM challenges WHERE email = ?`, "gone@example.com").Scan(&challenges); err != nil {
		t.Fatal(err)
	}
	if challenges != 0 {
		t.Errorf("%d pending authentication challenge(s) retained the deleted email", challenges)
	}

	// A request authenticated just before deletion can reach the store afterwards.
	// The transaction-time account check must keep it from recreating ownerless rows.
	lateID, latePack, _ := packOf("late upload")
	if _, err := s.PutPack(owner, lateID, latePack, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-delete pack upload = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(s.packPath(owner, lateID)); !os.IsNotExist(err) {
		t.Fatalf("post-delete pack file survived: %v", err)
	}

	// A failed re-PUT must not remove a file that existed before this invocation.
	if err := s.writePack(owner, lateID, latePack); err != nil {
		t.Fatalf("stage pre-existing pack: %v", err)
	}
	if _, err := s.PutPack(owner, lateID, latePack, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-PUT after deletion = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(s.packPath(owner, lateID)); err != nil {
		t.Fatalf("pre-existing pack was removed after failed re-PUT: %v", err)
	}

	// The neighbouring account must be untouched.
	if _, err := s.GetResource(otherRes, other); err != nil {
		t.Errorf("deleting one account disturbed another: %v", err)
	}
}

func TestDeleteAccountIsNotFoundForUnknownOwner(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if _, err := s.DeleteAccount("no-such-handle"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete unknown = %v, want ErrNotFound", err)
	}
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return n
}
