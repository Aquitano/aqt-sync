// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// TestListResourcesPaginationWalksAllPages covers the multi-page walk: every
// resource is returned exactly once, in id order, across bounded pages.
func TestListResourcesPaginationWalksAllPages(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "page@example.com")

	// Empty page: a fresh owner yields no items and no next cursor.
	if items, next, err := s.ListResources(owner, pageParams{limit: 10}); err != nil || len(items) != 0 || next != "" {
		t.Fatalf("empty page: items=%d next=%q err=%v", len(items), next, err)
	}

	const total = 25
	for range total {
		s.rootResource(t, owner, nil)
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, next, err := s.ListResources(owner, pageParams{limit: 10, cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		if len(page) > 10 {
			t.Fatalf("page %d returned %d items, over the limit", pages, len(page))
		}
		for i, it := range page {
			if seen[it.ID] {
				t.Fatalf("duplicate id %s across pages", it.ID)
			}
			seen[it.ID] = true
			if i > 0 && page[i-1].ID >= it.ID {
				t.Fatalf("page %d not ordered by id", pages)
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != total {
		t.Fatalf("saw %d ids, want %d", len(seen), total)
	}
	if pages != 3 { // 10 + 10 + 5
		t.Fatalf("pages = %d, want 3", pages)
	}
}

// TestListResourcesReportsGrantCount covers the per-row grant count the list
// echoes so `share ls` can skip grant fetches: zero for an ungranted resource
// (present, not nil — absent means an older server), the live count for a
// granted one, and the count shrinking on revocation.
func TestListResourcesReportsGrantCount(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "grantcount@example.com")
	plain := s.rootResource(t, owner, nil)
	shared := s.rootResource(t, owner, nil)
	for _, grantee := range []string{"g1", "g2"} {
		if err := s.PutGrant(owner, shared, grantee, []byte("wrap"), nil); err != nil {
			t.Fatalf("put grant %s: %v", grantee, err)
		}
	}

	counts := func() map[string]int {
		items, _, err := s.ListResources(owner, pageParams{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, it := range items {
			got[it.ID] = it.GrantCount
		}
		return got
	}
	if got := counts(); got[plain] != 0 || got[shared] != 2 {
		t.Fatalf("counts = %v, want %s=0 %s=2", got, plain, shared)
	}
	if err := s.DeleteGrant(owner, shared, "g1"); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if got := counts(); got[shared] != 1 {
		t.Fatalf("count after revoke = %d, want 1", got[shared])
	}
}

// TestListResourceGrantsPaginationWalksAllPages covers the grant-list walk:
// every grantee returned exactly once across bounded pages, terminating cursor.
func TestListResourceGrantsPaginationWalksAllPages(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "grantpage@example.com")
	id := s.rootResource(t, owner, nil)
	const total = 5
	for i := range total {
		if err := s.PutGrant(owner, id, fmt.Sprintf("grantee-%d", i), []byte("wrap"), nil); err != nil {
			t.Fatalf("put grant %d: %v", i, err)
		}
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, next, err := s.ListResourceGrants(owner, id, pageParams{limit: 2, cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		if len(page) > 2 {
			t.Fatalf("page %d returned %d grants, over the limit", pages, len(page))
		}
		for _, g := range page {
			if seen[g.GranteeHandle] {
				t.Fatalf("duplicate grantee %s across pages", g.GranteeHandle)
			}
			seen[g.GranteeHandle] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != total || pages != 3 { // 2 + 2 + 1
		t.Fatalf("grantees = %d pages = %d, want %d grantees over 3 pages", len(seen), pages, total)
	}
}

// TestListResourcesExactBoundary covers the boundary case: when the total is an exact
// multiple of the limit, the last full page must not be followed by a phantom empty page.
func TestListResourcesExactBoundary(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "boundary@example.com")
	for range 10 {
		s.rootResource(t, owner, nil)
	}
	items, next, err := s.ListResources(owner, pageParams{limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 10 {
		t.Fatalf("items = %d, want 10", len(items))
	}
	if next != "" {
		t.Fatalf("nextCursor = %q, want empty at an exact boundary", next)
	}
}

// TestListRejectsBadCursor covers cursor validation at the store: a non-decodable
// cursor and a well-formed one with the wrong key shape both return errBadCursor.
func TestListRejectsBadCursor(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "badcursor@example.com")

	if _, _, err := s.ListResources(owner, pageParams{limit: 10, cursor: "@@@not-base64@@@"}); !errors.Is(err, errBadCursor) {
		t.Fatalf("garbage cursor err = %v, want errBadCursor", err)
	}
	// Snapshots expect a two-part cursor; a one-part one is the wrong shape.
	if _, _, err := s.ListSnapshots(owner, "", pageParams{limit: 10, cursor: encodeCursor("just-one")}); !errors.Is(err, errBadCursor) {
		t.Fatalf("wrong-shape cursor err = %v, want errBadCursor", err)
	}
}

// TestListResourcesHTTPPaging covers the wire contract: the response carries the
// items array and a nextCursor a caller feeds back to fetch the rest.
func TestListResourcesHTTPPaging(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("httppage@example.com", "a passphrase for paging")
	owner, err := h.store.OwnerByToken(token)
	if err != nil {
		t.Fatalf("owner by token: %v", err)
	}
	for range 3 {
		h.store.rootResource(t, owner, nil)
	}

	var first api.ListResourcesResponse
	if code := h.do(http.MethodGet, "/v1/resources?limit=2", token, nil, &first); code != http.StatusOK {
		t.Fatalf("first page: status %d", code)
	}
	if len(first.Resources) != 2 || first.NextCursor == "" {
		t.Fatalf("first page: items=%d next=%q, want 2 items and a cursor", len(first.Resources), first.NextCursor)
	}

	var second api.ListResourcesResponse
	if code := h.do(http.MethodGet, "/v1/resources?limit=2&cursor="+url.QueryEscape(first.NextCursor), token, nil, &second); code != http.StatusOK {
		t.Fatalf("second page: status %d", code)
	}
	if len(second.Resources) != 1 || second.NextCursor != "" {
		t.Fatalf("second page: items=%d next=%q, want 1 item and no cursor", len(second.Resources), second.NextCursor)
	}
}

// TestListPageParamValidation covers the 400s: a bad cursor and a non-positive limit
// each carry their stable code.
func TestListPageParamValidation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("pageparams@example.com", "a passphrase for params")

	var e api.ErrorResponse
	if code := h.do(http.MethodGet, "/v1/resources?cursor=@@@", token, nil, &e); code != http.StatusBadRequest {
		t.Fatalf("bad cursor: status %d, want 400", code)
	}
	if e.Code != api.ErrCodeInvalidCursor {
		t.Fatalf("bad cursor code = %q, want %q", e.Code, api.ErrCodeInvalidCursor)
	}

	e = api.ErrorResponse{}
	if code := h.do(http.MethodGet, "/v1/resources?limit=0", token, nil, &e); code != http.StatusBadRequest {
		t.Fatalf("bad limit: status %d, want 400", code)
	}
	if e.Code != api.ErrCodeInvalidLimit {
		t.Fatalf("bad limit code = %q, want %q", e.Code, api.ErrCodeInvalidLimit)
	}
}

// TestChunkEndpointsCapIDCount covers the id-count cap on check/locate: over the cap
// is a 400 with the too_many_ids code, exactly at the cap is accepted.
func TestChunkEndpointsCapIDCount(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("chunkcap@example.com", "a passphrase for chunks")

	ids := make([]string, maxPublicObjectIDs+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i)
	}

	for _, path := range []string{"/v1/chunks/check", "/v1/chunks/locate"} {
		var e api.ErrorResponse
		if code := h.do(http.MethodPost, path, token, api.ChunkCheckRequest{IDs: ids}, &e); code != http.StatusBadRequest {
			t.Fatalf("%s over cap: status %d, want 400", path, code)
		}
		if e.Code != api.ErrCodeTooManyIDs {
			t.Fatalf("%s over cap: code = %q, want %q", path, e.Code, api.ErrCodeTooManyIDs)
		}
		if code := h.do(http.MethodPost, path, token, api.ChunkCheckRequest{IDs: ids[:maxPublicObjectIDs]}, nil); code != http.StatusOK {
			t.Fatalf("%s at cap: status %d, want 200", path, code)
		}
	}
}

// TestRateLimitSetsRetryAfter covers item 27: a 429 carries a Retry-After header of
// whole seconds computed from the limiter's own refill rate.
func TestRateLimitSetsRetryAfter(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	var rec *httptest.ResponseRecorder
	for range unauthBurst + 5 {
		rec = h.get("/v1/account/salt?email=rl@example.com")
		if rec.Code == http.StatusTooManyRequests {
			break
		}
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("never tripped the rate limit; last status %d", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("429 response is missing the Retry-After header")
	}
	secs, err := strconv.Atoi(ra)
	if err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer of seconds", ra)
	}

	// The same limiter result must also ride in the body, so a client behind an
	// intermediary that strips unknown headers still learns how long to wait.
	var body api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if body.Code != api.ErrCodeRateLimited {
		t.Fatalf("429 code = %q, want %q", body.Code, api.ErrCodeRateLimited)
	}
	if body.RetryAfterSeconds != secs {
		t.Fatalf("retryAfterSeconds = %d, Retry-After = %d; both must come from one limiter result",
			body.RetryAfterSeconds, secs)
	}
}
