// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// A grantee handle is deliberately unvalidated (a decoy handle must be
// indistinguishable from a real one), so a cursor part can contain the separator
// itself. Escaping must survive that rather than splitting into an extra field.
func TestCursorPartsSurviveSeparatorBytes(t *testing.T) {
	t.Parallel()
	for _, parts := range [][]string{
		{"1700000000", "handle\x1fwith-sep"},
		{"1700000000", "handle\x1ewith-esc"},
		{"1700000000", "\x1e\x1f\x1e\x1fboth"},
		{"", ""},
	} {
		got, err := decodeCursor(encodeCursor(parts...), len(parts))
		if err != nil {
			t.Fatalf("decodeCursor(encodeCursor(%q)) = %v", parts, err)
		}
		if len(got) != len(parts) {
			t.Fatalf("round trip of %q gave %d parts, want %d", parts, len(got), len(parts))
		}
		for i := range parts {
			if got[i] != parts[i] {
				t.Fatalf("part %d round-tripped to %q, want %q", i, got[i], parts[i])
			}
		}
	}
}
