package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// scrape renders the harness server's metrics endpoint as text exposition format.
func (h *harness) scrape() string {
	h.t.Helper()
	rec := httptest.NewRecorder()
	h.srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		h.t.Fatalf("metrics scrape: status %d", rec.Code)
	}
	return rec.Body.String()
}

func wantMetric(t *testing.T, body, line string) {
	t.Helper()
	if !strings.Contains(body, line) {
		t.Fatalf("metrics output missing %q", line)
	}
}

func TestMetricsNotOnAPIRouter(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if rec := h.get("/metrics"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics on the API router = %d, want 404 (metrics belong to the operator listener)", rec.Code)
	}
}

func TestMetricsRequestCountersAndAccountGauges(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("metrics@example.com", "passphrase for metrics")
	packID, pack, _ := packOf("metrics object one", "metrics object two")
	if rec := h.raw(http.MethodPut, "/v1/packs/"+packID, token,
		map[string]string{"Content-Type": "application/octet-stream"}, pack); rec.Code != http.StatusOK {
		t.Fatalf("put pack: %d", rec.Code)
	}
	// An unmatched path must not mint a per-path label.
	if rec := h.get("/no/such/route"); rec.Code != http.StatusNotFound {
		t.Fatalf("unmatched path: %d", rec.Code)
	}
	var gc api.GCResponse
	if code := h.do(http.MethodPost, "/v1/gc", token, struct{}{}, &gc); code != http.StatusOK {
		t.Fatalf("gc: %d", code)
	}

	owner, _, err := h.store.AuthByToken(token)
	if err != nil {
		t.Fatalf("resolve owner: %v", err)
	}
	usage, err := h.store.AccountUsage(owner)
	if err != nil {
		t.Fatal(err)
	}
	body := h.scrape()
	wantMetric(t, body, `aqt_http_requests_total{method="POST",route="/v1/account",status="201"} 1`)
	wantMetric(t, body, `aqt_http_requests_total{method="PUT",route="/v1/packs/:id",status="200"} 1`)
	wantMetric(t, body, `aqt_http_requests_total{method="GET",route="unmatched",status="404"} 1`)
	wantMetric(t, body, fmt.Sprintf("aqt_pack_bytes_received_total %d", len(pack)))
	wantMetric(t, body, `aqt_gc_runs_total{trigger="client"} 1`)
	wantMetric(t, body, "aqt_accounts 1")
	wantMetric(t, body, fmt.Sprintf(`aqt_account_storage_bytes{owner="%s"} %d`, owner, usage.StorageBytes))
	wantMetric(t, body, fmt.Sprintf(`aqt_account_objects{owner="%s"} 2`, owner))
	wantMetric(t, body, fmt.Sprintf(`aqt_account_devices{owner="%s"} 1`, owner))
}

func TestMetricsPackBytesServed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("served@example.com", "passphrase for served bytes")
	packID, pack, _ := packOf("served object payload")
	if rec := h.raw(http.MethodPut, "/v1/packs/"+packID, token,
		map[string]string{"Content-Type": "application/octet-stream"}, pack); rec.Code != http.StatusOK {
		t.Fatalf("put pack: %d", rec.Code)
	}
	rec := h.raw(http.MethodGet, "/v1/packs/"+packID, token, map[string]string{"Range": "bytes=0-9"}, nil)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("range get: %d", rec.Code)
	}
	wantMetric(t, h.scrape(), "aqt_pack_bytes_served_total 10")
}

func TestAccountUsageEndpoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("usage@example.com", "passphrase for usage")
	packID, pack, _ := packOf("usage object one", "usage object two", "usage object three")
	if rec := h.raw(http.MethodPut, "/v1/packs/"+packID, token,
		map[string]string{"Content-Type": "application/octet-stream"}, pack); rec.Code != http.StatusOK {
		t.Fatalf("put pack: %d", rec.Code)
	}

	var u api.UsageResponse
	if code := h.do(http.MethodGet, "/v1/account/usage", token, nil, &u); code != http.StatusOK {
		t.Fatalf("usage: %d", code)
	}
	if u.StorageBytes <= int64(len(pack)) {
		t.Fatalf("storageBytes = %d, want physical usage above pack bytes %d", u.StorageBytes, len(pack))
	}
	if u.Packs != 1 || u.Objects != 3 || u.Devices != 1 {
		t.Fatalf("counts = packs %d objects %d devices %d, want 1/3/1", u.Packs, u.Objects, u.Devices)
	}
	if u.Resources != 0 || u.Snapshots != 0 {
		t.Fatalf("resources/snapshots = %d/%d, want 0/0", u.Resources, u.Snapshots)
	}

	if code := h.do(http.MethodGet, "/v1/account/usage", "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated usage = %d, want 401", code)
	}
}

func TestAccountUsageAllPerOwnerIsolation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	tokenA, _ := h.signup("a@example.com", "passphrase for owner a")
	tokenB, _ := h.signup("b@example.com", "passphrase for owner b")
	packID, pack, _ := packOf("owner a's only object")
	if rec := h.raw(http.MethodPut, "/v1/packs/"+packID, tokenA,
		map[string]string{"Content-Type": "application/octet-stream"}, pack); rec.Code != http.StatusOK {
		t.Fatalf("put pack: %d", rec.Code)
	}

	ownerA, _, err := h.store.AuthByToken(tokenA)
	if err != nil {
		t.Fatal(err)
	}
	ownerB, _, err := h.store.AuthByToken(tokenB)
	if err != nil {
		t.Fatal(err)
	}
	usages, err := h.store.AccountUsageAll()
	if err != nil {
		t.Fatal(err)
	}
	byOwner := map[string]AccountUsage{}
	for _, u := range usages {
		byOwner[u.Owner] = u
	}
	if len(byOwner) != 2 {
		t.Fatalf("accounts = %d, want 2", len(byOwner))
	}
	if got := byOwner[ownerA].StorageBytes; got <= byOwner[ownerB].StorageBytes {
		t.Fatalf("owner a storage = %d, want above owner b baseline %d", got, byOwner[ownerB].StorageBytes)
	}
	if got := byOwner[ownerB]; got.Objects != 0 || got.Packs != 0 || got.Resources != 0 || got.Snapshots != 0 {
		t.Fatalf("owner b content usage = %+v, want no content rows", got)
	}
}
