package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
)

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"7d", 168 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"1.5d", 36 * time.Hour, false},
		{"", 0, true},
		{"d", 0, true},
		{"nonsense", 0, true},
		{"7x", 0, true},
	}
	for _, c := range cases {
		got, err := parseDuration(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseDuration(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDuration(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestResolveLinkPolicy(t *testing.T) {
	// --burn is shorthand for --max-reads 1.
	if p, err := resolveLinkPolicy("", 0, true); err != nil || p.maxReads != 1 {
		t.Fatalf("burn: p=%+v err=%v", p, err)
	}
	// --burn and --max-reads together conflict.
	if _, err := resolveLinkPolicy("", 3, true); err == nil {
		t.Fatal("burn + max-reads should conflict")
	}
	// A negative read cap is rejected.
	if _, err := resolveLinkPolicy("", -1, false); err == nil {
		t.Fatal("negative max-reads should error")
	}
	// A duration is parsed into seconds.
	p, err := resolveLinkPolicy("1h", 0, false)
	if err != nil || p.expireSeconds != 3600 {
		t.Fatalf("expire: p=%+v err=%v", p, err)
	}
	// An empty policy is not "requested".
	if p, _ := resolveLinkPolicy("", 0, false); p.requested() {
		t.Fatal("empty policy should not be requested")
	}
}

// The fail-closed check accepts a well-formed echo and rejects a missing one (an old
// server that ignored the policy fields).
func TestVerifyPolicyEcho(t *testing.T) {
	now := time.Now().Unix()
	burn := linkPolicy{maxReads: 1}
	if err := verifyPolicyEcho(burn, api.PutResourceResponse{MaxReads: 1}); err != nil {
		t.Fatalf("valid burn echo rejected: %v", err)
	}
	if err := verifyPolicyEcho(burn, api.PutResourceResponse{}); !errors.Is(err, errNoLifecycle) {
		t.Fatalf("missing burn echo: got %v, want errNoLifecycle", err)
	}
	expire := linkPolicy{expireSeconds: 3600}
	if err := verifyPolicyEcho(expire, api.PutResourceResponse{ExpiresAt: now + 3600}); err != nil {
		t.Fatalf("valid expiry echo rejected: %v", err)
	}
	if err := verifyPolicyEcho(expire, api.PutResourceResponse{}); !errors.Is(err, errNoLifecycle) {
		t.Fatalf("missing expiry echo: got %v, want errNoLifecycle", err)
	}
	// A mismatched read cap is a protocol error.
	if err := verifyPolicyEcho(burn, api.PutResourceResponse{MaxReads: 9}); err == nil {
		t.Fatal("mismatched maxReads should error")
	}
}

// confirmPolicy fails closed and deletes the just-created resource when the server does
// not echo the requested policy (a stubbed old server).
func TestConfirmPolicyDeletesOnMissingEcho(t *testing.T) {
	var deleted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cl, err := client.New(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	// An old server echoes {id, version} with no policy fields.
	resp := api.PutResourceResponse{ID: "abc123", Version: 1}
	err = confirmPolicy(cl, resp, linkPolicy{maxReads: 1})
	if !errors.Is(err, errNoLifecycle) {
		t.Fatalf("confirmPolicy err = %v, want errNoLifecycle", err)
	}
	if deleted == "" {
		t.Fatal("confirmPolicy should have deleted the unenforced resource")
	}
}
