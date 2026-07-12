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
	if p, err := resolveLinkPolicy("", 0, true, api.ExpiryReclaim); err != nil || p.maxReads != 1 {
		t.Fatalf("burn: p=%+v err=%v", p, err)
	}
	// --burn and --max-reads together conflict.
	if _, err := resolveLinkPolicy("", 3, true, api.ExpiryReclaim); err == nil {
		t.Fatal("burn + max-reads should conflict")
	}
	// A negative read cap is rejected.
	if _, err := resolveLinkPolicy("", -1, false, api.ExpiryReclaim); err == nil {
		t.Fatal("negative max-reads should error")
	}
	// A duration is parsed into seconds.
	p, err := resolveLinkPolicy("1h", 0, false, api.ExpiryReclaim)
	if err != nil || p.expireSeconds != 3600 {
		t.Fatalf("expire: p=%+v err=%v", p, err)
	}
	// An empty policy is not "requested".
	if p, _ := resolveLinkPolicy("", 0, false, api.ExpiryReclaim); p.requested() {
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

// A share asks for a link whose expiry only retires the link. A server that would
// instead reclaim the content — an old one, which echoes no action at all, or any server
// answering with `reclaim` — must be refused: honoring it would destroy the resource
// (a synced folder, say) when the link expired.
func TestVerifyPolicyEchoRequiresRetire(t *testing.T) {
	retire := linkPolicy{expireSeconds: 3600, onExpiry: api.ExpiryRetire}
	echo := api.PutResourceResponse{ExpiresAt: time.Now().Unix() + 3600}

	// A lifecycle-capable but pre-retire server echoes the expiry but no action.
	if err := verifyPolicyEcho(retire, echo); !errors.Is(err, errNoRetire) {
		t.Fatalf("pre-retire server (expiry echoed, no onExpiry): got %v, want errNoRetire", err)
	}
	// A server with no lifecycle at all echoes nothing: errNoLifecycle is the accurate
	// message, not errNoRetire — the retire check must not preempt the existence check.
	if err := verifyPolicyEcho(retire, api.PutResourceResponse{}); !errors.Is(err, errNoLifecycle) {
		t.Fatalf("no-lifecycle server against a retire policy: got %v, want errNoLifecycle", err)
	}
	reclaimEcho := echo
	reclaimEcho.OnExpiry = api.ExpiryReclaim
	if err := verifyPolicyEcho(retire, reclaimEcho); !errors.Is(err, errNoRetire) {
		t.Fatalf("server answering reclaim: got %v, want errNoRetire", err)
	}
	retireEcho := echo
	retireEcho.OnExpiry = api.ExpiryRetire
	if err := verifyPolicyEcho(retire, retireEcho); err != nil {
		t.Fatalf("valid retire echo rejected: %v", err)
	}
	// A push asks for reclaim, and an old server's silence means exactly that.
	reclaim := linkPolicy{expireSeconds: 3600, onExpiry: api.ExpiryReclaim}
	if err := verifyPolicyEcho(reclaim, echo); err != nil {
		t.Fatalf("reclaim policy against a silent server rejected: %v", err)
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
