package client

import (
	"net/http"
	"testing"
)

// TestNewRejectsInsecureSchemeWithToken covers the H3 fix: a bearer token must
// never travel over a non-HTTPS URL unless the host is loopback (the documented
// http://localhost dev workflow). An empty token may use any scheme — bootstrap,
// challenge, and public-link pulls carry no credential to leak.
func TestNewRejectsInsecureSchemeWithToken(t *testing.T) {
	cases := []struct {
		name    string
		base    string
		token   string
		wantErr bool
	}{
		{"https with token", "https://api.example.com", "tok", false},
		{"http no token", "http://api.example.com", "", false},
		{"http localhost with token", "http://localhost:8080", "tok", false},
		{"http 127.0.0.1 with token", "http://127.0.0.1:8080", "tok", false},
		{"http ::1 with token", "http://[::1]:8080", "tok", false},
		{"http 0.0.0.0 with token", "http://0.0.0.0:8080", "tok", false},
		{"http non-loopback with token", "http://api.example.com", "tok", true},
		{"https loopback with token", "https://localhost", "tok", false},
		{"invalid url", "://bad", "tok", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := New(c.base, c.token)
			if c.wantErr && err == nil {
				t.Fatalf("New(%q,%q): want error, got nil", c.base, c.token)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("New(%q,%q): want nil, got %v", c.base, c.token, err)
			}
			if cl == nil && err == nil {
				t.Fatalf("New returned nil client and nil error")
			}
		})
	}
}

// TestCheckRedirectDropsAuthOnInsecureTarget covers the redirect half of H3:
// Go's default CheckRedirect forwards Authorization to same-host redirect
// targets, so an https->http downgrade on the same host would leak the token.
// The installed CheckRedirect drops the header on any non-HTTPS, non-loopback
// target and leaves it in place for https and loopback targets.
func TestCheckRedirectDropsAuthOnInsecureTarget(t *testing.T) {
	cl, err := New("https://api.example.com", "tok")
	if err != nil {
		t.Fatal(err)
	}
	check := cl.http.CheckRedirect
	via := []*http.Request{mustReq("https://api.example.com/path")}

	t.Run("http downgrade drops token", func(t *testing.T) {
		req := mustReq("http://other.example.com/path")
		req.Header.Set("Authorization", "Bearer tok")
		if err := check(req, via); err != nil {
			t.Fatalf("CheckRedirect: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization not dropped on http downgrade: %q", got)
		}
	})

	t.Run("https redirect keeps token", func(t *testing.T) {
		req := mustReq("https://api.example.com/elsewhere")
		req.Header.Set("Authorization", "Bearer tok")
		if err := check(req, via); err != nil {
			t.Fatalf("CheckRedirect: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization dropped on https redirect: %q", got)
		}
	})

	t.Run("http loopback redirect keeps token", func(t *testing.T) {
		req := mustReq("http://localhost:8080/path")
		req.Header.Set("Authorization", "Bearer tok")
		if err := check(req, via); err != nil {
			t.Fatalf("CheckRedirect: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization dropped on loopback redirect: %q", got)
		}
	})
}

// TestCheckRedirectKeepsRedirectCap guards against the custom CheckRedirect
// silently dropping Go's default 10-redirect limit: a hostile server that
// redirects to itself would otherwise loop forever (and re-send the bearer
// token on every same-host https hop). The 11th hop must error out.
func TestCheckRedirectKeepsRedirectCap(t *testing.T) {
	cl, err := New("https://api.example.com", "tok")
	if err != nil {
		t.Fatal(err)
	}
	check := cl.http.CheckRedirect
	req := mustReq("https://api.example.com/loop")

	via := make([]*http.Request, 9)
	for i := range via {
		via[i] = mustReq("https://api.example.com/loop")
	}
	if err := check(req, via); err != nil {
		t.Fatalf("CheckRedirect errored at hop 10: %v", err)
	}

	via = append(via, mustReq("https://api.example.com/loop"))
	if err := check(req, via); err == nil {
		t.Fatal("CheckRedirect: want error after 10 redirects, got nil")
	}
}

func mustReq(u string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		panic(err)
	}
	return req
}
