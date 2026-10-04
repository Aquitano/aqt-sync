// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// TestStatusErrCodeBuckets pins the status→bucket mapping abort relies on, including
// the class fallbacks that keep an unlisted status from shipping without a code.
func TestStatusErrCodeBuckets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, api.ErrCodeInvalidRequest},
		{http.StatusUnauthorized, api.ErrCodeUnauthorized},
		{http.StatusForbidden, api.ErrCodeForbidden},
		{http.StatusNotAcceptable, api.ErrCodeNotAcceptable},
		{http.StatusRequestEntityTooLarge, api.ErrCodePayloadTooLarge},
		{http.StatusUnsupportedMediaType, api.ErrCodeUnsupportedMedia},
		{http.StatusInternalServerError, api.ErrCodeInternal},
		{http.StatusBadGateway, api.ErrCodeInternal},
		{http.StatusTeapot, api.ErrCodeInvalidRequest},
	}
	for _, tc := range cases {
		if got := statusErrCode(tc.status); got != tc.want {
			t.Errorf("statusErrCode(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

// TestErrorResponsesCarryCodes drives representative failing requests through the
// router and asserts the response carries the promised machine-readable code: the
// bucket codes attached by abort and the condition codes on the auth handlers.
func TestErrorResponsesCarryCodes(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("codes@example.com", "passphrase for codes")

	var challenge api.ChallengeResponse
	if code := h.do(http.MethodPost, "/v1/auth/challenge", "", api.ChallengeRequest{Email: "codes@example.com"}, &challenge); code != http.StatusOK {
		t.Fatalf("challenge: got status %d", code)
	}

	cases := []struct {
		name       string
		run        func() (int, api.ErrorResponse)
		wantStatus int
		wantCode   string
	}{
		{
			name: "missing token",
			run: func() (int, api.ErrorResponse) {
				var e api.ErrorResponse
				return h.do(http.MethodGet, "/v1/devices", "", nil, &e), e
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   api.ErrCodeUnauthorized,
		},
		{
			name: "malformed body",
			run: func() (int, api.ErrorResponse) {
				rec := h.raw(http.MethodPost, "/v1/account", "", nil, []byte(`{"email":`))
				var e api.ErrorResponse
				_ = json.Unmarshal(rec.Body.Bytes(), &e)
				return rec.Code, e
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   api.ErrCodeInvalidRequest,
		},
		{
			name: "unknown challenge",
			run: func() (int, api.ErrorResponse) {
				var e api.ErrorResponse
				return h.do(http.MethodPost, "/v1/devices", "", api.AttachDeviceRequest{
					Email:       "codes@example.com",
					ChallengeID: "no-such-challenge",
				}, &e), e
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   api.ErrCodeInvalidChallenge,
		},
		{
			name: "bad credentials",
			run: func() (int, api.ErrorResponse) {
				var e api.ErrorResponse
				return h.do(http.MethodPost, "/v1/devices", "", api.AttachDeviceRequest{
					Email:        "codes@example.com",
					ChallengeID:  challenge.ChallengeID,
					Signature:    make([]byte, ed25519.SignatureSize),
					AuthVerifier: []byte("not the verifier"),
				}, &e), e
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   api.ErrCodeInvalidCredentials,
		},
		{
			name: "wrong passphrase proof",
			run: func() (int, api.ErrorResponse) {
				var e api.ErrorResponse
				return h.do(http.MethodPut, "/v1/account/passphrase", token, api.PassphraseChangeRequest{
					WrappedRoot:     crypto.SealedBlob{Nonce: []byte("n"), Ciphertext: []byte("c")},
					OldAuthVerifier: []byte("not the verifier"),
					NewAuthVerifier: []byte("new verifier"),
					ExpectedEpoch:   1,
				}, &e), e
			},
			wantStatus: http.StatusForbidden,
			wantCode:   api.ErrCodeProofMismatch,
		},
	}
	for _, tc := range cases {
		status, e := tc.run()
		if status != tc.wantStatus || e.Code != tc.wantCode {
			t.Errorf("%s: got status %d code %q, want %d %q (error: %s)", tc.name, status, e.Code, tc.wantStatus, tc.wantCode, e.Error)
		}
	}
}

// TestUnmatchedPathCarriesNotFoundCode covers requests no route matches, such as an
// id containing a slash or an empty trailing id: they get the same JSON not_found as
// a missing resource instead of gin's plain-text page.
func TestUnmatchedPathCarriesNotFoundCode(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, path := range []string{"/v1/resources/a%2Fb", "/v1/snapshots/", "/v1/no-such-route"} {
		var e api.ErrorResponse
		if code := h.do(http.MethodGet, path, "", nil, &e); code != http.StatusNotFound || e.Code != api.ErrCodeNotFound {
			t.Errorf("GET %s: got %d %q, want 404 %q", path, code, e.Code, api.ErrCodeNotFound)
		}
	}
}

// The share paths refresh a resource's chunk refs just as a manifest PUT does, so refs
// naming objects a prune already removed are the same client-side condition and get
// the same missing_chunks code, not a 500 a client would retry unchanged.
func TestShareWithPrunedRefsIsMissingChunks(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("pruned-refs@example.com", "a passphrase here")
	res, code := h.putSized(token, mk, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("create = %d, want 201", code)
	}
	pruned := []string{strings.Repeat("ab", 32)}
	for _, tc := range []struct {
		path string
		body any
	}{
		{"/v1/resources/" + res.ID + "/grants", api.CreateGrantRequest{GranteeHandle: "grantee", WrappedKey: []byte("wrap"), ChunkRefs: pruned}},
		{"/v1/resources/" + res.ID + "/visibility", api.SetVisibilityRequest{Visibility: api.Public, ChunkRefs: pruned}},
	} {
		var e api.ErrorResponse
		if code := h.do(http.MethodPost, tc.path, token, tc.body, &e); code != http.StatusBadRequest || e.Code != api.ErrCodeMissingChunks {
			t.Errorf("POST %s with pruned refs: got %d %q, want 400 %q", tc.path, code, e.Code, api.ErrCodeMissingChunks)
		}
	}
}

// TestInviteRequiredCode covers signup against an invite-mode server: the refusal
// carries invite_required so a client can prompt for a token instead of giving up.
func TestInviteRequiredCode(t *testing.T) {
	t.Parallel()
	h := newHarnessCfg(t, Config{Registration: RegistrationInvite, InviteTokens: []string{"secret-invite"}})
	var e api.ErrorResponse
	code := h.do(http.MethodPost, "/v1/account", "", createReq(t, "nobody@example.com", "pass"), &e)
	if code != http.StatusForbidden || e.Code != api.ErrCodeInviteRequired {
		t.Fatalf("got status %d code %q, want %d %q", code, e.Code, http.StatusForbidden, api.ErrCodeInviteRequired)
	}
}
