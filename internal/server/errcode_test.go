// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
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
