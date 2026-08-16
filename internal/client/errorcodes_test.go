// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// TestErrorCodesMapToSentinels covers item 26: the client maps a response by its
// machine-readable code, so conditions the HTTP status alone cannot express
// (device_limit vs a plain 403, bad_pack vs a plain 400) still reach a distinct
// sentinel a caller can branch on.
func TestErrorCodesMapToSentinels(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{"device limit", http.StatusForbidden, api.ErrCodeDeviceLimit, ErrDeviceLimit},
		{"bad pack", http.StatusBadRequest, api.ErrCodeBadPack, ErrBadPack},
		{"resource too large", http.StatusBadRequest, api.ErrCodeResourceTooLarge, ErrResourceTooLarge},
		{"quota", http.StatusInsufficientStorage, api.ErrCodeQuotaExceeded, ErrQuotaExceeded},
		{"version conflict", http.StatusConflict, api.ErrCodeVersionConflict, ErrConflict},
		{"gone", http.StatusGone, api.ErrCodeGone, ErrGone},
		{"not found", http.StatusNotFound, api.ErrCodeNotFound, ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if err := json.NewEncoder(w).Encode(api.ErrorResponse{Error: "boom", Code: tc.code}); err != nil {
					t.Errorf("encode: %v", err)
				}
			}))
			defer srv.Close()

			cl, err := New(srv.URL, "tok")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := cl.GetResource("id"); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}
