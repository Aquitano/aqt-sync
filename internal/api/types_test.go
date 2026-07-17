package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestErrorResponseMinClientIsCamelCase pins the wire casing of ErrorResponse.MinClient
// to camelCase, matching every other field (issue #91 item 26 unified the stray
// snake_case min_client). A regression here would silently break the client's 426
// min_client surfacing.
func TestErrorResponseMinClientIsCamelCase(t *testing.T) {
	b, err := json.Marshal(ErrorResponse{Error: "x", Code: ErrCodeUpgradeRequired, MinClient: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"minClient"`) {
		t.Fatalf("ErrorResponse JSON = %s, want a camelCase minClient field", b)
	}
	if strings.Contains(string(b), "min_client") {
		t.Fatalf("ErrorResponse JSON = %s, still carries snake_case min_client", b)
	}
}
