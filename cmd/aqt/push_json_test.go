package main

import (
	"encoding/json"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

func TestBuildPushJSON(t *testing.T) {
	tests := []struct {
		name string
		in   pushJSON
		want map[string]any
	}{
		{
			name: "private without name omits url and name",
			in:   buildPushJSON("abc123", "aqt://abc123", "", 1024, api.Private),
			want: map[string]any{
				"id":         "abc123",
				"ref":        "aqt://abc123",
				"bytes":      float64(1024),
				"visibility": "private",
			},
		},
		{
			name: "private with name keeps name, still no url",
			in:   buildPushJSON("abc123", "aqt://abc123", "notes.txt", 1024, api.Private),
			want: map[string]any{
				"id":         "abc123",
				"ref":        "aqt://abc123",
				"name":       "notes.txt",
				"bytes":      float64(1024),
				"visibility": "private",
			},
		},
		{
			name: "public includes the https url and aqt ref",
			in:   buildPushJSON("xyz789", "https://srv.example/x/xyz789#frag", "pic.png", 2048, api.Public),
			want: map[string]any{
				"id":         "xyz789",
				"ref":        "aqt://xyz789",
				"url":        "https://srv.example/x/xyz789#frag",
				"name":       "pic.png",
				"bytes":      float64(2048),
				"visibility": "public",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("key set mismatch: got %v want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s: got %v want %v", k, got[k], v)
				}
			}
		})
	}
}
