package main

import (
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

func TestGitRemoteItems(t *testing.T) {
	items := []api.ResourceListItem{
		{ID: "folder"},
		{ID: "repo", CompactAt: 64},
		{ID: "invalid", CompactAt: -1},
	}
	got := gitRemoteItems(items)
	if len(got) != 1 || got[0].ID != "repo" {
		t.Fatalf("gitRemoteItems = %+v, want repo only", got)
	}
}
