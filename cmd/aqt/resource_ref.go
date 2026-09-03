// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// resolveOwnedResourceID accepts a bare id or an aqt:// ref, plus a tracked local path
// or an exact, uniquely matching decrypted resource name.
func resolveOwnedResourceID(cl *client.Client, mk crypto.MasterKey, ref string) (string, error) {
	if id, ok, err := trackedResourceID(ref); ok || err != nil {
		return id, err
	}
	items, err := cl.ListResources()
	if err != nil {
		return "", err
	}
	return resolveOwnedResourceIDFromItems(items, mk, ref)
}

func resolveOwnedResourceIDFromItems(items []api.ResourceListItem, mk crypto.MasterKey, ref string) (string, error) {
	id, _, _ := parseRef(ref)
	for _, it := range items {
		if it.ID == id {
			return it.ID, nil
		}
	}
	var matches []api.ResourceListItem
	for _, it := range items {
		if meta, ok := openMetadata(it, mk); ok && meta.Name == ref {
			matches = append(matches, it)
		}
	}
	switch len(matches) {
	case 0:
		// Nothing matched by name: hand the id back so the server answers the 404 for an
		// id or URL that does not belong to this account.
		return id, nil
	case 1:
		return matches[0].ID, nil
	default:
		ids := make([]string, len(matches))
		for i, it := range matches {
			ids[i] = it.ID
		}
		return "", fmt.Errorf("resource name %q is ambiguous (%s); use an id", ref, strings.Join(ids, ", "))
	}
}

func resolveOwnedResourceIDWithProfile(cl *client.Client, prof *identity.Profile, ref string) (string, error) {
	mk, err := unlockMaster(prof)
	if err != nil {
		return "", err
	}
	defer mk.Wipe()
	return resolveOwnedResourceID(cl, mk, ref)
}

// trackedResourceID recognizes local paths inside a tracked folder. URL-like refs
// are never treated as paths, even if a strangely named local file matches them.
func trackedResourceID(ref string) (id string, ok bool, err error) {
	if strings.Contains(ref, "://") || strings.Contains(ref, "#") {
		return "", false, nil
	}
	probe := ref
	if probe == "" {
		return "", false, nil
	}
	fi, statErr := os.Stat(probe)
	looksLikePath := statErr == nil || filepath.IsAbs(probe) || probe == "." || probe == ".." || strings.ContainsAny(probe, `/\\`)
	if !looksLikePath {
		return "", false, nil
	}
	if statErr == nil && !fi.IsDir() {
		probe = filepath.Dir(probe)
	}
	root, rootErr := trackedRoot(probe)
	if rootErr != nil {
		return "", false, nil
	}
	abs, absErr := filepath.Abs(ref)
	if absErr != nil {
		return "", false, nil
	}
	// Only the tracked root itself names the folder resource. A file or subdirectory
	// inside it is not a resource of its own, and silently widening it to the whole
	// folder would let `aqt rm notes.txt` delete the entire folder resource.
	if abs != root {
		return "", true, fmt.Errorf("%s is inside the tracked folder %s but is not a resource itself; pass %s to act on the whole folder, or use a resource id", ref, root, root)
	}
	st, err := folderstate.LoadState(root)
	if err != nil {
		return "", true, fmt.Errorf("read folder state: %w", err)
	}
	if st.ID == "" {
		return "", true, fmt.Errorf("%s has no synced resource yet; run `aqt sync` first", root)
	}
	return st.ID, true, nil
}

// resourceLabel is the human-readable form used by destructive confirmation
// prompts: the decrypted name with the id, or just the id when the resource is
// unknown or its metadata cannot be opened.
func resourceLabel(items []api.ResourceListItem, mk crypto.MasterKey, id string) string {
	for _, it := range items {
		if it.ID != id {
			continue
		}
		if meta, ok := openMetadata(it, mk); ok && meta.Name != "" {
			return fmt.Sprintf("%s (%s)", meta.Name, id)
		}
		break
	}
	return id
}
