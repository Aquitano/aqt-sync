// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// bindCreated re-seals a just-created resource's body and metadata to the id the
// server assigned, and writes them back as the resource's second version. A create
// cannot seal bound itself — the id exists only once the create returns — and reads
// open bound-only, so this write is what makes the resource readable at all.
//
// create is the request that produced resp; it is reused so visibility, wrapped key,
// chunk refs, min_client and compact-at carry over unchanged. sealBlob re-seals the
// body under the new id, since the root format differs per resource kind.
func bindCreated(cl *client.Client, create api.PutResourceRequest, resp api.PutResourceResponse, ck crypto.ContentKey, metaJSON []byte, sealBlob func(id string) (crypto.SealedBlob, error)) (api.PutResourceResponse, error) {
	bound, err := bindResource(create, resp, ck, metaJSON, sealBlob)
	if err == nil {
		var out api.PutResourceResponse
		if out, err = cl.PutResource(bound); err == nil {
			return out, nil
		}
	}
	// A bind write that commits and then loses its response is indistinguishable from
	// one that never happened, so the cleanup asks the server what it holds rather
	// than trusting err: a bound record is a readable resource — and, for a public
	// push, a live share link — and must survive the failure that reported it lost.
	stored, cleanupErr := cl.GetResource(resp.ID)
	if cleanupErr == nil {
		if _, openErr := crypto.OpenBound(stored.EncryptedMeta, ck, crypto.AADMeta, resp.ID); openErr == nil {
			return api.PutResourceResponse{ID: stored.ID, Version: stored.Version}, nil
		}
		// The unbound first version opens for nobody and nothing references it yet, so
		// drop it rather than leave the owner an orphan they cannot read. The delete
		// pins the version just read, so a bind landing in between is refused by the
		// server instead of destroying the resource it made readable.
		cleanupErr = cl.DeleteResourceVersion(stored.ID, stored.Version)
	}
	if cleanupErr != nil {
		//nolint:errorlint // secondary cleanup error must not reach exitCode
		return resp, fmt.Errorf("bind resource %s to its id: %w (the unreadable resource could not be removed: %v; `aqt rm %s` deletes it)", resp.ID, err, cleanupErr, resp.ID)
	}
	return resp, fmt.Errorf("bind resource %s to its id: %w", resp.ID, err)
}

func bindResource(create api.PutResourceRequest, resp api.PutResourceResponse, ck crypto.ContentKey, metaJSON []byte, sealBlob func(id string) (crypto.SealedBlob, error)) (api.PutResourceRequest, error) {
	blob, err := sealBlob(resp.ID)
	if err != nil {
		return api.PutResourceRequest{}, err
	}
	meta, err := crypto.SealBound(metaJSON, ck, crypto.AADMeta, resp.ID)
	if err != nil {
		return api.PutResourceRequest{}, err
	}
	bound := create
	bound.ID, bound.ExpectedVersion = resp.ID, resp.Version
	bound.Blob, bound.EncryptedMeta = blob, meta
	// The create already set the link's lifecycle policy and the server preserves it
	// for a write that carries none; re-sending it would restart the read counter.
	bound.ExpireSeconds, bound.MaxReads, bound.OnExpiry = 0, 0, ""
	// The idempotency key covers the create only: replaying it here would answer with
	// the create's own recorded response instead of performing the bind.
	bound.IdempotencyKey = ""
	return bound, nil
}

// verifiedMetaBound checks that a resource's carried-forward metadata opens under the
// resource id before an update writes it back unchanged. Metadata is sealed bound at
// create, so a blob that does not open is a wrong key or a record the server swapped —
// neither of which a re-seal could repair.
func verifiedMetaBound(meta crypto.SealedBlob, ck crypto.ContentKey, id string) (crypto.SealedBlob, error) {
	if _, err := crypto.OpenBound(meta, ck, crypto.AADMeta, id); err != nil {
		return crypto.SealedBlob{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	return meta, nil
}
