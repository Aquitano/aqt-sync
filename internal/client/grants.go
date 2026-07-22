package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aquitano/aqt-sync/internal/api"
)

// AccountKeys looks up a grant target's published keys by email. Unknown emails
// get a deterministic decoy from the server, so a lookup never confirms account
// existence; the caller verifies the enc-key self-signature and TOFU-pins the
// result before wrapping anything to it.
func (c *Client) AccountKeys(email string) (api.AccountKeysResponse, error) {
	var out api.AccountKeysResponse
	err := c.do(http.MethodGet, "/v1/account/keys?email="+url.QueryEscape(email), nil, &out)
	return out, err
}

// PublishEncKey uploads the account's X25519 encryption key and its identity
// self-signature — the lazy backfill for accounts created before grants existed.
func (c *Client) PublishEncKey(req api.PublishEncKeyRequest) error {
	return c.do(http.MethodPut, "/v1/account/enc-key", req, nil)
}

// CreateGrant stores a client-sealed grant wrap on a resource the caller owns.
// Re-granting an existing grantee replaces the wrap.
func (c *Client) CreateGrant(resourceID string, req api.CreateGrantRequest) error {
	if req.ExpectedVersion <= 0 {
		current, err := c.GetResource(resourceID)
		if err != nil {
			return err
		}
		req.ExpectedVersion = current.Version
	}
	return mutationOutcome("create grant", c.do(http.MethodPost, "/v1/resources/"+url.PathEscape(resourceID)+"/grants", req, nil))
}

// ListGrants lists a resource's grants (owner only), following pagination
// transparently.
func (c *Client) ListGrants(resourceID string) ([]api.GrantEntry, error) {
	base := "/v1/resources/" + url.PathEscape(resourceID) + "/grants"
	var all []api.GrantEntry
	cursor, pages := "", 0
	for {
		var out api.ListGrantsResponse
		if err := c.do(http.MethodGet, withCursor(base, cursor), nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Grants...)
		more, err := nextPage(&cursor, out.NextCursor, &pages)
		if err != nil {
			return nil, err
		}
		if !more {
			return all, nil
		}
	}
}

// RevokeGrant deletes one grant from a resource the caller owns.
func (c *Client) RevokeGrant(resourceID, granteeHandle string) error {
	version, err := c.versionToPin(resourceID)
	if err != nil {
		return err
	}
	path := "/v1/resources/" + url.PathEscape(resourceID) + "/grants/" + url.PathEscape(granteeHandle)
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("If-Match", strconv.Itoa(version))
	_, _, err = c.send(req, path)
	return mutationOutcome("revoke grant", err)
}

// ListShares lists the caller's incoming grants, following pagination transparently.
func (c *Client) ListShares() ([]api.ShareItem, error) {
	var all []api.ShareItem
	cursor, pages := "", 0
	for {
		var out api.ListSharesResponse
		if err := c.do(http.MethodGet, withCursor("/v1/shares", cursor), nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Shares...)
		more, err := nextPage(&cursor, out.NextCursor, &pages)
		if err != nil {
			return nil, err
		}
		if !more {
			return all, nil
		}
	}
}

// ResourceObjects is the authenticated counterpart of PublicObjects: exact object
// slices of a resource the caller owns or holds a grant on. Same positional
// framing and per-frame cap.
func (c *Client) ResourceObjects(resourceID string, ids []string) ([][]byte, error) {
	body, err := json.Marshal(api.PublicObjectsRequest{IDs: ids})
	if err != nil {
		return nil, err
	}
	path := "/v1/resources/" + url.PathEscape(resourceID) + "/objects"
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", api.ObjectFramesMediaType)
	_, data, err := c.send(req, path)
	if err != nil {
		return nil, err
	}
	return parsePublicFrames(data, len(ids))
}
