package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

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
	return c.do(http.MethodPost, "/v1/resources/"+url.PathEscape(resourceID)+"/grants", req, nil)
}

// ListGrants lists a resource's grants (owner only).
func (c *Client) ListGrants(resourceID string) ([]api.GrantEntry, error) {
	var out api.ListGrantsResponse
	err := c.do(http.MethodGet, "/v1/resources/"+url.PathEscape(resourceID)+"/grants", nil, &out)
	return out.Grants, err
}

// RevokeGrant deletes one grant from a resource the caller owns.
func (c *Client) RevokeGrant(resourceID, granteeHandle string) error {
	return c.do(http.MethodDelete,
		"/v1/resources/"+url.PathEscape(resourceID)+"/grants/"+url.PathEscape(granteeHandle), nil, nil)
}

// ListShares lists the caller's incoming grants.
func (c *Client) ListShares() ([]api.ShareItem, error) {
	var out api.ListSharesResponse
	err := c.do(http.MethodGet, "/v1/shares", nil, &out)
	return out.Shares, err
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
	req.Header.Set("Accept", "application/octet-stream")
	_, data, err := c.send(req, path)
	if err != nil {
		return nil, err
	}
	return parsePublicFrames(data, len(ids))
}
