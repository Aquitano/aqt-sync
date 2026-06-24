// Package client is a thin HTTP client for the aqt API. It carries the bearer
// token and (de)serializes the api wire types; it performs no cryptography.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// ErrNotFound maps a 404 so callers can distinguish "no such account/resource".
var ErrNotFound = errors.New("not found")

// ErrConflict maps a 409 so callers can distinguish a version conflict (the
// resource moved under them) and retry against the new state.
var ErrConflict = errors.New("conflict")

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) CreateAccount(req api.CreateAccountRequest) (api.AuthResponse, error) {
	var r api.AuthResponse
	err := c.do(http.MethodPost, "/v1/account", req, &r)
	return r, err
}

// Challenge requests a one-time nonce to sign when attaching a device.
func (c *Client) Challenge(email string) (api.ChallengeResponse, error) {
	var r api.ChallengeResponse
	err := c.do(http.MethodPost, "/v1/auth/challenge", api.ChallengeRequest{Email: email}, &r)
	return r, err
}

func (c *Client) AttachDevice(req api.AttachDeviceRequest) (api.AuthResponse, error) {
	var r api.AuthResponse
	err := c.do(http.MethodPost, "/v1/devices", req, &r)
	return r, err
}

// ListDevices returns the devices attached to the authenticated account.
func (c *Client) ListDevices() ([]api.Device, error) {
	var r api.ListDevicesResponse
	err := c.do(http.MethodGet, "/v1/devices", nil, &r)
	return r.Devices, err
}

// DeleteDevice revokes a device by id. Revoking the current device invalidates
// this client's own token.
func (c *Client) DeleteDevice(id string) error {
	return c.do(http.MethodDelete, "/v1/devices/"+url.PathEscape(id), nil, nil)
}

// Salt fetches an account's KDF params. found is false if the account does not
// exist, which `login` uses to branch between signup and device attach.
func (c *Client) Salt(email string) (params crypto.KdfParams, found bool, err error) {
	var r api.SaltResponse
	err = c.do(http.MethodGet, "/v1/account/salt?email="+url.QueryEscape(email), nil, &r)
	if errors.Is(err, ErrNotFound) {
		return crypto.KdfParams{}, false, nil
	}
	if err != nil {
		return crypto.KdfParams{}, false, err
	}
	return r.Kdf, true, nil
}

func (c *Client) PutResource(req api.PutResourceRequest) (api.PutResourceResponse, error) {
	var r api.PutResourceResponse
	err := c.do(http.MethodPut, "/v1/resources", req, &r)
	return r, err
}

func (c *Client) GetResource(id string) (api.GetResourceResponse, error) {
	var r api.GetResourceResponse
	err := c.do(http.MethodGet, "/v1/resources/"+url.PathEscape(id), nil, &r)
	return r, err
}

// SetVisibility flips a resource public/private without re-uploading its blob.
func (c *Client) SetVisibility(id string, vis api.Visibility) (api.PutResourceResponse, error) {
	var r api.PutResourceResponse
	err := c.do(http.MethodPost, "/v1/resources/"+url.PathEscape(id)+"/visibility", api.SetVisibilityRequest{Visibility: vis}, &r)
	return r, err
}

func (c *Client) ListResources() ([]api.ResourceListItem, error) {
	var r api.ListResourcesResponse
	err := c.do(http.MethodGet, "/v1/resources", nil, &r)
	return r.Resources, err
}

func (c *Client) DeleteResource(id string) error {
	return c.do(http.MethodDelete, "/v1/resources/"+url.PathEscape(id), nil, nil)
}

// CheckChunks returns which of the given object ids the server is missing — the
// have/want gate before packing and uploading.
func (c *Client) CheckChunks(ids []string) ([]string, error) {
	var r api.ChunkCheckResponse
	err := c.do(http.MethodPost, "/v1/chunks/check", api.ChunkCheckRequest{IDs: ids}, &r)
	return r.Missing, err
}

// LocateChunks resolves object ids to the packs and byte ranges that hold them, so
// the caller can range-fetch only what it needs.
func (c *Client) LocateChunks(ids []string) ([]api.ObjectLocation, error) {
	var r api.LocateResponse
	err := c.do(http.MethodPost, "/v1/chunks/locate", api.LocateRequest{IDs: ids}, &r)
	return r.Locations, err
}

// PutPack uploads one raw pack. The id is its content address; the server verifies
// it. Idempotent: re-uploading a stored pack succeeds without re-storing it.
func (c *Client) PutPack(packID string, pack []byte) error {
	return c.putRaw("/v1/packs/"+url.PathEscape(packID), pack)
}

// GetPackRange downloads length bytes of a pack starting at off, via an HTTP Range
// request, so a pull transfers only the span covering the objects it needs.
func (c *Client) GetPackRange(packID string, off, length int64) ([]byte, error) {
	return c.getRange("/v1/packs/"+url.PathEscape(packID), off, length)
}

// GC asks the server to sweep the owner's fully-dead packs, returning the pack
// count and bytes reclaimed.
func (c *Client) GC() (deletedPacks int, freedBytes int64, err error) {
	var r api.GCResponse
	err = c.do(http.MethodPost, "/v1/gc", nil, &r)
	return r.DeletedPacks, r.FreedBytes, err
}

// putRaw uploads an opaque body as application/octet-stream (the pack transport),
// mapping non-2xx responses the same way do() does.
func (c *Client) putRaw(path string, body []byte) error {
	req, err := http.NewRequest(http.MethodPut, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return statusError(resp.StatusCode, path, data)
}

// getRange downloads [off, off+length) of an opaque body via a Range request and
// returns the raw bytes. The server answers 206 (partial) or 200 (whole); both are
// success.
func (c *Client) getRange(path string, off, length int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+length-1))
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if err := statusError(resp.StatusCode, path, data); err != nil {
		return nil, err
	}
	return data, nil
}

// statusError maps an HTTP status to the package's sentinel errors, mirroring the
// tail of do() so the raw transport reports failures the same way.
func statusError(status int, path string, body []byte) error {
	switch {
	case status == http.StatusNotFound:
		return ErrNotFound
	case status == http.StatusConflict:
		return ErrConflict
	case status < 200 || status >= 300:
		var e api.ErrorResponse
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("server: %s (%d)", e.Error, status)
		}
		return fmt.Errorf("server returned %d for %s", status, path)
	}
	return nil
}

func (c *Client) do(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if err := statusError(resp.StatusCode, path, data); err != nil {
		return err
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
