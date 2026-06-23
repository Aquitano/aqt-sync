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

// CheckChunks returns which of the given chunk ids the server is missing.
func (c *Client) CheckChunks(ids []string) ([]string, error) {
	var r api.ChunkCheckResponse
	err := c.do(http.MethodPost, "/v1/chunks/check", api.ChunkCheckRequest{IDs: ids}, &r)
	return r.Missing, err
}

// PutChunks uploads a batch of content-addressed chunks. The caller is
// responsible for keeping a batch under the server body cap.
func (c *Client) PutChunks(chunks []api.ChunkData) error {
	return c.do(http.MethodPost, "/v1/chunks", api.ChunkUploadRequest{Chunks: chunks}, nil)
}

// FetchChunks downloads a batch of chunks by id.
func (c *Client) FetchChunks(ids []string) ([]api.ChunkData, error) {
	var r api.ChunkFetchResponse
	err := c.do(http.MethodPost, "/v1/chunks/fetch", api.ChunkFetchRequest{IDs: ids}, &r)
	return r.Chunks, err
}

// GC asks the server to sweep the owner's unreferenced chunks.
func (c *Client) GC() (int, error) {
	var r api.GCResponse
	err := c.do(http.MethodPost, "/v1/gc", nil, &r)
	return r.Deleted, err
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
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode == http.StatusConflict {
		return ErrConflict
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e api.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("server: %s (%d)", e.Error, resp.StatusCode)
		}
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
