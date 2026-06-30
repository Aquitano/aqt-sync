// Package client is a thin HTTP client for the aqt API. It carries the bearer
// token and (de)serializes the api wire types; it performs no cryptography.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

// ErrInsecureScheme is returned by New when a bearer token would be sent over a
// non-HTTPS URL. Loopback hosts (localhost, 127.0.0.1, ::1) are exempted so the
// documented http://localhost:8080 dev workflow keeps working without credentials
// leaking onto the network.
var ErrInsecureScheme = errors.New("aqt: refusing to send bearer token over non-HTTPS URL (use https://, or http://localhost for local dev)")

// New builds a Client. When token is non-empty the base URL must be HTTPS (or a
// loopback host), since every authenticated request carries the bearer token on
// the wire — a plaintext scheme would expose the only device credential to any
// on-path observer. The HTTP client also drops Authorization on any redirect to a
// non-HTTPS, non-loopback target, so an https→http downgrade on the same host
// (which Go's default CheckRedirect would forward the header to) cannot leak it.
func New(baseURL, token string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("aqt: invalid server URL: %w", err)
	}
	if token != "" && u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return nil, ErrInsecureScheme
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Preserve Go's default 10-redirect cap, which a custom
				// CheckRedirect would otherwise replace, leaving a hostile
				// server free to loop the client forever (and re-send the
				// bearer token on every same-host https hop).
				if len(via) >= 10 {
					return errors.New("aqt: stopped after 10 redirects")
				}
				if req.URL.Scheme != "https" && !isLoopbackHost(req.URL.Hostname()) {
					req.Header.Del("Authorization")
				}
				return nil
			},
		},
	}, nil
}

// isLoopbackHost reports whether host is a loopback or wildcard-bind address, the
// only non-HTTPS hosts permitted to carry a bearer token: a connection to any of
// them never leaves the machine. net.IP.IsLoopback covers the whole 127.0.0.0/8
// block and ::1; localhost and 0.0.0.0 are added explicitly since the former is a
// name and the latter (the wildcard bind, which dials to localhost) is not flagged
// loopback by the stdlib.
func isLoopbackHost(host string) bool {
	if host == "localhost" || host == "0.0.0.0" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
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

// Bootstrap fetches the new-device bootstrap for an email: the KDF params and the
// wrapped root key. The server returns an indistinguishable decoy for an unknown
// email (not a 404), so the caller cannot read account existence off the response;
// it derives the unlock key and tries to unwrap the root, and a failure means either
// no account exists or the passphrase is wrong.
func (c *Client) Bootstrap(email string) (api.SaltResponse, error) {
	var r api.SaltResponse
	err := c.do(http.MethodGet, "/v1/account/salt?email="+url.QueryEscape(email), nil, &r)
	return r, err
}

// ChangePassphrase re-wraps the account's root key under a new passphrase, returning
// the new auth epoch. The master key is unchanged, so no resource is re-encrypted.
func (c *Client) ChangePassphrase(req api.PassphraseChangeRequest) (api.AuthResponse, error) {
	var r api.AuthResponse
	err := c.do(http.MethodPut, "/v1/account/passphrase", req, &r)
	return r, err
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

// locateBatchSize bounds how many object ids ride in one /v1/chunks/locate request.
// The server caps that body at 32 MiB; at ~67 bytes per 64-hex id in the JSON array
// this keeps a request near 0.7 MiB, so a large clone (hundreds of thousands of chunk
// ids) splits into a handful of requests instead of one that trips the cap with a 413.
const locateBatchSize = 10_000

// LocateChunks resolves object ids to the packs and byte ranges that hold them, so
// the caller can range-fetch only what it needs. The id set is sent in bounded
// batches and the results merged, so a clone of a multi-GiB tree never exceeds the
// server's request-body cap.
func (c *Client) LocateChunks(ids []string) ([]api.ObjectLocation, error) {
	locations := make([]api.ObjectLocation, 0, len(ids))
	for start := 0; start < len(ids); start += locateBatchSize {
		end := start + locateBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		var r api.LocateResponse
		if err := c.do(http.MethodPost, "/v1/chunks/locate", api.LocateRequest{IDs: ids[start:end]}, &r); err != nil {
			return nil, err
		}
		locations = append(locations, r.Locations...)
	}
	return locations, nil
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

// GC asks the server to sweep the owner's fully-dead packs and compact the dead
// objects trapped in still-live ones, returning what each step reclaimed.
func (c *Client) GC() (api.GCResponse, error) {
	var r api.GCResponse
	err := c.do(http.MethodPost, "/v1/gc", nil, &r)
	return r, err
}

// --- snapshots ---

// CreateSnapshot pins the current version of a resource the caller owns, returning
// the new snapshot's metadata. label, when non-nil, is the client-sealed user label
// stored opaquely alongside (the client does the sealing; this package holds no
// keys).
func (c *Client) CreateSnapshot(resourceID string, label *crypto.SealedBlob) (api.SnapshotInfo, error) {
	var r api.SnapshotInfo
	err := c.do(http.MethodPost, "/v1/snapshots", api.CreateSnapshotRequest{ResourceID: resourceID, EncryptedLabel: label}, &r)
	return r, err
}

// ListSnapshots returns the caller's snapshots, newest first. A non-empty
// resourceID restricts the list to that resource's history.
func (c *Client) ListSnapshots(resourceID string) ([]api.SnapshotInfo, error) {
	path := "/v1/snapshots"
	if resourceID != "" {
		path += "?resource=" + url.QueryEscape(resourceID)
	}
	var r api.ListSnapshotsResponse
	err := c.do(http.MethodGet, path, nil, &r)
	return r.Snapshots, err
}

// GetSnapshot fetches a snapshot's sealed root blob plus the copied meta and
// wrapped key; the client reconstructs and decrypts it locally.
func (c *Client) GetSnapshot(id string) (api.GetSnapshotResponse, error) {
	var r api.GetSnapshotResponse
	err := c.do(http.MethodGet, "/v1/snapshots/"+url.PathEscape(id), nil, &r)
	return r, err
}

// DeleteSnapshot prunes a snapshot. Objects no live resource or other snapshot
// still roots are reclaimed by a later GC.
func (c *Client) DeleteSnapshot(id string) error {
	return c.do(http.MethodDelete, "/v1/snapshots/"+url.PathEscape(id), nil, nil)
}

// SetAutoSnapshot toggles whether the server's scheduled job snapshots a resource.
func (c *Client) SetAutoSnapshot(resourceID string, enabled bool) error {
	return c.do(http.MethodPost, "/v1/resources/"+url.PathEscape(resourceID)+"/auto-snapshot",
		api.SetAutoSnapshotRequest{Enabled: enabled}, nil)
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
// returns exactly that window. The server normally answers 206 with just the range,
// but 200 with the whole body is a valid response to a Range request; in that case the
// window is sliced out here, so callers can rely on getRange returning the requested
// bytes regardless of which status the server chose.
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
	if resp.StatusCode == http.StatusOK {
		// The server ignored the Range and sent the whole body; cut out the window.
		if off < 0 || off > int64(len(data)) {
			return nil, fmt.Errorf("range start %d beyond %s length %d", off, path, len(data))
		}
		end := off + length
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		return data[off:end], nil
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
