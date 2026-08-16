// SPDX-License-Identifier: AGPL-3.0-or-later

// Package client is a thin HTTP client for the aqt API. It carries the bearer
// token and (de)serializes the api wire types; it performs no cryptography.
package client

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/safetext"
)

// ErrNotFound maps a 404 so callers can distinguish "no such account/resource".
var ErrNotFound = errors.New("not found")

// ErrUnauthorized maps a 401 so login can distinguish a revoked local device
// from a transient network failure without creating a duplicate attachment.
var ErrUnauthorized = errors.New("unauthorized")

// ErrConflict maps a 409 so callers can distinguish a version conflict (the
// resource moved under them) and retry against the new state.
var ErrConflict = errors.New("conflict")

// UnknownOutcomeError means an unsafe mutation lost a definitive response.
type UnknownOutcomeError struct {
	Operation string
	Err       error
}

func (e *UnknownOutcomeError) Error() string {
	return fmt.Sprintf("%s outcome is unknown: %v", e.Operation, e.Err)
}
func (e *UnknownOutcomeError) Unwrap() error { return e.Err }

func mutationOutcome(operation string, err error) error {
	if err == nil {
		return nil
	}
	// ErrRateLimited belongs here: the limiter middleware aborts before the handler
	// runs, so a 429 means the mutation definitively did not happen.
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrConflict) || errors.Is(err, ErrGone) || errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrDeviceLimit) || errors.Is(err, ErrSenderBlocked) || errors.Is(err, ErrRateLimited) {
		return err
	}
	var upgrade *UpgradeRequiredError
	if errors.As(err, &upgrade) {
		return err
	}
	return &UnknownOutcomeError{Operation: operation, Err: err}
}

// ErrGone maps a 410: a public link has expired, reached its read limit, or been
// reclaimed. Callers surface it distinctly (exit code 7) from a plain not-found.
var ErrGone = errors.New("link expired or read limit reached")

// ErrQuotaExceeded maps a 507 (or the quota_exceeded code) so callers can surface
// "storage quota exceeded" distinctly from a generic server error.
var ErrQuotaExceeded = errors.New("storage quota exceeded; free space or ask the server operator to raise the quota")

// ErrRateLimited means the server answered 429 and the request had already ridden
// out its budget of Retry-After waits.
var ErrRateLimited = errors.New("server rate limit exceeded; retry in a moment")

// ErrSenderBlocked maps the sender_blocked code (a 403 on a grant write): the
// grantee has blocked this account. The refusal is definitive, not a lost outcome,
// and no retry or rewording of the grant changes it.
var ErrSenderBlocked = errors.New("the recipient is not accepting shares from your account")

// ErrDeviceLimit maps the device_limit code (a 403 on attach) so a caller can tell
// "revoke a device first" apart from a generic authorization failure.
var ErrDeviceLimit = errors.New("device limit reached; revoke a device before attaching another")

// ErrBadPack maps the bad_pack code (a 400 on pack upload): the pack was malformed or
// failed the server's verification, distinct from a generic bad request.
var ErrBadPack = errors.New("uploaded pack is malformed or fails verification")

// ErrUpgradeRequired maps a 426: the resource is sealed in a format newer than this
// build reads. Callers test errors.Is(err, ErrUpgradeRequired); the concrete
// UpgradeRequiredError carries the server-declared min_client for messaging.
var ErrUpgradeRequired = errors.New("client upgrade required to read this resource")

// UpgradeRequiredError is the 426 mapping. Its message is composed from facts this
// build knows first-hand — the capability it declares, and the capability the server
// says the resource needs — rather than echoing the server's prose, which is
// attacker-controlled on a hostile or compromised server. Detail carries that prose
// sanitized, for the cases where it explains something the numbers do not.
type UpgradeRequiredError struct {
	// MinClient is the capability the resource requires, per the server.
	MinClient int
	// Capability is what this build declared in X-Aqt-Capability.
	Capability int
	// Detail is the server's message, control characters stripped and length
	// bounded. Empty when the server sent none.
	Detail string
}

func (e *UpgradeRequiredError) Error() string {
	msg := fmt.Sprintf("this build reads capability %d formats; that resource needs capability %d or newer — run `aqt update`",
		e.Capability, e.MinClient)
	if e.Detail != "" {
		msg += fmt.Sprintf(" (server said: %s)", e.Detail)
	}
	return msg
}

// Is lets errors.Is(err, ErrUpgradeRequired) match any UpgradeRequiredError.
func (e *UpgradeRequiredError) Is(target error) bool { return target == ErrUpgradeRequired }

// ErrSnapshotAnchored maps a 409 carrying the anchored error code: the prune targeted
// an anchored snapshot. Callers test errors.Is(err, ErrSnapshotAnchored); the concrete
// SnapshotAnchoredError carries the server's message naming the unanchor escape hatch.
var ErrSnapshotAnchored = errors.New("snapshot is anchored")

// SnapshotAnchoredError is the anchored-prune 409 mapping. Message is the server's
// human-actionable text (printed verbatim).
type SnapshotAnchoredError struct{ Message string }

func (e *SnapshotAnchoredError) Error() string { return e.Message }

func (e *SnapshotAnchoredError) Is(target error) bool { return target == ErrSnapshotAnchored }

type Client struct {
	baseURL string
	token   string
	http    *http.Client
	// cooldown is shared by every request this client makes, so a 429 observed by
	// one of a sync's concurrent transfers backs all of them off together.
	cooldown *cooldown
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
		baseURL:  strings.TrimRight(baseURL, "/"),
		token:    token,
		cooldown: newCooldown(),
		http: &http.Client{
			// No Client.Timeout: it caps the whole exchange including body
			// transfer, so a 16 MiB pack upload failed permanently on links
			// below ~4-5 Mbps. Hung connections are bounded instead by the
			// per-request stall guard (see send) plus the dial/TLS timeouts.
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
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

// ListDevices returns the devices attached to the authenticated account, following
// pagination transparently.
func (c *Client) ListDevices() ([]api.Device, error) {
	return listAll("/v1/devices", func(path string) ([]api.Device, string, error) {
		var r api.ListDevicesResponse
		err := c.do(http.MethodGet, path, nil, &r)
		return r.Devices, r.NextCursor, err
	})
}

// DeleteDevice revokes a device by id. Revoking the current device invalidates
// this client's own token.
func (c *Client) DeleteDevice(id string) error {
	return c.do(http.MethodDelete, "/v1/devices/"+url.PathEscape(id), nil, nil)
}

// Usage fetches the account's storage summary.
func (c *Client) Usage() (api.UsageResponse, error) {
	var r api.UsageResponse
	err := c.do(http.MethodGet, "/v1/account/usage", nil, &r)
	return r, err
}

// DeleteAccount erases the account and everything stored under it, returning the
// server's receipt. The request carries the passphrase-derived auth verifier: this
// client's token alone does not authorize it. Every token on the account, including
// this one, stops working on success.
func (c *Client) DeleteAccount(req api.DeleteAccountRequest) (api.DeleteAccountResponse, error) {
	var r api.DeleteAccountResponse
	err := c.do(http.MethodDelete, "/v1/account", req, &r)
	return r, err
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

// RotateRootKey replaces the account root key and every server-held key wrap that
// depends on it. A successful rotation returns a fresh token for the current device.
func (c *Client) RotateRootKey(req api.RootKeyRotationRequest) (api.AuthResponse, error) {
	var r api.AuthResponse
	err := c.do(http.MethodPut, "/v1/account/root-key", req, &r)
	return r, err
}

// PutResource uploads a resource as a raw envelope (JSON header + ciphertext), so the
// blob never pays the base64-in-JSON tax. A create (empty id) goes to POST
// /v1/resources so the server assigns the id; an in-place update (id set) goes to PUT.
// Both land on the same server handler, which dispatches on the id.
func (c *Client) PutResource(req api.PutResourceRequest) (api.PutResourceResponse, error) {
	var r api.PutResourceResponse
	body, err := api.EncodeResourceUpload(req)
	if err != nil {
		return r, err
	}
	method := http.MethodPost
	if req.ID != "" {
		method = http.MethodPut
	}
	if req.ID == "" {
		err = c.doRawIdempotent(method, "/v1/resources", body, &r)
	} else {
		err = c.doRaw(method, "/v1/resources", body, &r)
	}
	return r, err
}

// GetResource fetches a resource; the response is the raw envelope, decoded
// straight off the body.
func (c *Client) GetResource(id string) (api.GetResourceResponse, error) {
	path := "/v1/resources/" + url.PathEscape(id)
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return api.GetResourceResponse{}, err
	}
	// Opt into the raw envelope; without this the server answers legacy JSON.
	req.Header.Set("Accept", api.ResourceEnvelopeMediaType)
	_, data, err := c.send(req, path)
	if err != nil {
		return api.GetResourceResponse{}, err
	}
	res, err := api.DecodeResourceDownload(bytes.NewReader(data))
	if err != nil {
		return api.GetResourceResponse{}, err
	}
	// Pin the echoed id to the requested one. The id-bound AAD checks downstream
	// verify against res.ID; without this pin a hostile server could serve another
	// resource's record and echo that record's id, satisfying its own binding.
	if res.ID != id {
		return api.GetResourceResponse{}, fmt.Errorf("server returned resource %q for requested id %q", res.ID, id)
	}
	return res, nil
}

// SetVisibility flips a resource public/private without re-uploading its blob. The
// request's ExpireSeconds/MaxReads/OnExpiry carry an optional lifecycle policy applied
// on the same call (meaningful only when going/staying public); zero means no limit.
// The response echoes the accepted policy so the caller can fail closed against a
// server that does not enforce it.
func (c *Client) SetVisibility(id string, req api.SetVisibilityRequest) (api.PutResourceResponse, error) {
	var r api.PutResourceResponse
	if req.ExpectedVersion <= 0 {
		version, err := c.versionToPin(id)
		if err != nil {
			return r, err
		}
		req.ExpectedVersion = version
	}
	err := c.do(http.MethodPost, "/v1/resources/"+url.PathEscape(id)+"/visibility", req, &r)
	err = mutationOutcome("set visibility", err)
	return r, err
}

// UpdateResourceMetadata replaces only the opaque sealed metadata blob.
func (c *Client) UpdateResourceMetadata(id string, req api.UpdateResourceMetadataRequest) (api.PutResourceResponse, error) {
	var r api.PutResourceResponse
	err := c.do(http.MethodPut, "/v1/resources/"+url.PathEscape(id)+"/metadata", req, &r)
	return r, err
}

// ListResources returns all of the owner's resources, following the endpoint's
// pagination transparently so a CLI caller still gets the whole slice in one call.
func (c *Client) ListResources() ([]api.ResourceListItem, error) {
	return listAll("/v1/resources", func(path string) ([]api.ResourceListItem, string, error) {
		var r api.ListResourcesResponse
		err := c.do(http.MethodGet, path, nil, &r)
		return r.Resources, r.NextCursor, err
	})
}

// maxListPages bounds every paginated listing. The cursor loops trust the server to
// terminate them, and nothing else does: a server that returns a constant nextCursor
// spins forever, and the stall guard never fires because each request completes
// normally. This layer distrusts the server everywhere else (redirect cap, id pin,
// per-frame content-address verification); the page count is the same kind of bound.
const maxListPages = 10_000

// errTooManyPages is what a listing returns when the server will not end it.
var errTooManyPages = errors.New("server did not end the listing (cursor never terminated)")

// listAll follows a paginated endpoint to its end, accumulating every page's items.
// fetch requests the one page at path — already carrying the cursor — and returns its
// items with the cursor for the next one. A fetch that fails aborts the whole listing,
// so a caller never sees a silently truncated slice.
func listAll[T any](base string, fetch func(path string) ([]T, string, error)) ([]T, error) {
	var all []T
	cursor, pages := "", 0
	for {
		items, next, err := fetch(withCursor(base, cursor))
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		more, err := nextPage(&cursor, next, &pages)
		if err != nil {
			return nil, err
		}
		if !more {
			return all, nil
		}
	}
}

// nextPage advances a cursor loop, returning false once the listing is done. It
// refuses a cursor that did not move and a page count past maxListPages, so a
// misbehaving or hostile server ends the loop instead of pinning the client.
func nextPage(cursor *string, next string, pages *int) (bool, error) {
	if next == "" {
		return false, nil
	}
	if next == *cursor {
		return false, errTooManyPages
	}
	if *pages++; *pages >= maxListPages {
		return false, errTooManyPages
	}
	*cursor = next
	return true, nil
}

// withCursor appends an opaque pagination cursor to a path, respecting any query
// string already present.
func withCursor(path, cursor string) string {
	if cursor == "" {
		return path
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "cursor=" + url.QueryEscape(cursor)
}

// versionToPin resolves the version a read-modify-write should pin itself to. A
// reclaimed tombstone answers 410 and has no content left to race over, so it pins
// nothing (the server treats 0 as unpinned) rather than failing — otherwise the row
// the owner is told to `aqt rm` could never be removed. Prefer passing a version you
// already hold: this costs a round trip, and for an inline resource it downloads the
// whole ciphertext to read an integer.
func (c *Client) versionToPin(id string) (int, error) {
	current, err := c.GetResource(id)
	if errors.Is(err, ErrGone) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return current.Version, nil
}

func (c *Client) DeleteResourceVersion(id string, version int) error {
	path := "/v1/resources/" + url.PathEscape(id)
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("If-Match", strconv.Itoa(version))
	_, _, err = c.send(req, path)
	return mutationOutcome("delete resource", err)
}

// checkBatchSize bounds how many object ids ride in one /v1/chunks/check request. It
// matches the locate batch cap and stays at or under the server's per-request id cap,
// so a large sync's have/want gate splits into several requests instead of one that
// the server rejects with a 400.
const checkBatchSize = 10_000

// CheckChunks returns which of the given object ids the server is missing — the
// have/want gate before packing and uploading. The id set is sent in bounded batches
// and the missing sets merged, so a large sync never exceeds the server's id cap.
func (c *Client) CheckChunks(ids []string) ([]string, error) {
	var missing []string
	for start := 0; start < len(ids); start += checkBatchSize {
		end := start + checkBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		var r api.ChunkCheckResponse
		if err := c.do(http.MethodPost, "/v1/chunks/check", api.ChunkCheckRequest{IDs: ids[start:end]}, &r); err != nil {
			return nil, err
		}
		missing = append(missing, r.Missing...)
	}
	return missing, nil
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

// maxPublicFrame bounds one framed object in a public-objects response so a hostile
// server cannot force a huge allocation off an oversized length prefix. It mirrors
// the server's per-pack body cap (an object slice is a sub-range of one pack).
const maxPublicFrame = 32 << 20

// maxResponseBytes bounds any single buffered response body (send's io.ReadAll):
// the largest legitimate bodies are pack ranges and root blobs, both bounded by
// api.MaxPackBytes, so 256 MiB is generous headroom rather than a tight fit.
const maxResponseBytes = 256 << 20

// PublicObjects fetches exact object slices for a public streamed resource over the
// unauthenticated public endpoint — the share-link path, where the content key lives
// in the caller's URL fragment, not here. It issues a single POST (the CLI caller
// batches) and returns one byte slice per requested id, in request order; a duplicate
// id yields a duplicate slice, since the wire framing is positional. A 404 maps to
// ErrNotFound like the other reads.
func (c *Client) PublicObjects(resourceID string, ids []string) ([][]byte, error) {
	body, err := json.Marshal(api.PublicObjectsRequest{IDs: ids})
	if err != nil {
		return nil, err
	}
	path := "/v1/public/resources/" + url.PathEscape(resourceID) + "/objects"
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", api.ObjectFramesMediaType)
	// Same stall-guarded transport as the pack download path; the CLI-side batching
	// keeps one response small enough to buffer.
	_, data, err := c.send(req, path)
	if err != nil {
		return nil, err
	}
	return parsePublicFrames(data, len(ids))
}

// parsePublicFrames splits a positional length-prefixed response into exactly want
// frames. A frame length of zero, one past the per-object cap, or a body too short
// for the declared length is a protocol error — a truncated or hostile response.
func parsePublicFrames(data []byte, want int) ([][]byte, error) {
	out := make([][]byte, 0, want)
	for i := 0; i < want; i++ {
		if len(data) < 4 {
			return nil, fmt.Errorf("aqt: public objects response truncated before frame %d of %d", i, want)
		}
		n := binary.BigEndian.Uint32(data[:4])
		data = data[4:]
		if n == 0 || n > maxPublicFrame {
			return nil, fmt.Errorf("aqt: public objects frame %d declares invalid length %d", i, n)
		}
		if uint32(len(data)) < n {
			return nil, fmt.Errorf("aqt: public objects frame %d truncated: want %d bytes, have %d", i, n, len(data))
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out, nil
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
// keys). anchor pins the snapshot against retention.
func (c *Client) CreateSnapshot(resourceID string, label *crypto.SealedBlob, anchor bool) (api.SnapshotInfo, error) {
	var r api.SnapshotInfo
	err := c.doIdempotent(http.MethodPost, "/v1/snapshots", api.CreateSnapshotRequest{ResourceID: resourceID, EncryptedLabel: label, Anchor: anchor}, &r)
	return r, err
}

// CreateAutoSnapshot pins a maintenance checkpoint immediately before git-remote
// compaction or restore swaps. It is marked automatic so it stays out of the
// user's manual history, and anchored because scheduled retention keeps only the
// newest keepLast automatic snapshots: the swap the checkpoint protects is not
// validated until after the PUT, and a prune tick in between must not delete the
// only rollback. The caller releases the anchor (SetSnapshotAnchor) once the swap
// commits.
func (c *Client) CreateAutoSnapshot(resourceID string) (api.SnapshotInfo, error) {
	var r api.SnapshotInfo
	err := c.doIdempotent(http.MethodPost, "/v1/snapshots", api.CreateSnapshotRequest{ResourceID: resourceID, Automatic: true, Anchor: true}, &r)
	return r, err
}

// SetSnapshotAnchor toggles a snapshot's anchor and returns the updated metadata, so
// the caller can verify the server honored the change (an older server that ignores
// the field echoes the old state, which the caller treats as a hard error).
func (c *Client) SetSnapshotAnchor(id string, anchored bool) (api.SnapshotInfo, error) {
	var r api.SnapshotInfo
	err := c.do(http.MethodPost, "/v1/snapshots/"+url.PathEscape(id)+"/anchor",
		api.SetSnapshotAnchorRequest{Anchored: anchored}, &r)
	err = mutationOutcome("set snapshot anchor", err)
	return r, err
}

// ListSnapshots returns the caller's snapshots, newest first. A non-empty
// resourceID restricts the list to that resource's history.
func (c *Client) ListSnapshots(resourceID string) ([]api.SnapshotInfo, error) {
	base := "/v1/snapshots"
	if resourceID != "" {
		base += "?resource=" + url.QueryEscape(resourceID)
	}
	return listAll(base, func(path string) ([]api.SnapshotInfo, string, error) {
		var r api.ListSnapshotsResponse
		if err := c.do(http.MethodGet, path, nil, &r); err != nil {
			return nil, "", err
		}
		// Pin a filtered listing to the requested resource: the ResourceID field is
		// server-supplied, and downstream id-bound AAD checks verify against it.
		if resourceID != "" {
			for _, s := range r.Snapshots {
				if s.ResourceID != resourceID {
					return nil, "", fmt.Errorf("server returned a snapshot of resource %q in a listing for %q", s.ResourceID, resourceID)
				}
			}
		}
		return r.Snapshots, r.NextCursor, nil
	})
}

// GetSnapshot fetches a snapshot's sealed root blob plus the copied meta and
// wrapped key; the client reconstructs and decrypts it locally.
func (c *Client) GetSnapshot(id string) (api.GetSnapshotResponse, error) {
	var r api.GetSnapshotResponse
	if err := c.do(http.MethodGet, "/v1/snapshots/"+url.PathEscape(id), nil, &r); err != nil {
		return r, err
	}
	if r.Snapshot.ID != id {
		return api.GetSnapshotResponse{}, fmt.Errorf("server returned snapshot %q for requested id %q", r.Snapshot.ID, id)
	}
	return r, nil
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

// stallTimeout aborts a request only after no request or response body bytes
// have moved for this long. Progress resets it, so total transfer time is
// unbounded — a multi-MiB pack completes on an arbitrarily slow link — while a
// wedged connection (or a server that never answers) still dies. It also spans
// the wait for response headers, so it must stay above the slowest
// non-streaming endpoint (GC planning on a large store). Var, not const, so
// tests can shorten it.
var stallTimeout = 60 * time.Second

func errStalled(timeout time.Duration) error {
	return fmt.Errorf("aqt: transfer stalled (no data for %s)", timeout)
}

// stallGuard cancels a request's context once no progress has been observed
// for its timeout. touch is called from body Read paths on any goroutine
// (atomic store only); the timer re-arms itself from its own callback for the
// remaining window, so Timer.Reset is never called concurrently. timeout is
// captured from stallTimeout at construction so the timer goroutine never reads
// the package var (which tests mutate).
type stallGuard struct {
	last    atomic.Int64
	timer   *time.Timer
	cancel  context.CancelCauseFunc
	timeout time.Duration
}

func newStallGuard(cancel context.CancelCauseFunc) *stallGuard {
	g := &stallGuard{cancel: cancel, timeout: stallTimeout}
	g.touch()
	g.timer = time.AfterFunc(g.timeout, g.check)
	return g
}

func (g *stallGuard) touch() { g.last.Store(time.Now().UnixNano()) }

func (g *stallGuard) check() {
	idle := time.Since(time.Unix(0, g.last.Load()))
	if idle >= g.timeout {
		g.cancel(errStalled(g.timeout))
		return
	}
	g.timer.Reset(g.timeout - idle)
}

func (g *stallGuard) stop() { g.timer.Stop() }

// progressBody wraps a request or response body so every successful read
// resets the stall guard.
type progressBody struct {
	rc    io.ReadCloser
	touch func()
}

func (p *progressBody) Read(b []byte) (int, error) {
	n, err := p.rc.Read(b)
	if n > 0 {
		p.touch()
	}
	return n, err
}

func (p *progressBody) Close() error { return p.rc.Close() }

// send executes req under the stall guard, attaches the bearer token, fully
// reads the response body, and maps the status via statusError. The transport
// reports a guard-canceled request as a bare context.Canceled, which would
// read as a user abort, so the guard's cause is surfaced instead.
func (c *Client) send(req *http.Request, path string) (status int, data []byte, err error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	defer cancel(nil)
	guard := newStallGuard(cancel)
	defer guard.stop()

	if req.Body != nil {
		req.Body = &progressBody{rc: req.Body, touch: guard.touch}
		if getBody := req.GetBody; getBody != nil {
			req.GetBody = func() (io.ReadCloser, error) {
				rc, err := getBody()
				if err != nil {
					return nil, err
				}
				return &progressBody{rc: rc, touch: guard.touch}, nil
			}
		}
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// Declare which sealed-resource formats this build reads, so the server can answer
	// a boundary it cannot cross with a 426 rather than serving bytes that fail to open.
	req.Header.Set(api.CapabilityHeader, strconv.Itoa(api.ClientCapability))

	var spent time.Duration
	for attempt := 0; ; attempt++ {
		// Observe any cooldown a *concurrent* request established before sending, so
		// one 429 throttles the whole client rather than only the request that saw it.
		// This is also where a retry serves its own wait.
		guard.touch()
		if err := c.cooldown.wait(ctx, guard.touch); err != nil {
			return 0, nil, fmt.Errorf("request %s %s: %w", req.Method, path, err)
		}

		resp, err := c.http.Do(req.WithContext(ctx))
		if err != nil {
			return 0, nil, fmt.Errorf("request %s %s: %w", req.Method, path, unwrapStall(ctx, err))
		}
		// Bounded against the client's own hostile-server posture: a server that
		// streams forever must not buffer unbounded memory here.
		data, readErr := io.ReadAll(io.LimitReader(&progressBody{rc: resp.Body, touch: guard.touch}, maxResponseBytes+1))
		resp.Body.Close()
		if readErr == nil && len(data) > maxResponseBytes {
			return 0, nil, fmt.Errorf("request %s %s: response exceeds %d bytes; refusing to buffer it", req.Method, path, maxResponseBytes)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			// The server computes its wait from the bucket's own refill rate, so
			// observing it is exactly long enough. Retrying here rather than failing
			// the command keeps a large sync from dying on a burst it will be allowed
			// to finish.
			wait := retryAfterFrom(resp, data, time.Now())
			deadline := c.cooldown.enter(wait)
			if attempt < maxRateLimitRetries && spent+wait <= maxRetryTotal {
				// The next pass observes the deadline just published, along with any
				// later one a concurrent request establishes while this one waits.
				if replay, rewound := rewindBody(req); rewound {
					req = replay
					spent += wait
					continue
				}
			}
			return resp.StatusCode, data, &RateLimitedError{
				Attempts:    attempt + 1,
				LastDelay:   wait,
				NextRetryAt: deadline,
			}
		}

		if err := statusError(resp.StatusCode, path, data); err != nil {
			return resp.StatusCode, data, err
		}
		if readErr != nil {
			return resp.StatusCode, nil, fmt.Errorf("read response %s %s: %w", req.Method, path, unwrapStall(ctx, readErr))
		}
		return resp.StatusCode, data, nil
	}
}

// rewindBody returns a replayable copy of req. A bodyless request always replays; a
// request with a body only does if it carries GetBody (every request this package
// builds from a buffer does).
func rewindBody(req *http.Request) (*http.Request, bool) {
	if req.Body == nil {
		return req, true
	}
	if req.GetBody == nil {
		return req, false
	}
	body, err := req.GetBody()
	if err != nil {
		return req, false
	}
	clone := req.Clone(req.Context())
	clone.Body = body
	return clone, true
}

func unwrapStall(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return err
}

// putRaw uploads an opaque body as application/octet-stream (the pack transport),
// mapping non-2xx responses the same way do() does.
func (c *Client) putRaw(path string, body []byte) error {
	req, err := http.NewRequest(http.MethodPut, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	_, _, err = c.send(req, path)
	return err
}

// doRaw sends body as application/octet-stream (the raw resource/pack envelope)
// and decodes a JSON response into out, mapping non-2xx the same way do() does.
// Unlike putRaw it carries a status/response body back to the caller.
func (c *Client) doRaw(method, path string, body []byte, out any) error {
	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", api.ResourceEnvelopeMediaType)
	_, data, err := c.send(req, path)
	if err != nil {
		return err
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func newIdempotencyKey() (string, error) {
	var raw [16]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate idempotency key: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// retryableCreate reports whether a failed idempotent create is worth one more
// attempt: transport failures (send reports status 0) and transient 5xx, which
// the idempotency key makes safe to replay. Definitive rejections — 4xx and the
// quota 507 — would only repeat the same answer at double the load.
func retryableCreate(status int) bool {
	return status == 0 || (status >= 500 && status != http.StatusInsufficientStorage)
}

func (c *Client) doRawIdempotent(method, path string, body []byte, out any) error {
	key, err := newIdempotencyKey()
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", api.ResourceEnvelopeMediaType)
		req.Header.Set("Idempotency-Key", key)
		status, data, err := c.send(req, path)
		if err != nil {
			if !retryableCreate(status) {
				return err
			}
			last = err
			continue
		}
		if out != nil && len(data) > 0 {
			return json.Unmarshal(data, out)
		}
		return nil
	}
	return last
}

func (c *Client) doIdempotent(method, path string, body, out any) error {
	key, err := newIdempotencyKey()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		status, data, err := c.send(req, path)
		if err != nil {
			if !retryableCreate(status) {
				return err
			}
			last = err
			continue
		}
		if out != nil && len(data) > 0 {
			return json.Unmarshal(data, out)
		}
		return nil
	}
	return last
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
	status, data, err := c.send(req, path)
	if err != nil {
		return nil, err
	}
	if status == http.StatusOK {
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

// statusError maps an HTTP response to the package's sentinel errors, mirroring the
// tail of do() so the raw transport reports failures the same way. It prefers the
// machine-readable ErrorResponse.Code and falls back to the HTTP status, so a
// condition the status alone cannot express (device_limit vs a plain 403, bad_pack
// vs a plain 400) is still surfaced distinctly.
func statusError(status int, path string, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	var e api.ErrorResponse
	json.Unmarshal(body, &e) // best effort; a bodyless or non-JSON error falls through to status

	switch e.Code {
	case api.ErrCodeSnapshotAnchored:
		return &SnapshotAnchoredError{Message: safetext.Clean(e.Error, safetext.DisplayMax)}
	case api.ErrCodeUpgradeRequired:
		return upgradeRequired(e)
	case api.ErrCodeGone:
		return ErrGone
	case api.ErrCodeQuotaExceeded:
		return ErrQuotaExceeded
	case api.ErrCodeVersionConflict:
		return ErrConflict
	case api.ErrCodeDeviceLimit:
		return ErrDeviceLimit
	case api.ErrCodeSenderBlocked:
		return ErrSenderBlocked
	case api.ErrCodeBadPack:
		return ErrBadPack
	case api.ErrCodeNotFound:
		return ErrNotFound
	case api.ErrCodeRateLimited:
		return ErrRateLimited
	case api.ErrCodeAccountExists:
		return ErrConflict
	}

	switch status {
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	case http.StatusGone:
		return ErrGone
	case http.StatusInsufficientStorage:
		return ErrQuotaExceeded
	case http.StatusUpgradeRequired:
		return upgradeRequired(e)
	}
	if e.Error != "" {
		// The fallback for any unmapped code prints server prose verbatim; a hostile
		// server's bytes reach the terminal here just like a grantor's name does.
		return fmt.Errorf("server: %s (%d)", safetext.Clean(e.Error, safetext.DisplayMax), status)
	}
	return fmt.Errorf("server returned %d for %s", status, path)
}

// upgradeRequired builds the 426 mapping. A server that declares a min_client at or
// below what this build supports is contradicting itself; report the next capability
// up rather than a message saying the running client needs to reach a bar it already
// clears.
func upgradeRequired(e api.ErrorResponse) *UpgradeRequiredError {
	need := e.MinClient
	if need <= api.ClientCapability {
		need = api.ClientCapability + 1
	}
	return &UpgradeRequiredError{
		MinClient:  need,
		Capability: api.ClientCapability,
		Detail:     safetext.Clean(e.Error, safetext.DisplayMax),
	}
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

	_, data, err := c.send(req, path)
	if err != nil {
		return err
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
