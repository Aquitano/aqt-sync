// SPDX-License-Identifier: AGPL-3.0-or-later

// Package server implements aqt's zero-knowledge HTTP API on top of Gin. Every
// payload it handles is opaque ciphertext or key material it cannot read.
package server

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

// RegistrationMode selects how POST /v1/account handles a new signup.
type RegistrationMode string

const (
	// RegistrationOpen (the default) lets anyone sign up. A signup for an email that
	// already has an account returns the same success shape as a fresh one instead of
	// a 409, so the endpoint is not an existence oracle; the duplicate creates
	// nothing and the caller's next authenticated call fails, matching the
	// wrong-passphrase ambiguity the decoy salt already presents.
	RegistrationOpen RegistrationMode = "open"
	// RegistrationInvite additionally requires a valid server-issued invite token on
	// every signup, so an attacker cannot squat an unclaimed email. Tokens are
	// deployment-configured shared secrets, compared in constant time.
	RegistrationInvite RegistrationMode = "invite"
)

// Config tunes deployment-specific hardening. The zero value is open registration
// (no 409 oracle), no quota, and no device cap; trusted proxies are left unset (see
// TrustedProxies), which the aqt-server binary fills in as loopback-only.
type Config struct {
	// Registration selects open (default) or invite-token signup; an empty value is
	// treated as open.
	Registration RegistrationMode
	// InviteTokens are the accepted invite secrets in RegistrationInvite mode.
	InviteTokens []string
	// QuotaBytes caps physical storage attributable to an account: packs, resource and
	// snapshot blobs, and modeled database-row growth. Zero means unlimited.
	QuotaBytes int64
	// MaxDevices caps devices per account. 0 means unlimited.
	MaxDevices   int
	MaxResources int
	MaxSnapshots int
	MaxObjects   int
	// TrustedProxies is passed to gin.SetTrustedProxies, but only when set through
	// WithTrustedProxies: the CIDRs/hosts whose X-Forwarded-* headers are believed.
	// Left unset (the zero value), gin's own default — which trusts every proxy —
	// applies, so the binary always sets it; an explicit empty slice trusts none
	// (RemoteAddr is used verbatim).
	TrustedProxies    []string
	trustedProxiesSet bool
	// AuthedRatePerSec and AuthedBurst bound per-device request rates on the
	// authenticated routes. Zero values pick the package defaults.
	AuthedRatePerSec float64
	AuthedBurst      float64
	// SourceURL is where the share page points for this server's source. The
	// upstream default is only accurate while the deployment runs unmodified code.
	SourceURL string
}

// DefaultSourceURL is the upstream repository, used when SourceURL is unset.
const DefaultSourceURL = "https://github.com/aquitano/aqt-sync"

func (c Config) sourceURL() string {
	if c.SourceURL == "" {
		return DefaultSourceURL
	}
	return c.SourceURL
}

func (c Config) Validate() error {
	registration := c.Registration
	if registration == "" {
		registration = RegistrationOpen
	}
	if registration != RegistrationOpen && registration != RegistrationInvite {
		return fmt.Errorf("registration mode %q must be open or invite", c.Registration)
	}
	if registration == RegistrationInvite && len(c.InviteTokens) == 0 {
		return errors.New("invite registration requires at least one invite token")
	}
	if c.QuotaBytes < 0 || c.MaxDevices < 0 || c.MaxResources < 0 || c.MaxSnapshots < 0 || c.MaxObjects < 0 {
		return errors.New("quotas and count limits must be non-negative")
	}
	if c.AuthedRatePerSec < 0 || c.AuthedBurst < 0 {
		return errors.New("authentication rate and burst must be non-negative")
	}
	for _, proxy := range c.TrustedProxies {
		if net.ParseIP(proxy) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			return fmt.Errorf("trusted proxy %q is not an IP address or CIDR", proxy)
		}
	}
	if c.SourceURL != "" {
		// Caught here because html/template swaps an unusable scheme for a
		// placeholder at render time, leaving a dead link and no error.
		u, err := url.Parse(c.SourceURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("source URL %q must be an absolute http(s) URL", c.SourceURL)
		}
	}
	return nil
}

// WithTrustedProxies records an explicit trusted-proxy list (including an empty one,
// which nil cannot express) so Router applies it instead of gin's default.
func (c Config) WithTrustedProxies(proxies []string) Config {
	c.TrustedProxies = proxies
	c.trustedProxiesSet = true
	return c
}

// inviteAccepted reports whether token matches a configured invite secret, in
// constant time over the whole list so timing does not leak which (or how many)
// tokens exist.
func (c Config) inviteAccepted(token string) bool {
	ok := 0
	for _, t := range c.InviteTokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(t)) == 1 {
			ok = 1
		}
	}
	return ok == 1 && token != ""
}

type Server struct {
	store *Store
	cfg   Config
	// Four limiters with four keys: unauth routes by peer address (no identity yet),
	// authed routes by device id (tokens are the identity; a NAT'd office must not
	// share a bucket), GC by owner (its planning cost scales with the owner's whole
	// object table, so it gets a far smaller budget), and the public object-read by
	// peer address but far looser than unauth (a bulk download would trip the 1-rps
	// brute-force bucket).
	limiter       *ipRateLimiter
	authLimiter   *ipRateLimiter
	gcLimiter     *ipRateLimiter
	publicLimiter *ipRateLimiter
	metrics       *Metrics
	ready         atomic.Bool
	workers       sync.WaitGroup
	accountLimits *keyedMutex
}

func NewWithConfig(store *Store, cfg Config) *Server {
	rps, burst := cfg.AuthedRatePerSec, cfg.AuthedBurst
	if rps <= 0 {
		rps = authedRatePerSec
	}
	if burst <= 0 {
		burst = authedBurst
	}
	s := &Server{
		store:         store,
		cfg:           cfg,
		limiter:       newIPRateLimiter(unauthRatePerSec, unauthBurst),
		authLimiter:   newIPRateLimiter(rps, burst),
		gcLimiter:     newIPRateLimiter(gcRatePerSec, gcBurst),
		publicLimiter: newIPRateLimiter(publicObjectsRatePerSec, publicObjectsBurst),
		metrics:       newMetrics(store),
		accountLimits: newKeyedMutex(),
	}
	s.ready.Store(true)
	return s
}

// BeginShutdown makes readiness fail before listeners begin draining.
func (s *Server) BeginShutdown() { s.ready.Store(false) }

func (s *Server) WaitWorkers(ctx context.Context) error {
	done := make(chan struct{})
	go func() { s.workers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Per-route request-body caps, each matched to what its route legitimately carries.
// A small JSON control request, a chunk batch, and a folder's whole sealed manifest
// are unrelated concerns; one shared cap would make the tightest reasonable limit for
// any of them a structural ceiling for the rest.
//
// A folder large enough to exceed maxResourceBody (hundreds of thousands of entries)
// needs a segmented manifest, which does not exist yet.
const (
	maxControlBody  = 64 << 10         // 64 KiB: account/auth/visibility — a few small fields
	maxChunkBody    = 32 << 20         // 32 MiB: a check/locate id list (client batches well under this)
	maxPackBody     = api.MaxPackBytes // one raw pack; the client builders bound themselves by the same constant
	maxResourceBody = 64 << 20         // 64 MiB: a file's ciphertext or a folder's sealed manifest
)

// Router builds the Gin engine with all routes mounted.
func (s *Server) Router() *gin.Engine {
	r := gin.New()
	// An API has no reason to 301 between /x and /x/. With the redirect on, a request
	// for /v1/resources/ (an empty resource id) lands on the authed list endpoint and
	// returns a 200 whose body the caller then misparses; a plain 404 is the honest
	// answer and maps to the client's not-found message.
	r.RedirectTrailingSlash = false
	// Trust only the configured reverse proxies for X-Forwarded-*. Without a call to
	// SetTrustedProxies gin trusts every proxy, so an attacker could spoof
	// X-Forwarded-Proto/For; the aqt-server binary always sets a list (loopback when
	// AQT_TRUSTED_PROXIES is unset). The rate-limit bucket key deliberately stays on the
	// TCP peer regardless. An explicit empty list trusts none.
	if s.cfg.trustedProxiesSet {
		if err := r.SetTrustedProxies(s.cfg.TrustedProxies); err != nil {
			log.Printf("trusted proxies: %v", err)
		}
	}
	// The engine-wide cap is the loosest; stacked limiters apply the smallest, so
	// per-route middleware below only tightens it (a forgotten route is still
	// bounded, never unlimited).
	r.Use(gin.Recovery(), s.metrics.middleware, limitBody(maxResourceBody))

	// Liveness probe for load balancers, container HEALTHCHECKs, and systemd. It
	// reads no state and needs no auth, so it stays cheap and can be hit before a
	// device token exists (e.g. a deploy readiness check).
	r.GET("/livez", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/readyz", func(c *gin.Context) {
		if !s.ready.Load() || s.store.Ping() != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Human-facing landing page for a public share link. Its pinned crypto assets
	// decrypt inline files in the browser; the content key remains in the URL
	// fragment, which never reaches the server.
	r.GET("/x-assets/:name", s.handleShareAsset)
	r.GET("/x/:id", s.handleShareView)

	v1 := r.Group("/v1")
	{
		// Unauthenticated account/auth routes are rate-limited per client: they are
		// the surface for brute-force, account enumeration, and challenge-table
		// pumping.
		unauth := v1.Group("", s.limiter.middleware, limitBody(maxControlBody))
		{
			unauth.POST("/account", s.handleCreateAccount)
			unauth.GET("/account/salt", s.handleAccountSalt)
			unauth.POST("/auth/challenge", s.handleAuthChallenge)
			unauth.POST("/devices", s.handleAttachDevice)
		}

		// Public resource reads need no auth; the id is unguessable and the
		// decrypt key lives only in the caller's URL fragment.
		v1.GET("/resources/:id", s.handleGetResource)
		v1.GET("/public/resources/:id/preflight", s.handlePublicResourcePreflight)

		// Public object read for a streamed (large) share: a link holder has the
		// content key (URL fragment) but object fetch is otherwise owner-scoped. Gated
		// per resource — it serves only a public resource's own referenced objects, and
		// as EXACT per-object slices, never raw pack ranges: a pack interleaves many
		// resources, so the client's span coalescing on raw ranges could leak a private
		// neighbor's gap bytes. Its own limiter, far looser than the unauth bucket,
		// which is tuned for auth brute force and would strangle a bulk download.
		v1.POST("/public/resources/:id/objects", s.publicLimiter.middleware, limitBody(maxChunkBody), s.handlePublicObjects)

		// gzipJSON rides the authed group: it compresses the hex-id JSON of
		// check/locate/list, and its Content-Type guard leaves the raw pack/blob
		// bodies (octet-stream) uncompressed. The public GET /resources/:id sits
		// outside this group, so a raw blob download is never buffered for gzip.
		// authMiddleware sets the device id and owner on the context; the auth limiter
		// then buckets per device token. A NAT'd office shares a peer address but not a
		// token, so it is not throttled as one client.
		authed := v1.Group("", s.authMiddleware, gzipJSON(), s.authLimiter.middlewareKeyed(deviceKey))
		{
			// The blob (a file's ciphertext or a folder's sealed manifest) is the one
			// large payload; it keeps the engine-wide maxResourceBody.
			// POST creates a resource (server-assigned id); PUT replaces the one its
			// envelope names. The single handler dispatches on the id, and refuses a PUT
			// that carries none.
			authed.POST("/resources", s.handlePutResource)
			authed.PUT("/resources", s.handlePutResource)
			authed.GET("/resources", s.handleListResources)
			authed.PUT("/resources/:id/metadata", limitBody(maxControlBody), s.handleUpdateResourceMetadata)
			// Visibility flips and grants take the chunk-size body cap, not the control
			// cap: on a client-GC account they may carry the resource's full ChunkRefs
			// to refresh the read scope they mint.
			authed.POST("/resources/:id/visibility", limitBody(maxChunkBody), s.handleSetVisibility)
			authed.DELETE("/resources/:id", s.handleDeleteResource)

			// Device management. Attach (POST /devices) is unauthenticated above
			// (it is how a new device proves itself); listing and revoking require
			// an existing device's token.
			authed.GET("/devices", s.handleListDevices)
			authed.DELETE("/devices/:id", s.handleDeleteDevice)

			// Re-wrap the account's root key under a new passphrase: a small body
			// (KDF params + a wrapped key + verifiers), so it keeps the control cap.
			// Root-key rotation does not — its body carries every re-wrapped
			// resource, snapshot, and grant key, so it needs the engine-wide cap.
			authed.PUT("/account/passphrase", limitBody(maxControlBody), s.handleChangePassphrase)
			authed.PUT("/account/root-key", s.handleRotateRootKey)

			// Storage summary for the calling account: pack bytes against quota plus
			// row counts. All plaintext-side metadata the owner already implies.
			authed.GET("/account/usage", s.handleAccountUsage)

			// Self-service erasure. The body carries only the passphrase proof, so it
			// keeps the control cap.
			authed.DELETE("/account", limitBody(maxControlBody), s.handleDeleteAccount)

			// Account-to-account grants. The key lookup answers unknown emails with a
			// deterministic decoy (like /account/salt), so it is not an existence
			// oracle; it still sits behind auth to keep probing costed. Grant rows are
			// client-sealed HPKE wraps the server stores opaquely. The grant object
			// read reuses the public endpoint's exact-slice framing with a grant check
			// in place of public visibility; it shares the chunk body cap.
			authed.GET("/account/keys", s.handleAccountKeys)
			authed.POST("/resources/:id/grants", limitBody(maxChunkBody), s.handleCreateGrant)
			authed.GET("/resources/:id/grants", s.handleListResourceGrants)
			authed.DELETE("/resources/:id/grants/:grantee", s.handleDeleteGrant)
			authed.GET("/shares", s.handleListShares)
			// The grantee side of revocation: the delete predicate is the caller's own
			// grantee handle, and an optional block keeps the grantor from re-adding the
			// row. Blocks live on their own path rather than under /shares/, whose :id
			// wildcard would collide with a static segment.
			authed.DELETE("/shares/:id", s.handleDeleteShare)
			authed.GET("/share-blocks", s.handleListShareBlocks)
			authed.DELETE("/share-blocks/:owner", s.handleDeleteShareBlock)
			authed.POST("/resources/:id/objects", limitBody(maxChunkBody), s.handleGrantObjects)

			// Folder-sync packed object store: opaque, content-addressed,
			// owner-scoped. Objects ship inside raw packs; check/locate negotiate
			// which objects to up/download by id.
			authed.POST("/chunks/check", limitBody(maxChunkBody), s.handleCheckChunks)
			authed.POST("/chunks/locate", limitBody(maxChunkBody), s.handleLocateChunks)
			authed.PUT("/packs/:id", limitBody(maxPackBody), s.handlePutPack)
			authed.GET("/packs/:id", s.handleGetPack)
			// GC is expensive (its planning scans the owner's object table), so it gets a
			// second, owner-keyed limiter far tighter than the general authed budget.
			authed.POST("/gc", s.gcLimiter.middlewareKeyed(ownerKey), s.handleRunGC)
			// Client-managed GC: a prune reads the full object inventory, diffs it
			// against the closure of its decrypted roots, and deletes the remainder.
			// Unlike POST /gc these are bounded per request (one indexed page, one
			// capped batch), so the general authed limiter is the right budget — the
			// gcLimiter's drip-rate would stretch a large account's prune into minutes.
			authed.GET("/chunks", s.handleListChunks)
			authed.POST("/chunks/delete", limitBody(maxChunkBody), s.handleDeleteChunks)

			// Snapshots: immutable, GC-pinned copies of a resource version. Owner-only;
			// a snapshot is never public, so unlike a resource there is no unauth read.
			authed.POST("/snapshots", limitBody(maxControlBody), s.handleCreateSnapshot)
			authed.GET("/snapshots", s.handleListSnapshots)
			authed.GET("/snapshots/:id", s.handleGetSnapshot)
			authed.POST("/snapshots/:id/anchor", limitBody(maxControlBody), s.handleSetSnapshotAnchor)
			authed.DELETE("/snapshots/:id", s.handleDeleteSnapshot)
			authed.POST("/resources/:id/auto-snapshot", limitBody(maxControlBody), s.handleSetAutoSnapshot)
		}
	}
	return r
}

// limitBody caps a route's request body at n bytes. Stacked limiters apply the
// smallest cap (each wraps the previous reader), so the engine-wide cap is the
// loosest and per-route middleware only tightens it.
func limitBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}

// --- auth ---

const (
	ownerContextKey  = "ownerHandle"
	deviceContextKey = "deviceId"
)

func (s *Server) authMiddleware(c *gin.Context) {
	token, ok := bearerToken(c)
	if !ok {
		abort(c, http.StatusUnauthorized, "missing bearer token")
		return
	}
	owner, deviceID, err := s.store.AuthByToken(token)
	if errors.Is(err, ErrNotFound) {
		// Either an unknown token or one issued before a passphrase change bumped the
		// account epoch; both mean "re-authenticate".
		abort(c, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	if errors.Is(err, ErrAccountDisabled) {
		// 403, not 401: the credential is valid and re-authenticating would send the
		// user in a circle. Only the operator can lift this.
		abortCode(c, http.StatusForbidden, ErrAccountDisabled.Error(), api.ErrCodeAccountDisabled)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "auth lookup failed")
		return
	}
	c.Set(ownerContextKey, owner)
	c.Set(deviceContextKey, deviceID)
	c.Next()
}

func bearerToken(c *gin.Context) (string, bool) {
	h := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}

// --- account limits ---

// effectiveQuota resolves the byte cap for one account: its operator-set override
// when present, otherwise the server-wide default. 0 means unlimited. A missing
// override is the common case, so this is one indexed read on an already-locked
// path, not a second usage walk.
func (s *Server) effectiveQuota(owner string) (int64, error) {
	override, err := s.store.AccountQuota(owner)
	if err != nil {
		return 0, err
	}
	if override.Valid {
		return override.Int64, nil
	}
	return s.cfg.QuotaBytes, nil
}

// checkAccountLimit refuses a write that would push the account past its byte quota
// or past the row cap for kind ("resources", "snapshots", "objects"). An empty kind
// checks bytes only, for a write that replaces an existing row rather than adding one.
func (s *Server) checkAccountLimit(owner, kind string, addedBytes int64) error {
	quota, err := s.effectiveQuota(owner)
	if err != nil {
		return err
	}
	var limit int64
	switch kind {
	case "resources":
		limit = int64(s.cfg.MaxResources)
	case "snapshots":
		limit = int64(s.cfg.MaxSnapshots)
	case "objects":
		limit = int64(s.cfg.MaxObjects)
	}
	// With no quota and no row cap configured there is nothing to enforce; skip the
	// usage scan, which sums every owner-scoped table and runs under the per-owner
	// lock on every quota-checked write.
	if quota <= 0 && limit <= 0 {
		return nil
	}
	u, err := s.store.AccountUsage(owner)
	if err != nil {
		return err
	}
	if quota > 0 && u.StorageBytes+addedBytes > quota {
		return &LimitExceededError{Kind: "storageBytes", Current: u.StorageBytes, Limit: quota}
	}
	var current int64
	switch kind {
	case "resources":
		current = u.Resources
	case "snapshots":
		current = u.Snapshots
	case "objects":
		current = u.Objects
	}
	if limit > 0 && current >= limit {
		return &LimitExceededError{Kind: kind, Current: current, Limit: limit}
	}
	return nil
}

func abortLimit(c *gin.Context, err error) bool {
	var limit *LimitExceededError
	if !errors.As(err, &limit) {
		return false
	}
	c.AbortWithStatusJSON(http.StatusInsufficientStorage, api.ErrorResponse{Error: "account limit exceeded; free space or raise the configured limit", Code: api.ErrCodeQuotaExceeded, LimitKind: limit.Kind, Current: limit.Current, Limit: limit.Limit})
	return true
}

func estimatedResourceBytes(req api.PutResourceRequest) int64 {
	b, _ := json.Marshal(req.EncryptedMeta)
	w, _ := json.Marshal(req.WrappedKey)
	return int64(len(req.Blob.Ciphertext) + len(req.Blob.Nonce) + len(b) + len(w) + 256)
}

// --- background workers ---

// StartAutoSnapshot runs the scheduled snapshot job every interval until stop is
// closed (a non-positive interval disables it). A snapshot is keyless — the server
// copies already-sealed ciphertext — so the job needs no client online; version
// dedup keeps a tick that finds no changes nearly free. keepLast caps how many
// scheduled snapshots each resource retains (0 keeps all; manual snapshots are
// never pruned).
func (s *Server) StartAutoSnapshot(interval time.Duration, keepLast int, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	s.workers.Add(1)
	go func() {
		defer t.Stop()
		defer s.workers.Done()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if n, err := s.store.RunAutoSnapshotsWithLimits(s.cfg.MaxSnapshots, s.cfg.QuotaBytes); err != nil {
					log.Printf("auto-snapshot: %v", err)
				} else if n > 0 {
					log.Printf("auto-snapshot: created %d snapshot(s)", n)
				}
				if n, err := s.store.PruneAutoSnapshots(keepLast); err != nil {
					log.Printf("auto-snapshot prune: %v", err)
				} else if n > 0 {
					log.Printf("auto-snapshot: pruned %d snapshot(s)", n)
				}
			}
		}
	}()
}

// StartGC runs the scheduled GC sweep every interval until stop is closed (a
// non-positive interval disables it). Client-triggered POST /v1/gc stays available
// as a manual path, but reclamation does not depend on a device syncing: an
// account whose devices go quiet still gets its dead packs swept. Both paths use
// the same age guard, and the store's per-owner lock serializes them if they
// collide.
func (s *Server) StartGC(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	s.workers.Add(1)
	go func() {
		defer t.Stop()
		defer s.workers.Done()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				res, err := s.store.RunGCAll(gcMinAge)
				if err != nil {
					log.Printf("scheduled gc: %v", err)
					continue
				}
				s.metrics.observeGC("scheduled", res)
				if res.DeletedPacks > 0 || res.RepackedPacks > 0 {
					log.Printf("scheduled gc: swept %d pack(s) / %d bytes, repacked %d / %d bytes",
						res.DeletedPacks, res.FreedBytes, res.RepackedPacks, res.ReclaimedBytes)
				}
			}
		}
	}()
}

// --- helpers ---

func bindJSON(c *gin.Context, v any) bool {
	if err := c.ShouldBindJSON(v); err != nil {
		abort(c, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// abort answers with the status-bucket Code for its HTTP status, so every error
// response carries a machine-readable code. Handlers use it for conditions where
// the status is the whole distinction a client needs; a condition a client
// branches on more finely goes through abortCode with a condition code.
func abort(c *gin.Context, code int, msg string) {
	abortCode(c, code, msg, statusErrCode(code))
}

// statusErrCode maps an HTTP status to its bucket code. Statuses that always
// carry a condition code (404, 409, 410, 426, 429, 507) never reach here; an
// unlisted status falls back by class so no response can ship without a code.
func statusErrCode(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return api.ErrCodeUnauthorized
	case http.StatusForbidden:
		return api.ErrCodeForbidden
	case http.StatusNotAcceptable:
		return api.ErrCodeNotAcceptable
	case http.StatusRequestEntityTooLarge:
		return api.ErrCodePayloadTooLarge
	case http.StatusUnsupportedMediaType:
		return api.ErrCodeUnsupportedMedia
	}
	if status >= 500 {
		return api.ErrCodeInternal
	}
	return api.ErrCodeInvalidRequest
}

// abortCode answers with a condition-specific Code, so a client can branch on the
// condition without string-matching the message. The message stays a fixed,
// user-facing string — never a raw Go error, which may carry internal detail.
func abortCode(c *gin.Context, code int, msg, errCode string) {
	c.AbortWithStatusJSON(code, api.ErrorResponse{Error: msg, Code: errCode})
}

// abortNotFound answers the canonical 404 with the not_found code. A missing or
// foreign-owned resource, device, snapshot, or grant all reduce to this: the store
// returns ErrNotFound for a foreign owner too, so the code reveals nothing an
// unauthorized caller could not already infer from the status.
func abortNotFound(c *gin.Context) {
	abortCode(c, http.StatusNotFound, "not found", api.ErrCodeNotFound)
}

// requestCapability fails closed for a caller that announces nothing — a bare curl
// of a public link, or any tool that is not aqt. Reading absent or malformed values
// as baseline gates such a request at the format boundary, before any encrypted
// payload is served, instead of handing it ciphertext that fails at AEAD open.
func requestCapability(c *gin.Context) int {
	v := c.GetHeader(api.CapabilityHeader)
	n, err := strconv.Atoi(v)
	if err != nil || n < api.CapabilityBaseline {
		return api.CapabilityBaseline
	}
	return n
}

// abortUpgradeRequired answers 426 with the structured upgrade error. The message is
// self-contained because the client quotes the server prose verbatim ("server said:
// %s") and hand-rolled requests see only the body, so it must explain the mismatch on
// its own. need is the capability the resource requires; have is what the requester
// declared.
func abortUpgradeRequired(c *gin.Context, need, have int) {
	c.AbortWithStatusJSON(http.StatusUpgradeRequired, api.ErrorResponse{
		Error:     fmt.Sprintf("resource requires client capability %d or newer (this client supports %d): upgrade aqt", need, have),
		Code:      api.ErrCodeUpgradeRequired,
		MinClient: need,
	})
}

// abortGone answers 410 for an expired, exhausted, or reclaimed public link. The Code
// is stable so the client maps it to a distinct exit status.
func abortGone(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusGone, api.ErrorResponse{
		Error: "link expired or read limit reached",
		Code:  api.ErrCodeGone,
	})
}

func parseIfMatch(c *gin.Context) (int, bool) {
	raw := strings.TrimSpace(c.GetHeader("If-Match"))
	if raw == "" {
		return 0, true
	}
	if len(raw) >= 2 && strings.HasPrefix(raw, "\"") && strings.HasSuffix(raw, "\"") {
		raw = raw[1 : len(raw)-1]
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		abort(c, http.StatusBadRequest, "If-Match must contain a positive resource version")
		return 0, false
	}
	return n, true
}

// decoyStream derives one decoy field deterministically from the server secret, so
// repeated lookups for the same email return the same decoy. The email must already
// be normalized: real accounts answer any casing of their address, so a decoy that
// varied by case would out an email as unregistered. decoyBootstrap normalizes it
// itself; decoyAccountKeys takes it normalized from its caller.
func (s *Server) decoyStream(secret []byte, email, label string, n int) []byte {
	out, err := hkdf.Key(sha256.New, secret, []byte(email), label, n)
	if err != nil {
		panic("hkdf decoy: " + err.Error()) // unreachable: every decoy field is a fixed, short length
	}
	return out
}
