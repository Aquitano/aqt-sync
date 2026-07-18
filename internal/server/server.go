// Package server implements aqt's zero-knowledge HTTP API on top of Gin. Every
// payload it handles is opaque ciphertext or key material it cannot read.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/hkdf"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// RegistrationMode selects how POST /v1/account handles a new signup.
type RegistrationMode string

const (
	// RegistrationOpen (the default) lets anyone sign up. A signup for an email that
	// already has an account returns the same success shape as a fresh one instead of
	// a 409, so the endpoint is no longer an existence oracle; the duplicate creates
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

func New(store *Store) *Server { return NewWithConfig(store, Config{}) }

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

// Per-route request-body caps. A single global cap previously coupled three
// unrelated concerns — a small JSON control request, a chunk batch, and a folder's
// whole sealed manifest — so the tightest reasonable limit for one became a
// structural ceiling for the others (A2). Each route now gets a cap matched to
// what it legitimately carries.
//
// A folder large enough to exceed maxResourceBody (hundreds of thousands of
// entries) still needs a segmented manifest; that is the remaining half of A2.
const (
	maxControlBody  = 64 << 10 // 64 KiB: account/auth/visibility — a few small fields
	maxChunkBody    = 32 << 20 // 32 MiB: a check/locate id list (client batches well under this)
	maxPackBody     = 32 << 20 // 32 MiB: one raw pack (client targets ~16 MiB, headroom for the index)
	maxResourceBody = 64 << 20 // 64 MiB: a file's ciphertext or a folder's sealed manifest
)

// Router builds the Gin engine with all routes mounted.
func (s *Server) Router() *gin.Engine {
	r := gin.New()
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
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
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
	r.GET("/x-assets/:name", s.shareAsset)
	r.GET("/x/:id", s.shareView)

	v1 := r.Group("/v1")
	{
		// Unauthenticated account/auth routes are rate-limited per client: they are
		// the surface for brute-force, account enumeration, and challenge-table
		// pumping.
		unauth := v1.Group("", s.limiter.middleware, limitBody(maxControlBody))
		{
			unauth.POST("/account", s.createAccount)
			unauth.GET("/account/salt", s.accountSalt)
			unauth.POST("/auth/challenge", s.authChallenge)
			unauth.POST("/devices", s.attachDevice)
		}

		// Public resource reads need no auth; the id is unguessable and the
		// decrypt key lives only in the caller's URL fragment.
		v1.GET("/resources/:id", s.getResource)
		v1.GET("/public/resources/:id/preflight", s.publicResourcePreflight)

		// Public object read for a streamed (large) share: a link holder has the
		// content key (URL fragment) but object fetch is otherwise owner-scoped. Gated
		// per resource — it serves only a public resource's own referenced objects, and
		// as EXACT per-object slices, never raw pack ranges: a pack interleaves many
		// resources, so the client's span coalescing on raw ranges could leak a private
		// neighbor's gap bytes. Its own limiter, far looser than the unauth bucket,
		// which is tuned for auth brute force and would strangle a bulk download.
		v1.POST("/public/resources/:id/objects", s.publicLimiter.middleware, limitBody(maxChunkBody), s.publicObjects)

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
			// POST creates a resource (server-assigned id); PUT replaces one in place.
			// The single handler dispatches on whether the request carries an id, and the
			// legacy PUT-create path stays wired so an older client keeps working.
			authed.POST("/resources", s.putResource)
			authed.PUT("/resources", s.putResource)
			authed.GET("/resources", s.listResources)
			authed.PUT("/resources/:id/metadata", limitBody(maxControlBody), s.updateResourceMetadata)
			authed.POST("/resources/:id/visibility", limitBody(maxControlBody), s.setVisibility)
			authed.DELETE("/resources/:id", s.deleteResource)

			// Device management. Attach (POST /devices) is unauthenticated above
			// (it is how a new device proves itself); listing and revoking require
			// an existing device's token.
			authed.GET("/devices", s.listDevices)
			authed.DELETE("/devices/:id", s.deleteDevice)

			// Re-wrap the account's root key under a new passphrase. Small body
			// (KDF params + a wrapped key + verifiers), so it keeps the control cap.
			authed.PUT("/account/passphrase", limitBody(maxControlBody), s.changePassphrase)
			authed.PUT("/account/root-key", s.rotateRootKey)

			// Storage summary for the calling account: pack bytes against quota plus
			// row counts. All plaintext-side metadata the owner already implies.
			authed.GET("/account/usage", s.accountUsage)

			// Account-to-account grants. The key lookup answers unknown emails with a
			// deterministic decoy (like /account/salt), so it is not an existence
			// oracle; it still sits behind auth to keep probing costed. Grant rows are
			// client-sealed HPKE wraps the server stores opaquely. The grant object
			// read reuses the public endpoint's exact-slice framing with a grant check
			// in place of public visibility; it shares the chunk body cap.
			authed.GET("/account/keys", s.accountKeys)
			authed.PUT("/account/enc-key", limitBody(maxControlBody), s.publishEncKey)
			authed.POST("/resources/:id/grants", limitBody(maxControlBody), s.createGrant)
			authed.GET("/resources/:id/grants", s.listResourceGrants)
			authed.DELETE("/resources/:id/grants/:grantee", s.deleteGrant)
			authed.GET("/shares", s.listShares)
			authed.POST("/resources/:id/objects", limitBody(maxChunkBody), s.grantObjects)

			// Folder-sync packed object store: opaque, content-addressed,
			// owner-scoped. Objects ship inside raw packs; check/locate negotiate
			// which objects to up/download by id.
			authed.POST("/chunks/check", limitBody(maxChunkBody), s.checkChunks)
			authed.POST("/chunks/locate", limitBody(maxChunkBody), s.locateChunks)
			authed.PUT("/packs/:id", limitBody(maxPackBody), s.putPack)
			authed.GET("/packs/:id", s.getPack)
			// GC is expensive (its planning scans the owner's object table), so it gets a
			// second, owner-keyed limiter far tighter than the general authed budget.
			authed.POST("/gc", s.gcLimiter.middlewareKeyed(ownerKey), s.runGC)

			// Snapshots: immutable, GC-pinned copies of a resource version. Owner-only;
			// a snapshot is never public, so unlike a resource there is no unauth read.
			authed.POST("/snapshots", limitBody(maxControlBody), s.createSnapshot)
			authed.GET("/snapshots", s.listSnapshots)
			authed.GET("/snapshots/:id", s.getSnapshot)
			authed.POST("/snapshots/:id/anchor", limitBody(maxControlBody), s.setSnapshotAnchor)
			authed.DELETE("/snapshots/:id", s.deleteSnapshot)
			authed.POST("/resources/:id/auto-snapshot", limitBody(maxControlBody), s.setAutoSnapshot)
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

// --- account & device handlers ---

func (s *Server) createAccount(c *gin.Context) {
	var req api.CreateAccountRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.Email == "" || len(req.PublicKey) != ed25519.PublicKeySize {
		abort(c, http.StatusBadRequest, "email and a valid public key are required")
		return
	}
	if len(req.WrappedRoot.Ciphertext) == 0 || len(req.AuthVerifier) == 0 {
		abort(c, http.StatusBadRequest, "wrapped root and auth verifier are required")
		return
	}
	// Invite mode gates every signup on a server-issued token, so an attacker cannot
	// register (and thereby squat) an unclaimed email. The response is uniform whether
	// the token is missing or wrong, so it leaks nothing about the token set.
	if s.cfg.Registration == RegistrationInvite && !s.cfg.inviteAccepted(req.InviteToken) {
		abort(c, http.StatusForbidden, "a valid invite token is required to register on this server")
		return
	}
	// The enc key is optional (pre-grants clients omit it) but if present its
	// identity self-signature must verify, or a bad key would poison future grants.
	if len(req.EncPublicKey) > 0 {
		if len(req.EncPublicKey) != crypto.EncPublicKeySize ||
			!crypto.VerifyEncKey(req.PublicKey, req.EncPublicKey, req.EncKeySig) {
			abort(c, http.StatusBadRequest, "enc public key must be 32 bytes and self-signed by the identity key")
			return
		}
	}
	acc, err := s.store.CreateAccount(req.Email, req.Kdf, req.PublicKey, req.WrappedRoot, req.AuthVerifier, req.EncPublicKey, req.EncKeySig)
	if errors.Is(err, ErrConflict) {
		// A duplicate email must not answer differently from a fresh signup, or the
		// endpoint becomes an existence oracle. Return the same 201 success shape with a
		// decoy token that grants nothing: the caller's next authenticated call fails,
		// indistinguishable from the wrong-passphrase path. The existing account is
		// untouched — the duplicate creates no device on it.
		c.JSON(http.StatusCreated, s.decoyAuthResponse())
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "create account failed")
		return
	}
	deviceID, token, err := s.store.CreateDevice(acc.OwnerHandle, deviceName(req.DeviceName), 1, s.cfg.MaxDevices)
	if err != nil {
		abort(c, http.StatusInternalServerError, "create device failed")
		return
	}
	c.JSON(http.StatusCreated, api.AuthResponse{
		OwnerHandle: acc.OwnerHandle, DeviceID: deviceID, Token: token, Epoch: 1,
	})
}

// decoyAuthResponse builds a success-shaped auth response whose fields match a real
// one's lengths but authenticate nothing. It backs the enumeration-safe duplicate
// signup path: the handle/device/token are random, so the response is
// indistinguishable on the wire from a genuine account creation.
func (s *Server) decoyAuthResponse() api.AuthResponse {
	return api.AuthResponse{
		OwnerHandle: newID(12),
		DeviceID:    newID(10),
		Token:       newID(32),
		Epoch:       1,
	}
}

// accountSalt is the new-device bootstrap: it returns the KDF params and wrapped
// root key for an email. An unknown email gets a deterministic decoy (200, not 404)
// so the endpoint does not reveal which emails have accounts; only someone who knows
// the passphrase can tell a decoy from a real account (the decoy never unwraps).
func (s *Server) accountSalt(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		abort(c, http.StatusBadRequest, "email query param required")
		return
	}
	acc, err := s.store.AccountByEmail(email)
	if errors.Is(err, ErrNotFound) {
		decoy, derr := s.decoyBootstrap(email)
		if derr != nil {
			abort(c, http.StatusInternalServerError, "lookup failed")
			return
		}
		c.JSON(http.StatusOK, decoy)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	c.JSON(http.StatusOK, api.SaltResponse{Kdf: acc.Kdf, WrappedRoot: acc.WrappedRoot})
}

// decoyBootstrap synthesizes a bootstrap response for an unknown email,
// deterministically from the server secret so the same email always yields the same
// decoy. The salt and wrapped-root bytes are indistinguishable from a real account's
// to anyone without the passphrase, so a registered and an unregistered email look
// identical on the wire.
func (s *Server) decoyBootstrap(email string) (api.SaltResponse, error) {
	secret, err := s.store.ServerSecret()
	if err != nil {
		return api.SaltResponse{}, err
	}
	stream := func(label string, n int) []byte {
		out := make([]byte, n)
		r := hkdf.New(sha256.New, secret, []byte(email), []byte(label))
		if _, err := io.ReadFull(r, out); err != nil {
			panic("hkdf decoy: " + err.Error()) // unreachable for an in-memory reader
		}
		return out
	}
	// Derive the decoy's Argon2id costs from the same value set a real moderate
	// calibration produces, seeded deterministically per email. The package-default
	// (3, 64 MiB, 4) marked every decoy identically; drawing from the realistic
	// distribution instead means a decoy's params are indistinguishable from a
	// calibrated account's.
	timeCost, memoryKiB, threads := crypto.DecoyKdfCosts(stream("aqt-decoy-costs", 2))
	def, err := crypto.ManualKdfParams(timeCost, memoryKiB, threads)
	if err != nil {
		return api.SaltResponse{}, err
	}
	def.Salt = stream("aqt-decoy-salt", len(def.Salt))
	// A real wrapped root is a 32-byte key sealed with XChaCha20-Poly1305: a 24-byte
	// nonce and 48 bytes of ciphertext+tag. Match those lengths exactly.
	return api.SaltResponse{
		Kdf: def,
		WrappedRoot: crypto.SealedBlob{
			Nonce:      stream("aqt-decoy-nonce", crypto.NonceSize),
			Ciphertext: stream("aqt-decoy-ct", crypto.KeySize+16),
		},
	}, nil
}

func (s *Server) authChallenge(c *gin.Context) {
	var req api.ChallengeRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.Email == "" {
		abort(c, http.StatusBadRequest, "email required")
		return
	}
	id, nonce, err := s.store.CreateChallenge(req.Email)
	if err != nil {
		abort(c, http.StatusInternalServerError, "challenge failed")
		return
	}
	c.JSON(http.StatusOK, api.ChallengeResponse{ChallengeID: id, Nonce: nonce})
}

func (s *Server) attachDevice(c *gin.Context) {
	var req api.AttachDeviceRequest
	if !bindJSON(c, &req) {
		return
	}
	// Consume the challenge first so a bad attempt can't be replayed against it.
	nonce, err := s.store.ConsumeChallenge(req.ChallengeID, req.Email)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusUnauthorized, "invalid or expired challenge")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "challenge lookup failed")
		return
	}
	owner, pub, verifierHash, epoch, err := s.store.AccountForAuth(req.Email)
	// Attaching needs both the signing key (proves the master key) and the passphrase
	// verifier (proves the current passphrase), so a stale passphrase or a cached
	// master key alone cannot attach. A missing account, a bad signature, and a bad
	// verifier all return the same 401: no oracle.
	sigOK := err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, nonce, req.Signature)
	verifierOK := err == nil && verifierMatches(req.AuthVerifier, verifierHash)
	if sigOK && verifierOK {
		deviceID, token, err := s.store.CreateDevice(owner, deviceName(req.DeviceName), epoch, s.cfg.MaxDevices)
		if errors.Is(err, ErrDeviceLimit) {
			u, _ := s.store.AccountUsage(owner)
			c.AbortWithStatusJSON(http.StatusForbidden, api.ErrorResponse{Error: "device limit reached; revoke a device before attaching another", Code: api.ErrCodeDeviceLimit, LimitKind: "devices", Current: u.Devices, Limit: int64(s.cfg.MaxDevices)})
			return
		}
		if err != nil {
			abort(c, http.StatusInternalServerError, "create device failed")
			return
		}
		c.JSON(http.StatusCreated, api.AuthResponse{OwnerHandle: owner, DeviceID: deviceID, Token: token, Epoch: epoch})
		return
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		abort(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	abort(c, http.StatusUnauthorized, "invalid credentials")
}

// verifierMatches reports whether the presented auth verifier hashes to the stored
// hash, in constant time.
func verifierMatches(verifier, storedHash []byte) bool {
	if len(verifier) == 0 || len(storedHash) != sha256.Size {
		return false
	}
	h := sha256.Sum256(verifier)
	return subtle.ConstantTimeCompare(h[:], storedHash) == 1
}

// changePassphrase re-wraps the account's root key under a new passphrase. The store
// verifies the caller knows the current passphrase and bumps the account epoch, so
// every other device's token stops authenticating (they re-login with the new
// passphrase); the calling device keeps working.
func (s *Server) changePassphrase(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	deviceID := c.GetString(deviceContextKey)
	var req api.PassphraseChangeRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.WrappedRoot.Ciphertext) == 0 || len(req.OldAuthVerifier) == 0 || len(req.NewAuthVerifier) == 0 {
		abort(c, http.StatusBadRequest, "wrapped root and both verifiers are required")
		return
	}
	newEpoch, err := s.store.ChangePassphrase(owner, deviceID, req.Kdf, req.WrappedRoot, req.OldAuthVerifier, req.NewAuthVerifier, req.ExpectedEpoch)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusForbidden, "current passphrase proof did not match")
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "the passphrase changed on another device; re-run with the current one", api.ErrCodeVersionConflict)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "passphrase change failed")
		return
	}
	// The calling device's token is unchanged (its epoch was advanced with the
	// account's), so no new token is issued; the client keeps using it.
	c.JSON(http.StatusOK, api.AuthResponse{OwnerHandle: owner, DeviceID: deviceID, Epoch: newEpoch})
}

// rotateRootKey performs the account-wide recovery operation. It requires the
// current capability because old clients cannot safely recover a post-rotation
// account identity.
func (s *Server) rotateRootKey(c *gin.Context) {
	if requestCapability(c) < api.CapabilityRootKeyRotation {
		abortUpgradeRequired(c, api.CapabilityRootKeyRotation, requestCapability(c))
		return
	}
	owner := c.GetString(ownerContextKey)
	deviceID := c.GetString(deviceContextKey)
	var req api.RootKeyRotationRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.WrappedRoot.Ciphertext) == 0 || len(req.OldAuthVerifier) == 0 || len(req.NewAuthVerifier) == 0 || len(req.PublicKey) != ed25519.PublicKeySize || len(req.EncPublicKey) != crypto.EncPublicKeySize || !crypto.VerifyEncKey(ed25519.PublicKey(req.PublicKey), req.EncPublicKey, req.EncKeySig) {
		abort(c, http.StatusBadRequest, "complete, self-consistent new account identity is required")
		return
	}
	token, epoch, err := s.store.RotateRootKey(owner, deviceID, req)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusForbidden, "current passphrase proof did not match")
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "account or a protected key changed while rotating; re-run root-key rotation", api.ErrCodeVersionConflict)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "root-key rotation failed")
		return
	}
	c.JSON(http.StatusOK, api.AuthResponse{OwnerHandle: owner, DeviceID: deviceID, Token: token, Epoch: epoch})
}

func (s *Server) accountUsage(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	u, err := s.store.AccountUsage(owner)
	if err != nil {
		abort(c, http.StatusInternalServerError, "usage lookup failed")
		return
	}
	c.JSON(http.StatusOK, api.UsageResponse{
		StorageBytes: u.StorageBytes,
		QuotaBytes:   s.cfg.QuotaBytes,
		Packs:        u.Packs,
		Objects:      u.Objects,
		Resources:    u.Resources,
		Snapshots:    u.Snapshots,
		Devices:      u.Devices,
		MaxResources: int64(s.cfg.MaxResources), MaxSnapshots: int64(s.cfg.MaxSnapshots),
		MaxObjects: int64(s.cfg.MaxObjects), MaxDevices: int64(s.cfg.MaxDevices),
	})
}

func (s *Server) checkAccountLimit(owner, kind string, addedBytes int64) error {
	u, err := s.store.AccountUsage(owner)
	if err != nil {
		return err
	}
	if s.cfg.QuotaBytes > 0 && u.StorageBytes+addedBytes > s.cfg.QuotaBytes {
		return &LimitExceededError{Kind: "storageBytes", Current: u.StorageBytes, Limit: s.cfg.QuotaBytes}
	}
	var current, limit int64
	switch kind {
	case "resources":
		current, limit = u.Resources, int64(s.cfg.MaxResources)
	case "snapshots":
		current, limit = u.Snapshots, int64(s.cfg.MaxSnapshots)
	case "objects":
		current, limit = u.Objects, int64(s.cfg.MaxObjects)
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

func (s *Server) listDevices(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	devices, next, err := s.store.ListDevices(owner, page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list devices failed")
		return
	}
	c.JSON(http.StatusOK, api.ListDevicesResponse{Devices: devices, NextCursor: next})
}

func (s *Server) deleteDevice(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	err := s.store.DeleteDevice(owner, c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "delete device failed")
		return
	}
	c.Status(http.StatusNoContent)
}

// --- resource handlers ---

func (s *Server) putResource(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	capability := requestCapability(c)
	req, ok := decodePutResource(c)
	if !ok {
		return
	}
	if key := c.GetHeader("Idempotency-Key"); len(key) > 128 {
		abort(c, http.StatusBadRequest, "Idempotency-Key must be at most 128 bytes")
		return
	} else {
		req.IdempotencyKey = key
	}
	// A client cannot declare content unreadable by itself: that would be a resource
	// it just wrote but could never read back. Reject it as a client bug.
	if req.MinClient > capability {
		abort(c, http.StatusBadRequest, "declared min_client exceeds this client's capability")
		return
	}
	switch req.Visibility {
	case api.Private:
		if req.WrappedKey == nil {
			abort(c, http.StatusBadRequest, "private resource requires a wrapped key")
			return
		}
	case api.Public:
		// A wrapped key is optional and welcome: it is the owner's recovery path
		// (so they can later share/rotate), and GetResource strips it from
		// non-owner reads.
	default:
		abort(c, http.StatusBadRequest, "visibility must be private or public")
		return
	}
	if req.ID == "" {
		defer s.accountLimits.lock(owner)()
		if err := s.checkAccountLimit(owner, "resources", estimatedResourceBytes(req)); err != nil {
			if !abortLimit(c, err) {
				abort(c, http.StatusInternalServerError, "usage lookup failed")
			}
			return
		}
	}
	id, version, err := s.store.PutResource(owner, capability, req)
	var upgrade *UpgradeRequiredError
	if errors.As(err, &upgrade) {
		abortUpgradeRequired(c, upgrade.MinClient, capability)
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; re-sync", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrIdempotencyConflict) {
		abortCode(c, http.StatusConflict, "Idempotency-Key was already used for another request", api.ErrCodeIdempotencyConflict)
		return
	}
	if errors.Is(err, ErrDropsRoots) {
		abortCode(c, http.StatusBadRequest, "replace would drop every chunk root of an object-backed resource; refused to prevent data loss", api.ErrCodeDropsRoots)
		return
	}
	if errors.Is(err, ErrPolicyOnPrivate) || errors.Is(err, ErrBadPolicy) {
		abortCode(c, http.StatusBadRequest, policyErrorMessage(err), api.ErrCodeInvalidPolicy)
		return
	}
	if errors.Is(err, ErrNotFound) {
		// Update targeting an id the caller doesn't own (or that doesn't exist).
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "store failed")
		return
	}
	status := http.StatusCreated
	if req.ID != "" {
		status = http.StatusOK
	}
	expiresAt, maxReads := policyExpiresAt(req), policyMaxReads(req)
	c.JSON(status, api.PutResourceResponse{
		ID: id, Version: version,
		ExpiresAt: expiresAt, MaxReads: maxReads,
		OnExpiry: echoedOnExpiry(req.OnExpiry, expiresAt, maxReads),
	})
}

// policyExpiresAt is the absolute expiry the server just stored, echoed so a new client
// can confirm an old server did not silently drop the policy. It recomputes now + TTL;
// the microsecond drift from the store's own clock is immaterial (the client's sanity
// check tolerates it). Zero unless a policy was accepted on a public resource.
func policyExpiresAt(req api.PutResourceRequest) int64 {
	if req.Visibility == api.Public && req.ExpireSeconds > 0 {
		return time.Now().Unix() + req.ExpireSeconds
	}
	return 0
}

func policyMaxReads(req api.PutResourceRequest) int64 {
	if req.Visibility == api.Public {
		return req.MaxReads
	}
	return 0
}

// echoedOnExpiry reports the end-of-life action the server just stored, so a client that
// asked to retire the link can fail closed against a server that would instead destroy
// the content behind it. A server that predates the field echoes nothing at all, which
// is how the client tells the two apart. Empty when no policy was accepted: there is
// then no end of life to act on.
func echoedOnExpiry(requested api.OnExpiry, expiresAt, maxReads int64) api.OnExpiry {
	if expiresAt == 0 && maxReads == 0 {
		return ""
	}
	if requested == api.ExpiryRetire {
		return api.ExpiryRetire
	}
	return api.ExpiryReclaim
}

func (s *Server) publicResourcePreflight(c *gin.Context) {
	preflight, err := s.store.PublicResourcePreflight(c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if errors.Is(err, ErrGone) {
		abortGone(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "preflight failed")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, preflight)
}

func (s *Server) getResource(c *gin.Context) {
	// An authenticated owner can read their private resources; anyone can read a
	// public one. We pass the owner (empty if unauthenticated) to the store so a
	// private id returns 404 to everyone else.
	var owner string
	if token, ok := bearerToken(c); ok {
		if o, err := s.store.OwnerByToken(token); err == nil {
			owner = o
		}
	}
	res, err := s.store.GetResource(c.Param("id"), owner)
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if errors.Is(err, ErrGone) {
		abortGone(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "fetch failed")
		return
	}
	// Gate the read on the requester's capability before any payload is written: a
	// client too old to open the sealed format gets an actionable 426 instead of the
	// bytes and a downstream AEAD failure. This route is public, so the check lives
	// here rather than in the authed middleware.
	if capability := requestCapability(c); capability < res.MinClient {
		abortUpgradeRequired(c, res.MinClient, capability)
		return
	}
	format, ok := negotiateResourceResponse(c.GetHeader("Accept"))
	if !ok {
		abort(c, http.StatusNotAcceptable, "no acceptable resource representation; request version=1 JSON or envelope media type")
		return
	}
	if format == resourceEnvelope {
		body, err := api.EncodeResourceDownload(res)
		if err != nil {
			abort(c, http.StatusInternalServerError, "encode failed")
			return
		}
		c.Data(http.StatusOK, api.ResourceEnvelopeMediaType, body)
		return
	}
	c.Header("Content-Type", api.ResourceJSONMediaType)
	c.JSON(http.StatusOK, res)
}

// decodePutResource reads a resource upload by content negotiation: an
// octet-stream body is the raw envelope (blob ciphertext single-buffered, never
// JSON-decoded); anything else is the legacy JSON body, so old clients keep
// working. Both paths sit behind the same maxResourceBody cap.
func decodePutResource(c *gin.Context) (api.PutResourceRequest, bool) {
	format, ok := resourceRequestFormat(c.GetHeader("Content-Type"))
	if !ok {
		abort(c, http.StatusUnsupportedMediaType, "unsupported resource Content-Type; send version=1 JSON or envelope media type")
		return api.PutResourceRequest{}, false
	}
	if format == resourceJSON {
		var req api.PutResourceRequest
		if !bindJSON(c, &req) {
			return api.PutResourceRequest{}, false
		}
		return req, true
	}
	req, err := api.DecodeResourceUpload(c.Request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			abort(c, http.StatusRequestEntityTooLarge, "resource body exceeds limit")
		} else {
			abort(c, http.StatusBadRequest, "invalid resource body")
		}
		return api.PutResourceRequest{}, false
	}
	return req, true
}

type resourceFormat int

const (
	resourceJSON resourceFormat = iota
	resourceEnvelope
)

func resourceRequestFormat(header string) (resourceFormat, bool) {
	if strings.TrimSpace(header) == "" {
		return resourceJSON, true
	}
	mediaType, params, err := mime.ParseMediaType(header)
	if err != nil {
		return 0, false
	}
	switch mediaType {
	case "application/json":
		return resourceJSON, true
	case "application/octet-stream":
		return resourceEnvelope, true
	case "application/vnd.aqt.resource+json":
		return resourceJSON, params["version"] == "1"
	case "application/vnd.aqt.resource+octet-stream":
		return resourceEnvelope, params["version"] == "1"
	default:
		return 0, false
	}
}

func negotiateResourceResponse(header string) (resourceFormat, bool) {
	if strings.TrimSpace(header) == "" {
		return resourceJSON, true
	}
	bestQ, bestSpecificity, best := -1.0, -1, resourceJSON
	for _, item := range strings.Split(header, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(item))
		if err != nil {
			continue
		}
		q := 1.0
		if raw := params["q"]; raw != "" {
			q, err = strconv.ParseFloat(raw, 64)
			if err != nil || q < 0 || q > 1 {
				continue
			}
		}
		if q == 0 {
			continue
		}
		var format resourceFormat
		specificity := 2
		switch mediaType {
		case "application/vnd.aqt.resource+octet-stream":
			if params["version"] != "1" {
				continue
			}
			format = resourceEnvelope
		case "application/vnd.aqt.resource+json":
			if params["version"] != "1" {
				continue
			}
			format = resourceJSON
		case "application/octet-stream":
			format = resourceEnvelope
		case "application/json":
			format = resourceJSON
		case "application/*":
			format, specificity = resourceJSON, 1
		case "*/*":
			format, specificity = resourceJSON, 0
		default:
			continue
		}
		if q > bestQ || q == bestQ && specificity > bestSpecificity {
			bestQ, bestSpecificity, best = q, specificity, format
		}
	}
	return best, bestQ >= 0
}

func (s *Server) listResources(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	items, next, err := s.store.ListResources(owner, page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list failed")
		return
	}
	c.JSON(http.StatusOK, api.ListResourcesResponse{Resources: items, NextCursor: next})
}

func (s *Server) updateResourceMetadata(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.UpdateResourceMetadataRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.EncryptedMeta.Nonce) == 0 || len(req.EncryptedMeta.Ciphertext) == 0 || req.ExpectedVersion <= 0 {
		abort(c, http.StatusBadRequest, "encrypted metadata and expectedVersion are required")
		return
	}
	capability := requestCapability(c)
	version, err := s.store.UpdateResourceMetadata(owner, c.Param("id"), capability, req)
	var upgrade *UpgradeRequiredError
	if errors.As(err, &upgrade) {
		abortUpgradeRequired(c, upgrade.MinClient, capability)
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; retry the rename", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "metadata update failed")
		return
	}
	c.JSON(http.StatusOK, api.PutResourceResponse{ID: c.Param("id"), Version: version})
}

func (s *Server) setVisibility(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.SetVisibilityRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.Visibility != api.Private && req.Visibility != api.Public {
		abort(c, http.StatusBadRequest, "visibility must be private or public")
		return
	}
	version, err := s.store.SetVisibility(owner, c.Param("id"), req)
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; retry the visibility change", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrPolicyOnPrivate) || errors.Is(err, ErrBadPolicy) {
		abortCode(c, http.StatusBadRequest, policyErrorMessage(err), api.ErrCodeInvalidPolicy)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "update failed")
		return
	}
	resp := api.PutResourceResponse{ID: c.Param("id"), Version: version}
	if req.Visibility == api.Public {
		if req.ExpireSeconds > 0 {
			resp.ExpiresAt = time.Now().Unix() + req.ExpireSeconds
		}
		resp.MaxReads = req.MaxReads
		resp.OnExpiry = echoedOnExpiry(req.OnExpiry, resp.ExpiresAt, resp.MaxReads)
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) deleteResource(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	expected, ok := parseIfMatch(c)
	if !ok {
		return
	}
	err := s.store.DeleteResourceVersion(owner, c.Param("id"), expected)
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; retry the delete", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.Status(http.StatusNoContent)
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

// --- snapshot handlers ---

func (s *Server) createSnapshot(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.CreateSnapshotRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.ResourceID == "" {
		abort(c, http.StatusBadRequest, "resourceId is required")
		return
	}
	defer s.accountLimits.lock(owner)()
	resource, err := s.store.GetResource(req.ResourceID, owner)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			abortNotFound(c)
		} else {
			abort(c, http.StatusInternalServerError, "resource lookup failed")
		}
		return
	}
	if err := s.checkAccountLimit(owner, "snapshots", estimatedResourceBytes(api.PutResourceRequest{Blob: resource.Blob, EncryptedMeta: resource.EncryptedMeta, WrappedKey: resource.WrappedKey})); err != nil {
		if !abortLimit(c, err) {
			abort(c, http.StatusInternalServerError, "usage lookup failed")
		}
		return
	}
	if key := c.GetHeader("Idempotency-Key"); len(key) > 128 {
		abort(c, http.StatusBadRequest, "Idempotency-Key must be at most 128 bytes")
		return
	} else {
		req.IdempotencyKey = key
	}
	info, err := s.store.CreateSnapshotIdempotent(owner, req)
	if errors.Is(err, ErrIdempotencyConflict) {
		abortCode(c, http.StatusConflict, "Idempotency-Key was already used for another request", api.ErrCodeIdempotencyConflict)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "snapshot failed")
		return
	}
	c.JSON(http.StatusCreated, info)
}

func (s *Server) setSnapshotAnchor(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.SetSnapshotAnchorRequest
	if !bindJSON(c, &req) {
		return
	}
	info, err := s.store.SetSnapshotAnchor(owner, c.Param("id"), req.Anchored)
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "update failed")
		return
	}
	c.JSON(http.StatusOK, info)
}

func (s *Server) listSnapshots(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	snaps, next, err := s.store.ListSnapshots(owner, c.Query("resource"), page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list snapshots failed")
		return
	}
	c.JSON(http.StatusOK, api.ListSnapshotsResponse{Snapshots: snaps, NextCursor: next})
}

func (s *Server) getSnapshot(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	resp, err := s.store.GetSnapshot(owner, c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "fetch snapshot failed")
		return
	}
	// A snapshot copies its source resource's sealed format, so restore is gated the
	// same way a resource read is: a client below the snapshot's min_client gets a 426.
	if capability := requestCapability(c); capability < resp.MinClient {
		abortUpgradeRequired(c, resp.MinClient, capability)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) deleteSnapshot(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	if err := s.store.DeleteSnapshot(owner, c.Param("id")); errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	} else if errors.Is(err, ErrSnapshotAnchored) {
		c.AbortWithStatusJSON(http.StatusConflict, api.ErrorResponse{
			Error: "snapshot is anchored and protected from pruning; run `aqt snapshot unanchor " +
				c.Param("id") + "` first",
			Code: api.ErrCodeSnapshotAnchored,
		})
		return
	} else if err != nil {
		abort(c, http.StatusInternalServerError, "delete snapshot failed")
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) setAutoSnapshot(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.SetAutoSnapshotRequest
	if !bindJSON(c, &req) {
		return
	}
	if err := s.store.SetAutoSnapshot(owner, c.Param("id"), req.Enabled); errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	} else if err != nil {
		abort(c, http.StatusInternalServerError, "update failed")
		return
	}
	c.Status(http.StatusNoContent)
}

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
// as a manual path, but reclamation no longer depends on a device syncing: an
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

func abort(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, api.ErrorResponse{Error: msg})
}

// abortCode is abort with a stable machine-readable Code, so a client can branch on
// the condition without string-matching the message. The message stays a fixed,
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

// policyErrorMessage maps the two lifecycle-policy validation errors to fixed,
// user-facing messages, so the handler answers a stable string (and a stable Code)
// rather than echoing the raw error value.
func policyErrorMessage(err error) string {
	if errors.Is(err, ErrPolicyOnPrivate) {
		return "a link lifecycle policy can only be set on a public resource"
	}
	return "link lifecycle policy values must be non-negative"
}

// requestCapability fails closed for clients that predate capability headers.
// The old header-less fallback made a pre-v0.2 binary indistinguishable from a
// v0.2 reader and could hand it an id-bound root that only failed at AEAD open.
// Treating absent or malformed values as baseline makes the server gate that
// boundary before any encrypted payload is served.
func requestCapability(c *gin.Context) int {
	v := c.GetHeader(api.CapabilityHeader)
	n, err := strconv.Atoi(v)
	if err != nil || n < api.CapabilityBaseline {
		return api.CapabilityBaseline
	}
	return n
}

// abortUpgradeRequired answers 426 with the structured upgrade error. The message is
// self-contained because a header-less old client prints it verbatim (server: %s), so
// it must explain the mismatch on its own. need is the capability the resource
// requires; have is what the requester declared.
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

func deviceName(name string) string {
	if name == "" {
		return "unnamed-device"
	}
	return name
}
