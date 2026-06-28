// Package server implements aqt's zero-knowledge HTTP API on top of Gin. Every
// payload it handles is opaque ciphertext or key material it cannot read.
package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/hkdf"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

type Server struct {
	store    *Store
	resLocks *keyedMutex
	limiter  *ipRateLimiter
}

func New(store *Store) *Server {
	return &Server{
		store:    store,
		resLocks: newKeyedMutex(),
		limiter:  newIPRateLimiter(unauthRatePerSec, unauthBurst),
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
	// The engine-wide cap is the loosest; stacked limiters apply the smallest, so
	// per-route middleware below only tightens it (a forgotten route is still
	// bounded, never unlimited).
	r.Use(gin.Recovery(), limitBody(maxResourceBody))

	// Human-facing landing page for a public share link. Decryption runs in the
	// CLI; the content key is in the URL fragment, which never reaches the server.
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

		authed := v1.Group("", s.authMiddleware)
		{
			// The blob (a file's ciphertext or a folder's sealed manifest) is the one
			// large payload; it keeps the engine-wide maxResourceBody.
			authed.PUT("/resources", s.putResource)
			authed.GET("/resources", s.listResources)
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

			// Folder-sync packed object store: opaque, content-addressed,
			// owner-scoped. Objects ship inside raw packs; check/locate negotiate
			// which objects to up/download by id.
			authed.POST("/chunks/check", limitBody(maxChunkBody), s.checkChunks)
			authed.POST("/chunks/locate", limitBody(maxChunkBody), s.locateChunks)
			authed.PUT("/packs/:id", limitBody(maxPackBody), s.putPack)
			authed.GET("/packs/:id", s.getPack)
			authed.POST("/gc", s.runGC)

			// Snapshots: immutable, GC-pinned copies of a resource version. Owner-only;
			// a snapshot is never public, so unlike a resource there is no unauth read.
			authed.POST("/snapshots", limitBody(maxControlBody), s.createSnapshot)
			authed.GET("/snapshots", s.listSnapshots)
			authed.GET("/snapshots/:id", s.getSnapshot)
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
	acc, err := s.store.CreateAccount(req.Email, req.Kdf, req.PublicKey, req.WrappedRoot, req.AuthVerifier)
	if errors.Is(err, ErrConflict) {
		abort(c, http.StatusConflict, "account already exists")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "create account failed")
		return
	}
	deviceID, token, err := s.store.CreateDevice(acc.OwnerHandle, deviceName(req.DeviceName), 1)
	if err != nil {
		abort(c, http.StatusInternalServerError, "create device failed")
		return
	}
	c.JSON(http.StatusCreated, api.AuthResponse{
		OwnerHandle: acc.OwnerHandle, DeviceID: deviceID, Token: token, Epoch: 1,
	})
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
	def, err := crypto.NewKdfParams()
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
		deviceID, token, err := s.store.CreateDevice(owner, deviceName(req.DeviceName), epoch)
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
		abort(c, http.StatusConflict, "the passphrase changed on another device; re-run with the current one")
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

func (s *Server) listDevices(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	devices, err := s.store.ListDevices(owner)
	if err != nil {
		abort(c, http.StatusInternalServerError, "list devices failed")
		return
	}
	c.JSON(http.StatusOK, api.ListDevicesResponse{Devices: devices})
}

func (s *Server) deleteDevice(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	err := s.store.DeleteDevice(owner, c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
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
	var req api.PutResourceRequest
	if !bindJSON(c, &req) {
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
	// Serialize updates to an existing resource so two concurrent syncs cannot
	// interleave their writes. A create (no id) targets a fresh id, so no lock.
	if req.ID != "" {
		defer s.resLocks.lock(req.ID)()
	}
	id, version, err := s.store.PutResource(owner, req)
	if errors.Is(err, ErrVersionConflict) {
		abort(c, http.StatusConflict, "resource changed since you last fetched it; re-sync")
		return
	}
	if errors.Is(err, ErrDropsRoots) {
		abort(c, http.StatusBadRequest, "replace would drop every chunk root of an object-backed resource; refused to prevent data loss")
		return
	}
	if errors.Is(err, ErrNotFound) {
		// Update targeting an id the caller doesn't own (or that doesn't exist).
		abort(c, http.StatusNotFound, "not found")
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
	c.JSON(status, api.PutResourceResponse{ID: id, Version: version})
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
		abort(c, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "fetch failed")
		return
	}
	c.JSON(http.StatusOK, res)
}

func (s *Server) listResources(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	items, err := s.store.ListResources(owner)
	if err != nil {
		abort(c, http.StatusInternalServerError, "list failed")
		return
	}
	c.JSON(http.StatusOK, api.ListResourcesResponse{Resources: items})
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
	defer s.resLocks.lock(c.Param("id"))()
	version, err := s.store.SetVisibility(owner, c.Param("id"), req.Visibility)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "update failed")
		return
	}
	c.JSON(http.StatusOK, api.PutResourceResponse{ID: c.Param("id"), Version: version})
}

func (s *Server) deleteResource(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	defer s.resLocks.lock(c.Param("id"))()
	err := s.store.DeleteResource(owner, c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.Status(http.StatusNoContent)
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
	// Serialize against a concurrent update of the same resource so the snapshot
	// copies a consistent (blob, chunk-roots) pair, not a torn mix of two versions.
	defer s.resLocks.lock(req.ResourceID)()
	info, err := s.store.CreateSnapshot(owner, req.ResourceID, req.EncryptedLabel)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "snapshot failed")
		return
	}
	c.JSON(http.StatusCreated, info)
}

func (s *Server) listSnapshots(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	snaps, err := s.store.ListSnapshots(owner, c.Query("resource"))
	if err != nil {
		abort(c, http.StatusInternalServerError, "list snapshots failed")
		return
	}
	c.JSON(http.StatusOK, api.ListSnapshotsResponse{Snapshots: snaps})
}

func (s *Server) getSnapshot(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	resp, err := s.store.GetSnapshot(owner, c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "fetch snapshot failed")
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) deleteSnapshot(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	if err := s.store.DeleteSnapshot(owner, c.Param("id")); errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
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
		abort(c, http.StatusNotFound, "not found")
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
// dedup keeps a tick that finds no changes nearly free.
func (s *Server) StartAutoSnapshot(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if n, err := s.store.RunAutoSnapshots(); err != nil {
					log.Printf("auto-snapshot: %v", err)
				} else if n > 0 {
					log.Printf("auto-snapshot: created %d snapshot(s)", n)
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

func deviceName(name string) string {
	if name == "" {
		return "unnamed-device"
	}
	return name
}
