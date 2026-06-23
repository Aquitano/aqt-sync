// Package server implements aqt's zero-knowledge HTTP API on top of Gin. Every
// payload it handles is opaque ciphertext or key material it cannot read.
package server

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
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

// maxBodyBytes caps a single request body. It bounds the per-resource size in
// v1 (chunked uploads for large files are deferred) and limits memory blowup.
const maxBodyBytes = 32 << 20 // 32 MiB

// Router builds the Gin engine with all routes mounted.
func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), limitBody)

	// Human-facing landing page for a public share link. Decryption runs in the
	// CLI; the content key is in the URL fragment, which never reaches the server.
	r.GET("/x/:id", s.shareView)

	v1 := r.Group("/v1")
	{
		// Unauthenticated account/auth routes are rate-limited per client: they are
		// the surface for brute-force, account enumeration, and challenge-table
		// pumping.
		unauth := v1.Group("", s.limiter.middleware)
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
			authed.PUT("/resources", s.putResource)
			authed.GET("/resources", s.listResources)
			authed.POST("/resources/:id/visibility", s.setVisibility)
			authed.DELETE("/resources/:id", s.deleteResource)

			// Folder-sync chunk store: opaque, content-addressed, owner-scoped.
			authed.POST("/chunks/check", s.checkChunks)
			authed.POST("/chunks", s.uploadChunks)
			authed.POST("/chunks/fetch", s.fetchChunks)
			authed.POST("/gc", s.runGC)
		}
	}
	return r
}

func limitBody(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
	c.Next()
}

// --- auth ---

const ownerContextKey = "ownerHandle"

func (s *Server) authMiddleware(c *gin.Context) {
	token, ok := bearerToken(c)
	if !ok {
		abort(c, http.StatusUnauthorized, "missing bearer token")
		return
	}
	owner, err := s.store.OwnerByToken(token)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusUnauthorized, "invalid token")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "auth lookup failed")
		return
	}
	c.Set(ownerContextKey, owner)
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
	acc, err := s.store.CreateAccount(req.Email, req.Kdf, req.PublicKey)
	if errors.Is(err, ErrConflict) {
		abort(c, http.StatusConflict, "account already exists")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "create account failed")
		return
	}
	deviceID, token, err := s.store.CreateDevice(acc.OwnerHandle, deviceName(req.DeviceName))
	if err != nil {
		abort(c, http.StatusInternalServerError, "create device failed")
		return
	}
	c.JSON(http.StatusCreated, api.AuthResponse{
		OwnerHandle: acc.OwnerHandle, DeviceID: deviceID, Token: token,
	})
}

func (s *Server) accountSalt(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		abort(c, http.StatusBadRequest, "email query param required")
		return
	}
	acc, err := s.store.AccountByEmail(email)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "no such account")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	c.JSON(http.StatusOK, api.SaltResponse{Kdf: acc.Kdf})
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
	owner, pub, err := s.store.AccountForAuth(req.Email)
	// A missing account and a bad signature return the same 401: no oracle.
	if err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, nonce, req.Signature) {
		deviceID, token, err := s.store.CreateDevice(owner, deviceName(req.DeviceName))
		if err != nil {
			abort(c, http.StatusInternalServerError, "create device failed")
			return
		}
		c.JSON(http.StatusCreated, api.AuthResponse{OwnerHandle: owner, DeviceID: deviceID, Token: token})
		return
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		abort(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	abort(c, http.StatusUnauthorized, "invalid credentials")
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
