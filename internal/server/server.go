// Package server implements aqt's zero-knowledge HTTP API on top of Gin. Every
// payload it handles is opaque ciphertext or key material it cannot read.
package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

type Server struct {
	store *Store
}

func New(store *Store) *Server { return &Server{store: store} }

// Router builds the Gin engine with all routes mounted.
func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	v1 := r.Group("/v1")
	{
		v1.POST("/account", s.createAccount)
		v1.GET("/account/salt", s.accountSalt)
		v1.POST("/devices", s.attachDevice)

		// Public resource reads need no auth; the id is unguessable and the
		// decrypt key lives only in the caller's URL fragment.
		v1.GET("/resources/:id", s.getResource)

		authed := v1.Group("", s.authMiddleware)
		{
			authed.PUT("/resources", s.putResource)
			authed.GET("/resources", s.listResources)
			authed.DELETE("/resources/:id", s.deleteResource)
		}
	}
	return r
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
	if req.Email == "" || len(req.AuthKey) == 0 {
		abort(c, http.StatusBadRequest, "email and authKey are required")
		return
	}
	acc, err := s.store.CreateAccount(req.Email, req.Kdf, req.AuthKey)
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

func (s *Server) attachDevice(c *gin.Context) {
	var req api.AttachDeviceRequest
	if !bindJSON(c, &req) {
		return
	}
	acc, ok, err := s.store.VerifyAuthKey(req.Email, req.AuthKey)
	if err != nil {
		abort(c, http.StatusInternalServerError, "verify failed")
		return
	}
	if !ok {
		abort(c, http.StatusUnauthorized, "invalid credentials")
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
		if req.WrappedKey != nil {
			abort(c, http.StatusBadRequest, "public resource must not carry a wrapped key")
			return
		}
	default:
		abort(c, http.StatusBadRequest, "visibility must be private or public")
		return
	}
	id, version, err := s.store.PutResource(owner, req)
	if err != nil {
		abort(c, http.StatusInternalServerError, "store failed")
		return
	}
	c.JSON(http.StatusCreated, api.PutResourceResponse{ID: id, Version: version})
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

func (s *Server) deleteResource(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
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
