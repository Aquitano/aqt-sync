package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

// gcMinAge is the age guard for garbage collection: a pack younger than this is
// never swept, so an in-flight push's freshly uploaded packs survive until its
// manifest commits and roots their objects.
const gcMinAge = time.Hour

func (s *Server) checkChunks(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.ChunkCheckRequest
	if !bindJSON(c, &req) {
		return
	}
	missing, err := s.store.MissingChunks(owner, req.IDs)
	if err != nil {
		abort(c, http.StatusInternalServerError, "chunk check failed")
		return
	}
	c.JSON(http.StatusOK, api.ChunkCheckResponse{Missing: missing})
}

// putPack stores one raw pack (application/octet-stream). The id in the path is the
// pack's content address; the store verifies it and every object slice, so a
// corrupt or mislabeled pack is rejected wholesale.
func (s *Server) putPack(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	packID := c.Param("id")
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		// The body cap (http.MaxBytesReader) surfaces here when exceeded.
		abort(c, http.StatusBadRequest, "read pack body failed")
		return
	}
	stored, err := s.store.PutPack(owner, packID, data)
	if errors.Is(err, ErrBadPack) {
		abort(c, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "store pack failed")
		return
	}
	c.JSON(http.StatusOK, api.PutPackResponse{StoredObjects: stored})
}

// getPack serves a pack's raw bytes, honoring Range so a pull can fetch only the
// byte span covering the objects it needs. The pack is streamed straight from disk,
// never loaded whole into memory.
func (s *Server) getPack(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	path, err := s.store.PackFileForOwner(owner, c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "locate pack failed")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		abort(c, http.StatusInternalServerError, "open pack failed")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		abort(c, http.StatusInternalServerError, "stat pack failed")
		return
	}
	// The pack is opaque ciphertext; set the type so ServeContent does not sniff it.
	c.Header("Content-Type", "application/octet-stream")
	http.ServeContent(c.Writer, c.Request, c.Param("id"), info.ModTime(), f)
}

// locateChunks resolves object ids to pack byte ranges for the pull path.
func (s *Server) locateChunks(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.LocateRequest
	if !bindJSON(c, &req) {
		return
	}
	locations, err := s.store.LocateObjects(owner, req.IDs)
	if err != nil {
		abort(c, http.StatusInternalServerError, "locate failed")
		return
	}
	c.JSON(http.StatusOK, api.LocateResponse{Locations: locations})
}

func (s *Server) runGC(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	deleted, freed, err := s.store.GCPacks(owner, gcMinAge)
	if err != nil {
		abort(c, http.StatusInternalServerError, "gc failed")
		return
	}
	// Sweep fully-dead packs first, then compact the dead objects trapped in
	// still-live ones. Both honor the same age guard.
	repacked, reclaimed, err := s.store.RepackOwner(owner, gcMinAge)
	if err != nil {
		abort(c, http.StatusInternalServerError, "repack failed")
		return
	}
	c.JSON(http.StatusOK, api.GCResponse{
		DeletedPacks:   deleted,
		FreedBytes:     freed,
		RepackedPacks:  repacked,
		ReclaimedBytes: reclaimed,
	})
}
