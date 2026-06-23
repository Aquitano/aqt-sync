package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

// gcMinAge is the age guard for chunk garbage collection: a chunk younger than
// this is never swept, so an in-flight push's freshly uploaded chunks survive
// until its manifest commits and roots them.
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

func (s *Server) uploadChunks(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.ChunkUploadRequest
	if !bindJSON(c, &req) {
		return
	}
	stored, err := s.store.PutChunks(owner, req.Chunks)
	if err != nil {
		// The only non-internal failure is an id/data mismatch (a bad client).
		abort(c, http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusOK, api.ChunkUploadResponse{Stored: stored})
}

func (s *Server) fetchChunks(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.ChunkFetchRequest
	if !bindJSON(c, &req) {
		return
	}
	chunks, err := s.store.GetChunks(owner, req.IDs)
	if err != nil {
		abort(c, http.StatusInternalServerError, "chunk fetch failed")
		return
	}
	c.JSON(http.StatusOK, api.ChunkFetchResponse{Chunks: chunks})
}

func (s *Server) runGC(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	deleted, err := s.store.GCChunks(owner, gcMinAge)
	if err != nil {
		abort(c, http.StatusInternalServerError, "gc failed")
		return
	}
	c.JSON(http.StatusOK, api.GCResponse{Deleted: deleted})
}
