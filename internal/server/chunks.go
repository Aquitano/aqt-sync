package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquitano/aqt-sync/internal/api"
)

// maxPublicObjectIDs caps one public-read request. It mirrors the client-side
// locate batch cap (locateBatchSize), keeping a single response's pack-read set
// bounded no matter how the caller frames its batches.
const maxPublicObjectIDs = 10_000

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
	stored, err := s.store.PutPack(owner, packID, data, s.cfg.QuotaBytes)
	if errors.Is(err, ErrBadPack) {
		abort(c, http.StatusBadRequest, err.Error())
		return
	}
	if errors.Is(err, ErrQuotaExceeded) {
		abort(c, http.StatusInsufficientStorage, "storage quota exceeded; free space or raise the quota")
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "store pack failed")
		return
	}
	s.metrics.packBytesIn.Add(float64(len(data)))
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
	addResponseBytes(s.metrics.packBytesOut, c.Writer.Size())
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

// publicObjects serves exact object slices for a public streamed resource without
// auth. A share-link holder already has the content key (URL fragment) but object
// fetch is otherwise owner-scoped, so this is the only unauthenticated path to the
// packed object bytes. It answers EXACT per-object slices, never a raw pack range: a
// pack interleaves many resources' objects, and the client's span coalescing on raw
// ranges would let a public reader pull gap bytes belonging to a private neighbor.
//
// The response is a positional binary framing — for each requested id, a 4-byte
// big-endian length followed by exactly that many bytes, in request order.
func (s *Server) publicObjects(c *gin.Context) {
	var req api.PublicObjectsRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.IDs) > maxPublicObjectIDs {
		abort(c, http.StatusBadRequest, "too many object ids in one request")
		return
	}
	owner, locs, err := s.store.PublicObjectSlices(c.Param("id"), req.IDs)
	if errors.Is(err, ErrNotFound) {
		abort(c, http.StatusNotFound, "not found")
		return
	}
	if errors.Is(err, ErrGone) {
		abortGone(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "locate failed")
		return
	}
	s.writeObjectFrames(c, owner, locs, s.metrics.publicObjectBytes)
}

// writeObjectFrames streams resolved object slices as the positional binary
// framing (4-byte big-endian length + bytes per id, in request order), shared by
// the public and grant object endpoints.
func (s *Server) writeObjectFrames(c *gin.Context, owner string, locs []api.ObjectLocation, counter prometheus.Counter) {
	c.Header("Content-Type", "application/octet-stream")
	c.Status(http.StatusOK)

	// Keep each pack open for the response's duration: a streamed file's objects
	// cluster into a handful of packs, so this bounds open fds without re-opening per
	// slice. Closed before returning.
	open := map[string]*os.File{}
	defer func() {
		for _, f := range open {
			f.Close()
		}
	}()

	defer func() { addResponseBytes(counter, c.Writer.Size()) }()

	// Past the first byte the headers are committed, so a disk error can only
	// truncate the body; the client detects the short read off the length framing.
	var lenbuf [4]byte
	for _, loc := range locs {
		f, ok := open[loc.PackID]
		if !ok {
			var err error
			f, err = os.Open(s.store.packPath(owner, loc.PackID))
			if err != nil {
				return
			}
			open[loc.PackID] = f
		}
		binary.BigEndian.PutUint32(lenbuf[:], uint32(loc.Len))
		if _, err := c.Writer.Write(lenbuf[:]); err != nil {
			return
		}
		if _, err := f.Seek(loc.Off, io.SeekStart); err != nil {
			return
		}
		if _, err := io.CopyN(c.Writer, f, loc.Len); err != nil {
			return
		}
	}
}

func (s *Server) runGC(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	// GC sweeps fully-dead packs first, then compacts the dead objects trapped in
	// still-live ones; both honor the same age guard, and the whole sequence is
	// serialized per owner inside the store.
	res, err := s.store.GC(owner, gcMinAge)
	if err != nil {
		abort(c, http.StatusInternalServerError, "gc failed")
		return
	}
	s.metrics.observeGC("client", res)
	c.JSON(http.StatusOK, res)
}
