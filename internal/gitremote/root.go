// Package gitremote implements the sealed client-side data model used by the
// git-remote-aqt helper. The server stores these values opaquely.
package gitremote

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

const (
	RefsRootVersion  = 1
	DefaultCompactAt = 64
)

// Segment names one independently sealed slice of a Git bundle. Len is the
// plaintext length and Size is the stored nonce+ciphertext length.
type Segment struct {
	ID   string `json:"id"`
	Len  int    `json:"len"`
	Size int    `json:"size"`
}

// BundleRef names one push's bundle and the refs needed to decide whether a
// client must apply it. Segments are embedded because the existing public object
// API roots and locates concrete object IDs; ID remains the stable group/cache key.
type BundleRef struct {
	ID string `json:"id"`
	// Full distinguishes a compaction bundle from a one-push delta with no bases,
	// allowing repeated GC to stop without uploading or snapshotting again.
	Full     bool      `json:"full,omitempty"`
	Tips     []string  `json:"tips,omitempty"`
	Bases    []string  `json:"bases,omitempty"`
	Segments []Segment `json:"segments,omitempty"`
}

// RefsRoot is the small sealed resource blob for a Git remote.
type RefsRoot struct {
	Version      int               `json:"version"`
	Head         string            `json:"head,omitempty"`
	Refs         map[string]string `json:"refs,omitempty"`
	Bundles      []BundleRef       `json:"bundles,omitempty"`
	Generation   int               `json:"generation"`
	ObjectFormat string            `json:"objectFormat,omitempty"`
}

func NewRefsRoot() RefsRoot {
	return RefsRoot{Version: RefsRootVersion, Refs: make(map[string]string)}
}

// SegmentIDs returns the concrete object IDs the server must retain for this root.
func (r RefsRoot) SegmentIDs() []string {
	var ids []string
	for _, bundle := range r.Bundles {
		for _, segment := range bundle.Segments {
			ids = append(ids, segment.ID)
		}
	}
	return ids
}

func (r RefsRoot) Size() int64 {
	var size int64
	for _, bundle := range r.Bundles {
		for _, segment := range bundle.Segments {
			size += int64(segment.Size)
		}
	}
	return size
}

func (r RefsRoot) Validate() error {
	if r.Version != RefsRootVersion {
		return fmt.Errorf("unsupported git remote root version %d", r.Version)
	}
	if r.Generation < 0 {
		return errors.New("git remote root has a negative generation")
	}
	if r.Head != "" && !strings.HasPrefix(r.Head, "refs/heads/") {
		return fmt.Errorf("invalid git remote HEAD %q", r.Head)
	}
	switch r.ObjectFormat {
	case "", "sha1", "sha256":
	default:
		return fmt.Errorf("unsupported git object format %q", r.ObjectFormat)
	}
	oidLen := oidHexLen(r.ObjectFormat)
	for name, oid := range r.Refs {
		if !strings.HasPrefix(name, "refs/") {
			return fmt.Errorf("invalid git ref %q", name)
		}
		if !validOID(oid, oidLen) {
			return fmt.Errorf("invalid object id %q for git ref %q", oid, name)
		}
	}
	for _, bundle := range r.Bundles {
		if bundle.ID == "" || len(bundle.Segments) == 0 {
			return errors.New("git bundle entry is missing its id or segments")
		}
		for _, oid := range bundle.Tips {
			if !validOID(oid, oidLen) {
				return fmt.Errorf("invalid tip object id %q in git bundle %q", oid, bundle.ID)
			}
		}
		for _, oid := range bundle.Bases {
			if !validOID(oid, oidLen) {
				return fmt.Errorf("invalid base object id %q in git bundle %q", oid, bundle.ID)
			}
		}
		for _, segment := range bundle.Segments {
			if segment.ID == "" || segment.Len < 0 || segment.Size <= crypto.NonceSize {
				return fmt.Errorf("invalid segment in git bundle %q", bundle.ID)
			}
		}
	}
	return nil
}

// oidHexLen gives the hex length every object id in the root must have. An empty
// ObjectFormat is a root written before the first push negotiated one, so it can
// only be sha1.
func oidHexLen(objectFormat string) int {
	if objectFormat == "sha256" {
		return 64
	}
	return 40
}

// validOID keeps ids that git would parse as an option, or that belong to the
// other hash algorithm, from reaching the helper's git subprocesses.
func validOID(oid string, hexLen int) bool {
	if len(oid) != hexLen {
		return false
	}
	for _, c := range oid {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func SealRefsRoot(root RefsRoot, key crypto.ContentKey, resourceID string) (crypto.SealedBlob, error) {
	if err := root.Validate(); err != nil {
		return crypto.SealedBlob{}, err
	}
	b, err := json.Marshal(root)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.SealBound(b, key, crypto.AADGitRefsRoot, resourceID)
}

func OpenRefsRoot(blob crypto.SealedBlob, key crypto.ContentKey, resourceID string) (RefsRoot, error) {
	var root RefsRoot
	b, err := crypto.OpenBound(blob, key, crypto.AADGitRefsRoot, resourceID)
	if err != nil {
		return root, err
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return root, err
	}
	if err := root.Validate(); err != nil {
		return root, err
	}
	if root.Refs == nil {
		root.Refs = make(map[string]string)
	}
	return root, nil
}
