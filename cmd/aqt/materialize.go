// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/fsatomic"
	"github.com/aquitano/aqt-sync/internal/packio"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// materializeManifest checks the complete tree before writing any entries, then
// downloads bounded batches and records mtimes for callers that keep a sync base.
func (app *application) materializeManifest(cl *client.Client, slices sliceFetch, dir string, m *syncengine.Manifest) error {
	if syncengine.CaseInsensitiveDir(dir) {
		if err := refuseCaseCollisions(m.Entries, m.Dirs); err != nil {
			return err
		}
	}
	prog := app.newProgressBar("downloading", entriesBytes(m.Entries))
	mtimes, err := runDownloads(cl, slices, dir, m.Entries, prog)
	prog.finish(err == nil)
	if err != nil {
		return err
	}
	if err := syncengine.MaterializeDirs(dir, m.Dirs); err != nil {
		return err
	}
	for i := range m.Entries {
		if mtime, ok := mtimes[m.Entries[i].Path]; ok {
			m.Entries[i].MTime = mtime
		}
	}
	return nil
}

// chunkSource selects owner pack access or the exact-object transport allowed by
// a share or grant. Both decryptors consume the same object lookup function.
func chunkSource(cl *client.Client, slices sliceFetch, chunks []crypto.Chunk) (func(string) ([]byte, error), error) {
	if slices != nil {
		return newPublicChunkSource(slices, chunks, packio.NewCache(packio.DefaultCacheBytes)).get, nil
	}
	src, err := packio.NewSource(cl, distinctChunkIDs([]syncengine.Entry{{Chunks: chunks}}))
	if err != nil {
		return nil, err
	}
	return src.Get, nil
}

type fileContent struct {
	size  int64
	write func(io.Writer) error
}

// openFileContent authenticates the file root before any destination is opened.
// Streamed content is fetched and decrypted as write consumes it.
func openFileContent(cl *client.Client, res api.GetResourceResponse, ck crypto.ContentKey, meta api.Metadata, slices sliceFetch) (fileContent, error) {
	if !meta.Streamed {
		plain, err := crypto.OpenBound(res.Blob, ck, crypto.AADBlob, res.ID)
		if err != nil {
			return fileContent{}, fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
		}
		return fileContent{size: int64(len(plain)), write: func(w io.Writer) error {
			_, err := w.Write(plain)
			return err
		}}, nil
	}
	root, err := syncengine.OpenFileRoot(res.Blob, ck, res.ID)
	if err != nil {
		return fileContent{}, fmt.Errorf("decrypt file root: %w", err)
	}
	chunks := root.Chunks
	if root.Indirect() {
		get, err := chunkSource(cl, slices, root.ChunkList)
		if err != nil {
			return fileContent{}, err
		}
		chunks, err = root.Resolve(get)
		if err != nil {
			return fileContent{}, err
		}
	}
	get, err := chunkSource(cl, slices, chunks)
	if err != nil {
		return fileContent{}, err
	}
	return fileContent{size: root.Size, write: func(w io.Writer) error {
		return syncengine.WriteFileRoot(w, chunks, get)
	}}, nil
}

func (c fileContent) writeFile(dest string, perm os.FileMode, force bool) error {
	if !force {
		if _, err := os.Lstat(dest); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", dest)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return fsatomic.WriteStream(dest, perm, func(f *os.File) error { return c.write(f) })
}

func (app *application) writeOutput(content fileContent, dest string, perm os.FileMode, toStdout, force bool) error {
	if toStdout {
		return content.write(os.Stdout)
	}
	if err := content.writeFile(dest, perm, force); err != nil {
		return err
	}
	if app.json {
		return printJSON(map[string]any{"path": dest, "bytes": content.size})
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d B)\n", dest, content.size)
	return nil
}
