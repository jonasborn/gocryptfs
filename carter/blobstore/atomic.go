package blobstore

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to a sibling ".tmp" file, fsyncs it, renames it
// over path, and best-effort fsyncs the containing directory. A crash at any
// point leaves either the old file intact or the new file fully in place —
// never a torn blob.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	fsyncDirBestEffort(dir)
	return nil
}

// fsyncDirBestEffort flushes the rename to disk where the platform/filesystem
// supports syncing a directory handle. Where it does not (notably Windows),
// the error is ignored — the rename itself is still ordered by the OS.
func fsyncDirBestEffort(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
