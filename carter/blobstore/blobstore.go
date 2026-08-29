// Package blobstore is the FS v3 backing-store layer (CON-3.1): a
// hash-sharded flat directory of opaque blobs, each blob laid out as
//
//	[ 16-byte random FileUUID (cleartext) ] [ info-chunk ] [ content blocks ]
//
// blobstore owns everything up to and including the info-chunk (the encrypted
// per-file metadata). Content bytes are opaque to it — it only reports the
// offset at which they begin so the content-encryption layer can seek there.
//
// It has no FUSE or card dependency: keys come in through the KeySource
// interface, so it is fully testable over a temp dir with a deterministic
// fake.
package blobstore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/carter/blobmeta"
)

// PrefixLen is the cleartext FileUUID prefix every blob starts with.
const PrefixLen = 16

// KeySource supplies the card-derived keys blobstore needs. In production
// this is implemented by *externalenc.Client; tests pass a fake.
type KeySource interface {
	// IndexKey returns K_index (32 bytes), stable for the life of the mount.
	IndexKey() ([]byte, error)
	// MetaKey returns K_meta for a file UUID (32 bytes).
	MetaKey(uuid [16]byte) ([]byte, error)
}

var (
	// ErrNotExist is returned when a blob for a UUID is not present.
	ErrNotExist = errors.New("blobstore: blob does not exist")
	// ErrPrefixMismatch means the on-disk UUID prefix did not match the
	// UUID we resolved the blob path from — backing-store corruption.
	ErrPrefixMismatch = errors.New("blobstore: blob UUID prefix mismatch")
)

// Store is a handle to one backing directory (the profile's cipher_dir).
type Store struct {
	dir  string
	keys KeySource
}

// Open returns a Store for an already-initialised backing directory.
func Open(dir string, keys KeySource) *Store {
	return &Store{dir: dir, keys: keys}
}

// Init creates the bucket directories (00..ff), the idx/ directory, and the
// root-directory blob. It is idempotent: re-running against an initialised
// store re-creates only what is missing and never rewrites an existing root
// blob.
func Init(dir string, keys KeySource) (*Store, error) {
	s := Open(dir, keys)
	for i := 0; i < 256; i++ {
		if err := os.MkdirAll(filepath.Join(dir, fmt.Sprintf("%02x", i)), 0700); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "idx"), 0700); err != nil {
		return nil, err
	}
	if _, err := s.blobPath(blobmeta.RootDirUUID); err != nil {
		return nil, err
	}
	exists, err := s.Exists(blobmeta.RootDirUUID)
	if err != nil {
		return nil, err
	}
	if !exists {
		root := &blobmeta.MetaRecord{
			SchemaVersion: blobmeta.SchemaVersion,
			FileUUID:      blobmeta.RootDirUUID,
			Name:          "",
			Type:          blobmeta.TypeDir,
			Mode:          0o40755,
		}
		if err := s.WriteMeta(root, nil); err != nil {
			return nil, fmt.Errorf("blobstore: writing root blob: %w", err)
		}
	}
	return s, nil
}

// Dir returns the backing directory path.
func (s *Store) Dir() string { return s.dir }

// blobPath resolves the absolute on-disk path of a blob from its UUID.
func (s *Store) blobPath(uuid [16]byte) (string, error) {
	kIndex, err := s.keys.IndexKey()
	if err != nil {
		return "", err
	}
	id := blobmeta.BlobID(kIndex, uuid)
	return filepath.Join(s.dir, blobmeta.ShardPath(id)), nil
}

// Exists reports whether a blob for uuid is present.
func (s *Store) Exists(uuid [16]byte) (bool, error) {
	p, err := s.blobPath(uuid)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// ReadMeta opens the blob for uuid, verifies its cleartext prefix, decrypts
// the info-chunk, and returns the record plus the byte offset at which
// content blocks begin (PrefixLen + info-chunk length).
func (s *Store) ReadMeta(uuid [16]byte) (rec *blobmeta.MetaRecord, contentOff int64, err error) {
	p, err := s.blobPath(uuid)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrNotExist
		}
		return nil, 0, err
	}
	defer f.Close()

	var prefix [PrefixLen]byte
	if _, err := io.ReadFull(f, prefix[:]); err != nil {
		return nil, 0, fmt.Errorf("blobstore: reading UUID prefix: %w", err)
	}
	if prefix != uuid {
		return nil, 0, ErrPrefixMismatch
	}

	key, err := s.keys.MetaKey(uuid)
	if err != nil {
		return nil, 0, err
	}
	rec, chunkLen, err := blobmeta.ReadInfoChunk(key, uuid, io.NewSectionReader(f, PrefixLen, 1<<62))
	if err != nil {
		return nil, 0, fmt.Errorf("blobstore: info-chunk for %x: %w", uuid, err)
	}
	return rec, PrefixLen + chunkLen, nil
}

// WriteMeta writes (creates or replaces) the blob for rec.FileUUID with the
// given content appended after the info-chunk. Pass content == nil to keep a
// directory/empty blob content-free. The write is atomic: a sibling .tmp
// file is fsync'd and renamed over the target.
//
// For an in-place metadata update that must preserve existing content, use
// ReplaceMeta, which splices the current content back in.
func (s *Store) WriteMeta(rec *blobmeta.MetaRecord, content []byte) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	key, err := s.keys.MetaKey(rec.FileUUID)
	if err != nil {
		return err
	}
	chunk, err := blobmeta.SealInfoChunk(key, rec)
	if err != nil {
		return err
	}
	p, err := s.blobPath(rec.FileUUID)
	if err != nil {
		return err
	}

	buf := make([]byte, 0, PrefixLen+len(chunk)+len(content))
	buf = append(buf, rec.FileUUID[:]...)
	buf = append(buf, chunk...)
	buf = append(buf, content...)
	return WriteFileAtomic(p, buf)
}

// ReplaceMeta rewrites only the metadata of an existing blob, preserving its
// content bytes verbatim. It is O(content size) (a full-blob rewrite via
// tmp+rename); on a reflink-capable backing FS the caller may prefer a
// clone-based path, see CON-3.1 open question 1.
func (s *Store) ReplaceMeta(rec *blobmeta.MetaRecord) error {
	_, contentOff, err := s.ReadMeta(rec.FileUUID)
	if err != nil {
		return err
	}
	p, err := s.blobPath(rec.FileUUID)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var content []byte
	if int64(len(old)) > contentOff {
		content = old[contentOff:]
	}
	return s.WriteMeta(rec, content)
}

// Delete removes the blob for uuid. Missing is not an error.
func (s *Store) Delete(uuid [16]byte) error {
	p, err := s.blobPath(uuid)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// OpenContent opens the blob for uuid for content I/O and returns the file
// handle plus the offset at which content begins. The caller is responsible
// for closing the handle and for seeking/pread/pwrite relative to
// contentOff. Used by the content-encryption layer.
func (s *Store) OpenContent(uuid [16]byte, flag int) (f *os.File, contentOff int64, err error) {
	_, contentOff, err = s.ReadMeta(uuid)
	if err != nil {
		return nil, 0, err
	}
	p, err := s.blobPath(uuid)
	if err != nil {
		return nil, 0, err
	}
	f, err = os.OpenFile(p, flag, 0600)
	if err != nil {
		return nil, 0, err
	}
	return f, contentOff, nil
}

// ScanFunc is called once per blob found by Scan.
type ScanFunc func(uuid [16]byte, rec *blobmeta.MetaRecord, contentSize int64) error

// Scan walks every bucket, reads each blob's prefix + info-chunk, and calls
// fn. A blob whose info-chunk fails to decrypt or parse is passed to
// onCorrupt (if non-nil) and skipped; fn is not called for it. This is the
// cold-rebuild path for the index cache.
func (s *Store) Scan(fn ScanFunc, onCorrupt func(path string, err error)) error {
	for i := 0; i < 256; i++ {
		bucket := filepath.Join(s.dir, fmt.Sprintf("%02x", i))
		ents, err := os.ReadDir(bucket)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if len(name) != 32 || strings.HasSuffix(name, ".tmp") {
				continue
			}
			p := filepath.Join(bucket, name)
			uuid, rec, contentSize, err := s.readBlobAt(p)
			if err != nil {
				if onCorrupt != nil {
					onCorrupt(p, err)
				}
				continue
			}
			if err := fn(uuid, rec, contentSize); err != nil {
				return err
			}
		}
	}
	return nil
}

// readBlobAt reads a blob by absolute path (used by Scan, where we have the
// path but not yet the UUID). The UUID comes from the cleartext prefix and
// is cross-checked against the record body.
func (s *Store) readBlobAt(path string) (uuid [16]byte, rec *blobmeta.MetaRecord, contentSize int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return uuid, nil, 0, err
	}
	defer f.Close()

	if _, err := io.ReadFull(f, uuid[:]); err != nil {
		return uuid, nil, 0, fmt.Errorf("reading UUID prefix: %w", err)
	}
	key, err := s.keys.MetaKey(uuid)
	if err != nil {
		return uuid, nil, 0, err
	}
	rec, chunkLen, err := blobmeta.ReadInfoChunk(key, uuid, io.NewSectionReader(f, PrefixLen, 1<<62))
	if err != nil {
		return uuid, nil, 0, err
	}
	if rec.FileUUID != uuid {
		return uuid, nil, 0, ErrPrefixMismatch
	}
	st, err := f.Stat()
	if err != nil {
		return uuid, nil, 0, err
	}
	contentSize = st.Size() - PrefixLen - chunkLen
	if contentSize < 0 {
		contentSize = 0
	}
	return uuid, rec, contentSize, nil
}
