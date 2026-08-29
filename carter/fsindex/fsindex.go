// Package fsindex is the FS v3 index cache (CON-3.1): a fast, in-memory
// directory tree plus its on-disk cache at cipher_dir/idx/tree.
//
// The cache is NEVER authoritative. The blobs' info-chunks are the source of
// truth; the cache only accelerates lookup/readdir. Deleting idx/tree (or
// failing to open it) is always safe — Rebuild reconstructs the whole tree
// by scanning every blob. A crash between a blob write and the matching
// cache update is caught on the next open via the idx/dirty marker, which
// forces a Rebuild.
//
// No FUSE or card dependency: the sealing key (K_idx) is passed in, and
// Rebuild takes a *blobstore.Store.
package fsindex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/carter/blobmeta"
	"github.com/rfjakob/gocryptfs/v2/carter/blobstore"
)

const (
	treeFile  = "idx/tree"
	dirtyFile = "idx/dirty"

	cacheFormat  = 1
	sealNonceLen = 16
)

// ErrNoCache means idx/tree is absent or unreadable; the caller should
// Rebuild.
var ErrNoCache = errors.New("fsindex: no usable cache")

// Entry is one directory entry.
type Entry struct {
	Name string
	UUID [16]byte
	Type blobmeta.FileType
}

// Index is the in-memory tree. Safe for concurrent use.
type Index struct {
	dir string

	mu       sync.RWMutex
	gen      uint64
	recs     map[[16]byte]*blobmeta.MetaRecord
	children map[[16]byte]map[string]Entry // parent UUID -> name -> entry
}

// --- construction ---------------------------------------------------------

func newIndex(dir string) *Index {
	return &Index{
		dir:      dir,
		recs:     make(map[[16]byte]*blobmeta.MetaRecord),
		children: make(map[[16]byte]map[string]Entry),
	}
}

// Rebuild scans every blob in st and returns a fresh Index. It does not
// write idx/tree — call Save for that.
func Rebuild(st *blobstore.Store) (*Index, error) {
	idx := newIndex(st.Dir())
	err := st.Scan(func(uuid [16]byte, rec *blobmeta.MetaRecord, _ int64) error {
		cp := *rec
		idx.putLocked(&cp)
		return nil
	}, func(path string, err error) {
		// A blob whose info-chunk will not decrypt/parse is dropped from the
		// tree; the file is effectively lost but the rest of the FS is fine.
		fmt.Fprintf(os.Stderr, "fsindex: skipping unreadable blob %s: %v\n", path, err)
	})
	if err != nil {
		return nil, err
	}
	if _, ok := idx.recs[blobmeta.RootDirUUID]; !ok {
		return nil, fmt.Errorf("fsindex: rebuild found no root directory blob")
	}
	return idx, nil
}

// Load reads and unseals idx/tree. It returns ErrNoCache if the file is
// missing, if it will not unseal under kIdx, or if the idx/dirty marker is
// present (a prior run may have crashed mid-update).
func Load(dir string, kIdx []byte) (*Index, error) {
	if _, err := os.Stat(filepath.Join(dir, dirtyFile)); err == nil {
		return nil, fmt.Errorf("%w: dirty marker present", ErrNoCache)
	}
	raw, err := os.ReadFile(filepath.Join(dir, treeFile))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCache, err)
	}
	body, err := unseal(kIdx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCache, err)
	}
	idx := newIndex(dir)
	if err := idx.decodeBody(body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCache, err)
	}
	if _, ok := idx.recs[blobmeta.RootDirUUID]; !ok {
		return nil, fmt.Errorf("%w: no root in cache", ErrNoCache)
	}
	return idx, nil
}

// LoadOrRebuild tries Load; on ErrNoCache it Rebuilds from st and writes a
// fresh cache.
func LoadOrRebuild(st *blobstore.Store, kIdx []byte) (*Index, error) {
	idx, err := Load(st.Dir(), kIdx)
	if err == nil {
		return idx, nil
	}
	if !errors.Is(err, ErrNoCache) {
		return nil, err
	}
	idx, err = Rebuild(st)
	if err != nil {
		return nil, err
	}
	if err := idx.Save(kIdx); err != nil {
		return nil, err
	}
	return idx, nil
}

// --- queries ------------------------------------------------------------

// Gen returns the cache generation counter (incremented on each Save).
func (idx *Index) Gen() uint64 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.gen
}

// Get returns a copy of the record for uuid.
func (idx *Index) Get(uuid [16]byte) (blobmeta.MetaRecord, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	r, ok := idx.recs[uuid]
	if !ok {
		return blobmeta.MetaRecord{}, false
	}
	return *r, true
}

// Lookup resolves (parent, name) to a directory entry.
func (idx *Index) Lookup(parent [16]byte, name string) (Entry, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	m := idx.children[parent]
	if m == nil {
		return Entry{}, false
	}
	e, ok := m[name]
	return e, ok
}

// Children returns the entries of a directory, in no particular order.
func (idx *Index) Children(parent [16]byte) []Entry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	m := idx.children[parent]
	out := make([]Entry, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	return out
}

// HasChildren reports whether a directory is non-empty (for rmdir).
func (idx *Index) HasChildren(parent [16]byte) bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.children[parent]) > 0
}

// --- mutations --------------------------------------------------------

// Put inserts or replaces a record and refreshes the parent's child entry.
func (idx *Index) Put(rec *blobmeta.MetaRecord) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	cp := *rec
	idx.putLocked(&cp)
}

// Remove drops a record and its entry from its parent directory.
func (idx *Index) Remove(uuid [16]byte) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	r, ok := idx.recs[uuid]
	if !ok {
		return
	}
	if m := idx.children[r.ParentDirID]; m != nil {
		delete(m, r.Name)
	}
	delete(idx.recs, uuid)
	delete(idx.children, uuid)
}

// putLocked assumes idx.mu is held (or that idx is not yet shared).
func (idx *Index) putLocked(rec *blobmeta.MetaRecord) {
	if old, ok := idx.recs[rec.FileUUID]; ok && (old.ParentDirID != rec.ParentDirID || old.Name != rec.Name) {
		if m := idx.children[old.ParentDirID]; m != nil {
			delete(m, old.Name)
		}
	}
	idx.recs[rec.FileUUID] = rec
	if !rec.IsRoot() {
		m := idx.children[rec.ParentDirID]
		if m == nil {
			m = make(map[string]Entry)
			idx.children[rec.ParentDirID] = m
		}
		m[rec.Name] = Entry{Name: rec.Name, UUID: rec.FileUUID, Type: rec.Type}
	}
}

// --- dirty marker ----------------------------------------------------

// MarkDirty writes idx/dirty. Call it before a batch of blob mutations; the
// next Load will refuse the cache and force a Rebuild if the process dies
// before Save clears the marker.
func (idx *Index) MarkDirty() error {
	return os.WriteFile(filepath.Join(idx.dir, dirtyFile), []byte("1"), 0600)
}

// --- persistence ---------------------------------------------------

// Save seals the tree to idx/tree (atomically) and clears idx/dirty.
func (idx *Index) Save(kIdx []byte) error {
	idx.mu.Lock()
	idx.gen++
	body := idx.encodeBody()
	idx.mu.Unlock()

	sealed, err := seal(kIdx, body)
	if err != nil {
		return err
	}
	if err := blobstore.WriteFileAtomic(filepath.Join(idx.dir, treeFile), sealed); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(idx.dir, dirtyFile))
	return nil
}

// body layout (all little-endian):
//
//	u32 cacheFormat
//	u64 gen
//	u32 recCount
//	recCount × ( u32 len ‖ blobmeta TLV record )
func (idx *Index) encodeBody() []byte {
	buf := make([]byte, 0, 16+len(idx.recs)*256)
	buf = binary.LittleEndian.AppendUint32(buf, cacheFormat)
	buf = binary.LittleEndian.AppendUint64(buf, idx.gen)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(idx.recs)))
	for _, r := range idx.recs {
		tlv, err := r.Marshal()
		if err != nil {
			// A record already in the tree failed to marshal — skip it
			// rather than poison the whole cache; a Rebuild will surface it.
			fmt.Fprintf(os.Stderr, "fsindex: dropping unmarshalable record %x: %v\n", r.FileUUID, err)
			continue
		}
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(tlv)))
		buf = append(buf, tlv...)
	}
	return buf
}

func (idx *Index) decodeBody(body []byte) error {
	if len(body) < 16 {
		return errors.New("fsindex: cache body too short")
	}
	off := 0
	if binary.LittleEndian.Uint32(body[off:]) != cacheFormat {
		return errors.New("fsindex: unknown cache format")
	}
	off += 4
	idx.gen = binary.LittleEndian.Uint64(body[off:])
	off += 8
	n := binary.LittleEndian.Uint32(body[off:])
	off += 4
	for i := uint32(0); i < n; i++ {
		if off+4 > len(body) {
			return errors.New("fsindex: cache truncated")
		}
		l := int(binary.LittleEndian.Uint32(body[off:]))
		off += 4
		if off+l > len(body) {
			return errors.New("fsindex: cache truncated")
		}
		rec, err := blobmeta.UnmarshalRecord(body[off : off+l])
		if err != nil {
			return fmt.Errorf("fsindex: bad record in cache: %w", err)
		}
		off += l
		idx.putLocked(rec)
	}
	return nil
}

// --- sealing -------------------------------------------------------

func gcmFor(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("fsindex: K_idx must be 32 bytes")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(blk, sealNonceLen)
}

func seal(key, body []byte) ([]byte, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, sealNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, sealNonceLen+len(body)+gcm.Overhead())
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, body, []byte("carter-fsindex-v1")), nil
}

func unseal(key, raw []byte) ([]byte, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	if len(raw) < sealNonceLen+gcm.Overhead() {
		return nil, errors.New("fsindex: sealed cache too short")
	}
	return gcm.Open(nil, raw[:sealNonceLen], raw[sealNonceLen:], []byte("carter-fsindex-v1"))
}
