package blobstore

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/carter/blobmeta"
)

// fakeKeys is a deterministic KeySource: every key is sha256(seed ‖ label),
// so BlobID / MetaKey are stable across a test run without a card.
type fakeKeys struct{ seed string }

func (k fakeKeys) derive(label string) []byte {
	h := sha256.Sum256([]byte(k.seed + "|" + label))
	return h[:]
}
func (k fakeKeys) IndexKey() ([]byte, error) { return k.derive("index"), nil }
func (k fakeKeys) MetaKey(uuid [16]byte) ([]byte, error) {
	return k.derive("meta:" + string(uuid[:])), nil
}

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Init(dir, fakeKeys{seed: "test-seed"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
}

func mkUUID(b byte) [16]byte {
	var u [16]byte
	for i := range u {
		u[i] = b
	}
	return u
}

func fileRec(uuid, parent [16]byte, name string, size int64) *blobmeta.MetaRecord {
	return &blobmeta.MetaRecord{
		SchemaVersion: blobmeta.SchemaVersion,
		FileUUID:      uuid,
		ParentDirID:   parent,
		Name:          name,
		Type:          blobmeta.TypeRegular,
		Mode:          0o644,
		Size:          size,
	}
}

func TestInitCreatesLayout(t *testing.T) {
	s := newStore(t)
	for _, b := range []string{"00", "7f", "ff", "idx"} {
		if fi, err := os.Stat(filepath.Join(s.Dir(), b)); err != nil || !fi.IsDir() {
			t.Fatalf("expected dir %q: %v", b, err)
		}
	}
	rec, contentOff, err := s.ReadMeta(blobmeta.RootDirUUID)
	if err != nil {
		t.Fatalf("ReadMeta(root): %v", err)
	}
	if rec.Type != blobmeta.TypeDir || !rec.IsRoot() {
		t.Fatalf("root record wrong: %+v", rec)
	}
	if contentOff != PrefixLen+blobmeta.UnitSize {
		t.Fatalf("root contentOff = %d, want %d", contentOff, PrefixLen+blobmeta.UnitSize)
	}
}

func TestInitIdempotent(t *testing.T) {
	s := newStore(t)
	if err := s.WriteMeta(fileRec(mkUUID(1), blobmeta.RootDirUUID, "keep.txt", 3), []byte("abc")); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	if _, err := Init(s.Dir(), fakeKeys{seed: "test-seed"}); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if _, _, err := s.ReadMeta(mkUUID(1)); err != nil {
		t.Fatalf("file gone after re-Init: %v", err)
	}
}

func TestWriteReadContent(t *testing.T) {
	s := newStore(t)
	uuid := mkUUID(2)
	content := bytes.Repeat([]byte("Z"), 10000)
	if err := s.WriteMeta(fileRec(uuid, blobmeta.RootDirUUID, "big.bin", int64(len(content))), content); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}

	rec, contentOff, err := s.ReadMeta(uuid)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if rec.Name != "big.bin" || rec.Size != int64(len(content)) {
		t.Fatalf("record mismatch: %+v", rec)
	}

	raw, err := os.ReadFile(mustPath(t, s, uuid))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(raw[contentOff:], content) {
		t.Fatalf("content not preserved at offset %d", contentOff)
	}
	if !bytes.Equal(raw[:PrefixLen], uuid[:]) {
		t.Fatalf("UUID prefix not written")
	}
}

func TestReplaceMetaPreservesContent(t *testing.T) {
	s := newStore(t)
	uuid := mkUUID(3)
	content := []byte("payload-bytes-1234567890")
	rec := fileRec(uuid, blobmeta.RootDirUUID, "f", int64(len(content)))
	if err := s.WriteMeta(rec, content); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}

	rec.Mode = 0o600
	rec.Name = "renamed"
	if err := s.ReplaceMeta(rec); err != nil {
		t.Fatalf("ReplaceMeta: %v", err)
	}

	got, contentOff, err := s.ReadMeta(uuid)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if got.Mode != 0o600 || got.Name != "renamed" {
		t.Fatalf("metadata not updated: %+v", got)
	}
	raw, _ := os.ReadFile(mustPath(t, s, uuid))
	if !bytes.Equal(raw[contentOff:], content) {
		t.Fatalf("content lost after ReplaceMeta")
	}
}

func TestMultiUnitMetaThroughStore(t *testing.T) {
	s := newStore(t)
	uuid := mkUUID(4)
	rec := fileRec(uuid, blobmeta.RootDirUUID, "x", 1)
	for i := 0; i < 8; i++ {
		rec.Xattrs = append(rec.Xattrs, blobmeta.Xattr{
			Name:  "user.k" + string(rune('0'+i)),
			Value: bytes.Repeat([]byte{byte(i)}, 400),
		})
	}
	if err := s.WriteMeta(rec, []byte("y")); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	got, contentOff, err := s.ReadMeta(uuid)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if len(got.Xattrs) != 8 {
		t.Fatalf("xattrs lost: %d", len(got.Xattrs))
	}
	if (contentOff-PrefixLen)%blobmeta.UnitSize != 0 || contentOff <= PrefixLen+blobmeta.UnitSize {
		t.Fatalf("expected multi-unit contentOff, got %d", contentOff)
	}
}

func TestDelete(t *testing.T) {
	s := newStore(t)
	uuid := mkUUID(5)
	if err := s.WriteMeta(fileRec(uuid, blobmeta.RootDirUUID, "gone", 0), nil); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	if err := s.Delete(uuid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := s.ReadMeta(uuid); err != ErrNotExist {
		t.Fatalf("expected ErrNotExist, got %v", err)
	}
	if err := s.Delete(uuid); err != nil {
		t.Fatalf("Delete of missing blob should be nil, got %v", err)
	}
}

func TestPrefixMismatchDetected(t *testing.T) {
	s := newStore(t)
	uuid := mkUUID(6)
	if err := s.WriteMeta(fileRec(uuid, blobmeta.RootDirUUID, "f", 0), nil); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	p := mustPath(t, s, uuid)
	raw, _ := os.ReadFile(p)
	raw[0] ^= 0xFF
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := s.ReadMeta(uuid); err != ErrPrefixMismatch {
		t.Fatalf("expected ErrPrefixMismatch, got %v", err)
	}
}

func TestNoTmpLeftBehind(t *testing.T) {
	s := newStore(t)
	uuid := mkUUID(7)
	if err := s.WriteMeta(fileRec(uuid, blobmeta.RootDirUUID, "f", 1), []byte("q")); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	err := filepath.WalkDir(s.Dir(), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(p) == ".tmp" {
			t.Fatalf("leftover tmp file: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	s := newStore(t)
	want := map[[16]byte]string{}
	for i := byte(10); i < 30; i++ {
		u := mkUUID(i)
		name := "file" + string(rune('a'+i))
		if err := s.WriteMeta(fileRec(u, blobmeta.RootDirUUID, name, int64(i)), bytes.Repeat([]byte{i}, int(i))); err != nil {
			t.Fatalf("WriteMeta: %v", err)
		}
		want[u] = name
	}

	got := map[[16]byte]string{}
	var corrupt []string
	err := s.Scan(func(uuid [16]byte, rec *blobmeta.MetaRecord, contentSize int64) error {
		got[uuid] = rec.Name
		if rec.Type == blobmeta.TypeRegular {
			b, _ := uuidByte(uuid)
			if contentSize != int64(b) {
				t.Fatalf("contentSize for %v = %d, want %d", uuid, contentSize, b)
			}
		}
		return nil
	}, func(p string, err error) { corrupt = append(corrupt, p) })
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(corrupt) != 0 {
		t.Fatalf("unexpected corrupt blobs: %v", corrupt)
	}
	// root + 20 files
	if len(got) != len(want)+1 {
		t.Fatalf("Scan found %d blobs, want %d", len(got), len(want)+1)
	}
	for u, n := range want {
		if got[u] != n {
			t.Fatalf("Scan missed/mismatched %v: got %q want %q", u, got[u], n)
		}
	}
}

func TestScanSkipsCorrupt(t *testing.T) {
	s := newStore(t)
	good := mkUUID(40)
	bad := mkUUID(41)
	s.WriteMeta(fileRec(good, blobmeta.RootDirUUID, "good", 0), nil)
	s.WriteMeta(fileRec(bad, blobmeta.RootDirUUID, "bad", 0), nil)

	// Corrupt the info-chunk (not the prefix) of "bad".
	p := mustPath(t, s, bad)
	raw, _ := os.ReadFile(p)
	raw[PrefixLen+20] ^= 0xFF
	os.WriteFile(p, raw, 0600)

	seen := map[string]bool{}
	var corrupt []string
	err := s.Scan(func(uuid [16]byte, rec *blobmeta.MetaRecord, _ int64) error {
		seen[rec.Name] = true
		return nil
	}, func(pth string, err error) { corrupt = append(corrupt, pth) })
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !seen["good"] || seen["bad"] {
		t.Fatalf("Scan result wrong: %v", seen)
	}
	if len(corrupt) != 1 {
		t.Fatalf("expected 1 corrupt blob reported, got %d", len(corrupt))
	}
}

// --- helpers ---

func mustPath(t *testing.T, s *Store, uuid [16]byte) string {
	t.Helper()
	p, err := s.blobPath(uuid)
	if err != nil {
		t.Fatalf("blobPath: %v", err)
	}
	return p
}

func uuidByte(u [16]byte) (byte, bool) {
	b := u[0]
	for _, x := range u {
		if x != b {
			return 0, false
		}
	}
	return b, true
}
