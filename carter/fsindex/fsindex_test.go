package fsindex

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/carter/blobmeta"
	"github.com/rfjakob/gocryptfs/v2/carter/blobstore"
)

type fakeKeys struct{ seed string }

func (k fakeKeys) derive(label string) []byte {
	h := sha256.Sum256([]byte(k.seed + "|" + label))
	return h[:]
}
func (k fakeKeys) IndexKey() ([]byte, error) { return k.derive("index"), nil }
func (k fakeKeys) MetaKey(u [16]byte) ([]byte, error) {
	return k.derive("meta:" + string(u[:])), nil
}

func kIdx() []byte {
	h := sha256.Sum256([]byte("K_idx-test"))
	return h[:]
}

func mkUUID(b byte) [16]byte {
	var u [16]byte
	for i := range u {
		u[i] = b
	}
	return u
}

func dirRec(uuid, parent [16]byte, name string) *blobmeta.MetaRecord {
	return &blobmeta.MetaRecord{
		SchemaVersion: blobmeta.SchemaVersion, FileUUID: uuid, ParentDirID: parent,
		Name: name, Type: blobmeta.TypeDir, Mode: 0o40755,
	}
}
func fileRec(uuid, parent [16]byte, name string) *blobmeta.MetaRecord {
	return &blobmeta.MetaRecord{
		SchemaVersion: blobmeta.SchemaVersion, FileUUID: uuid, ParentDirID: parent,
		Name: name, Type: blobmeta.TypeRegular, Mode: 0o644,
	}
}

// buildStore makes a store with: root/  dirA/  root/f1  dirA/f2
func buildStore(t *testing.T) (*blobstore.Store, [16]byte, [16]byte) {
	t.Helper()
	st, err := blobstore.Init(t.TempDir(), fakeKeys{seed: "s"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	root := blobmeta.RootDirUUID
	dirA := mkUUID(0xA0)
	f1 := mkUUID(0xF1)
	f2 := mkUUID(0xF2)
	must(t, st.WriteMeta(dirRec(dirA, root, "dirA"), nil))
	must(t, st.WriteMeta(fileRec(f1, root, "f1"), []byte("one")))
	must(t, st.WriteMeta(fileRec(f2, dirA, "f2"), []byte("two")))
	return st, dirA, f1
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func TestRebuildTree(t *testing.T) {
	st, dirA, f1 := buildStore(t)
	idx, err := Rebuild(st)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}

	rootKids := idx.Children(blobmeta.RootDirUUID)
	if len(rootKids) != 2 {
		t.Fatalf("root should have 2 children, got %d", len(rootKids))
	}
	e, ok := idx.Lookup(blobmeta.RootDirUUID, "dirA")
	if !ok || e.UUID != dirA || e.Type != blobmeta.TypeDir {
		t.Fatalf("Lookup dirA: %+v ok=%v", e, ok)
	}
	e, ok = idx.Lookup(blobmeta.RootDirUUID, "f1")
	if !ok || e.UUID != f1 {
		t.Fatalf("Lookup f1: %+v ok=%v", e, ok)
	}
	if kids := idx.Children(dirA); len(kids) != 1 || kids[0].Name != "f2" {
		t.Fatalf("dirA children: %+v", kids)
	}
	if r, ok := idx.Get(f1); !ok || r.Name != "f1" || r.Type != blobmeta.TypeRegular {
		t.Fatalf("Get f1: %+v ok=%v", r, ok)
	}
	if !idx.HasChildren(dirA) || idx.HasChildren(mkUUID(0xF1)) {
		t.Fatalf("HasChildren wrong")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	st, dirA, _ := buildStore(t)
	idx, err := Rebuild(st)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if err := idx.Save(kIdx()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if idx.Gen() != 1 {
		t.Fatalf("gen after first Save = %d, want 1", idx.Gen())
	}

	loaded, err := Load(st.Dir(), kIdx())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Gen() != 1 {
		t.Fatalf("loaded gen = %d, want 1", loaded.Gen())
	}
	if e, ok := loaded.Lookup(blobmeta.RootDirUUID, "dirA"); !ok || e.UUID != dirA {
		t.Fatalf("loaded Lookup dirA failed: %+v ok=%v", e, ok)
	}
	if kids := loaded.Children(dirA); len(kids) != 1 || kids[0].Name != "f2" {
		t.Fatalf("loaded dirA children: %+v", kids)
	}
}

func TestLoadWrongKeyFails(t *testing.T) {
	st, _, _ := buildStore(t)
	idx, _ := Rebuild(st)
	if err := idx.Save(kIdx()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	wrong := sha256.Sum256([]byte("other"))
	if _, err := Load(st.Dir(), wrong[:]); !errors.Is(err, ErrNoCache) {
		t.Fatalf("expected ErrNoCache under wrong key, got %v", err)
	}
}

func TestLoadMissingFails(t *testing.T) {
	st, _, _ := buildStore(t)
	if _, err := Load(st.Dir(), kIdx()); !errors.Is(err, ErrNoCache) {
		t.Fatalf("expected ErrNoCache when idx/tree absent, got %v", err)
	}
}

func TestDirtyMarkerForcesRebuild(t *testing.T) {
	st, _, _ := buildStore(t)
	idx, _ := Rebuild(st)
	if err := idx.Save(kIdx()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := idx.MarkDirty(); err != nil {
		t.Fatalf("MarkDirty: %v", err)
	}
	if _, err := Load(st.Dir(), kIdx()); !errors.Is(err, ErrNoCache) {
		t.Fatalf("expected ErrNoCache with dirty marker, got %v", err)
	}
	// LoadOrRebuild recovers and clears the marker.
	rebuilt, err := LoadOrRebuild(st, kIdx())
	if err != nil {
		t.Fatalf("LoadOrRebuild: %v", err)
	}
	if _, ok := rebuilt.Get(blobmeta.RootDirUUID); !ok {
		t.Fatalf("rebuilt index has no root")
	}
	if _, err := os.Stat(filepath.Join(st.Dir(), dirtyFile)); !os.IsNotExist(err) {
		t.Fatalf("dirty marker not cleared: %v", err)
	}
	if _, err := Load(st.Dir(), kIdx()); err != nil {
		t.Fatalf("Load after LoadOrRebuild should succeed: %v", err)
	}
}

func TestLoadOrRebuildFirstRun(t *testing.T) {
	st, _, _ := buildStore(t)
	idx, err := LoadOrRebuild(st, kIdx())
	if err != nil {
		t.Fatalf("LoadOrRebuild: %v", err)
	}
	if kids := idx.Children(blobmeta.RootDirUUID); len(kids) != 2 {
		t.Fatalf("root children: %d", len(kids))
	}
	// idx/tree now exists and loads.
	if _, err := Load(st.Dir(), kIdx()); err != nil {
		t.Fatalf("Load after LoadOrRebuild: %v", err)
	}
}

func TestPutRenameMovesChild(t *testing.T) {
	st, dirA, f1 := buildStore(t)
	idx, _ := Rebuild(st)

	r, _ := idx.Get(f1)
	// rename f1 -> "f1b" and move it into dirA
	r.Name = "f1b"
	r.ParentDirID = dirA
	idx.Put(&r)

	if _, ok := idx.Lookup(blobmeta.RootDirUUID, "f1"); ok {
		t.Fatal("old entry still under root")
	}
	e, ok := idx.Lookup(dirA, "f1b")
	if !ok || e.UUID != f1 {
		t.Fatalf("moved entry not found in dirA: %+v ok=%v", e, ok)
	}
	if len(idx.Children(blobmeta.RootDirUUID)) != 1 {
		t.Fatalf("root should have 1 child after move")
	}
	if len(idx.Children(dirA)) != 2 {
		t.Fatalf("dirA should have 2 children after move")
	}
}

func TestRemove(t *testing.T) {
	st, _, f1 := buildStore(t)
	idx, _ := Rebuild(st)
	idx.Remove(f1)
	if _, ok := idx.Get(f1); ok {
		t.Fatal("record still present after Remove")
	}
	if _, ok := idx.Lookup(blobmeta.RootDirUUID, "f1"); ok {
		t.Fatal("entry still in parent after Remove")
	}
	idx.Remove(f1) // idempotent
}

func TestRebuildNoRootFails(t *testing.T) {
	st, _, _ := buildStore(t)
	if err := st.Delete(blobmeta.RootDirUUID); err != nil {
		t.Fatalf("Delete root: %v", err)
	}
	if _, err := Rebuild(st); err == nil {
		t.Fatal("expected Rebuild to fail with no root blob")
	}
}

func TestCacheSurvivesBlobLoss(t *testing.T) {
	// The point of the design: losing one blob loses one file, not the tree.
	st, dirA, f1 := buildStore(t)
	idx, _ := Rebuild(st)
	_ = f1

	// Nuke dirA's blob, keep everything else.
	if err := st.Delete(dirA); err != nil {
		t.Fatalf("Delete dirA: %v", err)
	}
	idx2, err := Rebuild(st)
	if err != nil {
		t.Fatalf("Rebuild after blob loss: %v", err)
	}
	if _, ok := idx2.Get(dirA); ok {
		t.Fatal("dirA should be gone")
	}
	if _, ok := idx2.Lookup(blobmeta.RootDirUUID, "f1"); !ok {
		t.Fatal("f1 should still be reachable after losing an unrelated blob")
	}
	// f2 is now an orphan (its parent blob is gone) but its record still
	// loads; it just hangs under a parent UUID with no dir record.
	if _, ok := idx.Get(dirA); !ok {
		t.Fatal("pre-loss index still had dirA")
	}
}
