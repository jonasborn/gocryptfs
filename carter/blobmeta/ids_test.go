package blobmeta

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestMetaKeyIndexRange(t *testing.T) {
	kIndex := make([]byte, 32)
	rand.Read(kIndex)
	for i := 0; i < 5000; i++ {
		var uuid [16]byte
		rand.Read(uuid[:])
		idx := MetaKeyIndex(kIndex, uuid)
		if idx < IdxMetaBase || idx >= IdxMetaMax {
			t.Fatalf("MetaKeyIndex out of range: %#016x", idx)
		}
		if idx >= IdxReservedBase {
			t.Fatalf("MetaKeyIndex collides with reserved range: %#016x", idx)
		}
	}
}

func TestMetaKeyIndexDeterministicAndKeyed(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	var uuid [16]byte
	rand.Read(uuid[:])

	if MetaKeyIndex(k1, uuid) != MetaKeyIndex(k1, uuid) {
		t.Fatal("MetaKeyIndex not deterministic")
	}
	if MetaKeyIndex(k1, uuid) == MetaKeyIndex(k2, uuid) {
		t.Fatal("MetaKeyIndex should depend on K_index")
	}
}

func TestBlobIDDeterministicAndKeyed(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	var uuid [16]byte
	rand.Read(uuid[:])

	if BlobID(k1, uuid) != BlobID(k1, uuid) {
		t.Fatal("BlobID not deterministic")
	}
	if BlobID(k1, uuid) == BlobID(k2, uuid) {
		t.Fatal("BlobID should depend on K_index")
	}
	var uuid2 [16]byte
	copy(uuid2[:], uuid[:])
	uuid2[7] ^= 0x40
	if BlobID(k1, uuid) == BlobID(k1, uuid2) {
		t.Fatal("BlobID should depend on the UUID")
	}
}

func TestReservedIndicesDisjoint(t *testing.T) {
	if IdxBlobIDKey < IdxReservedBase || IdxIndexCacheKey < IdxReservedBase {
		t.Fatal("reserved singleton indices must be >= IdxReservedBase")
	}
	if IdxMetaMax > IdxReservedBase {
		t.Fatal("meta range must not overlap the reserved range")
	}
	if IdxMetaBase>>63 != 1 {
		t.Fatal("IdxMetaBase must have the top bit set")
	}
}

func TestShardPath(t *testing.T) {
	id := [16]byte{0xab, 0xcd, 0x01}
	full := hex.EncodeToString(id[:]) // 32 hex chars
	if got := BlobName(id); got != full {
		t.Fatalf("BlobName = %q, want %q", got, full)
	}
	if got := Bucket(id); got != "ab" {
		t.Fatalf("Bucket = %q", got)
	}
	if got := ShardPath(id); got != "ab/"+full {
		t.Fatalf("ShardPath = %q, want %q", got, "ab/"+full)
	}
	if len(full) != 32 {
		t.Fatalf("blob name should be 32 hex chars, got %d", len(full))
	}
}
