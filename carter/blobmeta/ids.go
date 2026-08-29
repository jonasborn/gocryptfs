package blobmeta

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Card block-index space partitioning (CON-3.1).
//
// DERIVE_BLOCK_KEY(keyId, index uint64, usagePrefix) is the only key source.
// The uint64 index space is carved so the three uses can never collide:
//
//	[0x0000000000000000, IdxMetaBase)      content-block keys (small sequential offsets)
//	[IdxMetaBase,        IdxMetaMax)       per-file info-chunk keys (K_meta)
//	[IdxReservedBase,    max]              reserved singletons (K_index, K_idx, …)
const (
	IdxMetaBase uint64 = 0x8000000000000000
	IdxMetaMax  uint64 = 0xC000000000000000

	IdxReservedBase uint64 = 0xFFFFFFFFFFFFFF00

	// IdxBlobIDKey derives K_index: the key for BlobID and MetaKeyIndex.
	IdxBlobIDKey uint64 = 0xFFFFFFFFFFFFFF01
	// IdxIndexCacheKey derives K_idx: the key that seals idx/tree.
	IdxIndexCacheKey uint64 = 0xFFFFFFFFFFFFFF02
)

// RootDirUUID is the fixed FileUUID of the filesystem root directory blob.
// Its ParentDirID is the all-zero value.
var RootDirUUID = [16]byte{'C', 'A', 'R', 'T', 'E', 'R', '-', 'R', 'O', 'O', 'T', 0, 0, 0, 0, 0}

var (
	blobIDInfo  = []byte("carter-blobid-v1")
	metaIdxInfo = []byte("carter-metaidx-v1")
)

// BlobID derives the 16-byte opaque backing-store id for a file from its
// UUID and the mount's card-derived index key K_index.
func BlobID(kIndex []byte, uuid [16]byte) [16]byte {
	m := hmac.New(sha256.New, kIndex)
	m.Write(blobIDInfo)
	m.Write(uuid[:])
	var out [16]byte
	copy(out[:], m.Sum(nil))
	return out
}

// MetaKeyIndex maps a file UUID to its info-chunk key's card block index.
// The result always lands in [IdxMetaBase, IdxMetaMax): the top bit is set
// and the next bit is clear, so it can never collide with a content-block
// index (top bit clear) or a reserved singleton (top eight bits set).
func MetaKeyIndex(kIndex []byte, uuid [16]byte) uint64 {
	m := hmac.New(sha256.New, kIndex)
	m.Write(metaIdxInfo)
	m.Write(uuid[:])
	v := binary.BigEndian.Uint64(m.Sum(nil)[:8])
	return IdxMetaBase | (v >> 2)
}

// Bucket returns the two-hex-digit shard directory name for a blob id.
func Bucket(id [16]byte) string {
	return hex.EncodeToString(id[:1])
}

// BlobName returns the full 32-hex-digit backing file name for a blob id.
func BlobName(id [16]byte) string {
	return hex.EncodeToString(id[:])
}

// ShardPath returns the bucket-relative path for a blob id: "ab/abcd…ef".
func ShardPath(id [16]byte) string {
	full := hex.EncodeToString(id[:])
	return full[:2] + "/" + full
}
