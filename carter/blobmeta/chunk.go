package blobmeta

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Info-chunk framing (CON-3.1). Every unit is exactly UnitSize bytes on disk:
//
//	16 bytes   random nonce
//	496 bytes  AES-256-GCM ciphertext (480 plaintext + 16 tag)
//
// Unit 0 plaintext: version(1) ‖ flags(1) ‖ metaLen(uint16 BE) ‖ tlv[0:476]
// Unit i plaintext: tlv[476 + 480*(i-1) : …]
//
// On disk the whole chunk is 512*unitCount bytes of uniform random-looking
// data: no magic, no cleartext length, no cleartext unit count.
const (
	UnitSize     = 512
	unitNonceLen = 16
	unitTagLen   = 16
	unitPlainLen = UnitSize - unitNonceLen - unitTagLen // 480

	unit0HdrLen  = 4                          // version + flags + uint16 metaLen
	unit0Payload = unitPlainLen - unit0HdrLen // 476
	unitNPayload = unitPlainLen               // 480

	formatVersion = 3
	flagMore      = 0x01

	// MaxInfoChunkUnits caps how far a reader will follow the MORE flag,
	// bounding a malformed/hostile chunk. 65535-byte records fit well under
	// this (≈137 units).
	MaxInfoChunkUnits = 256
)

const aadSuffix = "carter-blobmeta-v1"

var (
	errKeyLen        = errors.New("blobmeta: key must be 32 bytes")
	errChunkShort    = errors.New("blobmeta: info-chunk buffer shorter than unit count requires")
	errUnitVersion   = errors.New("blobmeta: info-chunk unit has wrong format version")
	errUnitCountMism = errors.New("blobmeta: MORE flag and derived unit count disagree")
	errTooManyUnits  = errors.New("blobmeta: info-chunk exceeds MaxInfoChunkUnits")
)

// UnitCountFor returns how many 512-byte units a record of metaLen bytes
// occupies.
func UnitCountFor(metaLen int) int {
	if metaLen <= unit0Payload {
		return 1
	}
	rest := metaLen - unit0Payload
	return 1 + (rest+unitNPayload-1)/unitNPayload
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errKeyLen
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(blk, unitNonceLen)
}

// unitAAD binds a unit to its file UUID and its position in the chunk.
func unitAAD(uuid [16]byte, index int) []byte {
	aad := make([]byte, 16+4+len(aadSuffix))
	copy(aad, uuid[:])
	binary.BigEndian.PutUint32(aad[16:20], uint32(index))
	copy(aad[20:], aadSuffix)
	return aad
}

// SealInfoChunk marshals rec and returns its sealed info-chunk: a byte slice
// of length 512*unitCount, ready to be written as the prefix of the blob.
// key is K_meta(rec.FileUUID), 32 bytes.
func SealInfoChunk(key []byte, rec *MetaRecord) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	tlv, err := rec.Marshal()
	if err != nil {
		return nil, err
	}
	n := UnitCountFor(len(tlv))
	if n > MaxInfoChunkUnits {
		return nil, errTooManyUnits
	}

	out := make([]byte, 0, n*UnitSize)
	for i := 0; i < n; i++ {
		plain := make([]byte, unitPlainLen)
		if i == 0 {
			plain[0] = formatVersion
			if n > 1 {
				plain[1] = flagMore
			}
			binary.BigEndian.PutUint16(plain[2:4], uint16(len(tlv)))
			copy(plain[unit0HdrLen:], tlv[:min(len(tlv), unit0Payload)])
		} else {
			start := unit0Payload + (i-1)*unitNPayload
			copy(plain, tlv[start:min(len(tlv), start+unitNPayload)])
		}

		nonce := make([]byte, unitNonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		out = append(out, nonce...)
		out = gcm.Seal(out, nonce, plain, unitAAD(rec.FileUUID, i))
	}
	return out, nil
}

// openUnit decrypts one 512-byte unit and returns its 480-byte plaintext.
func openUnit(gcm cipher.AEAD, uuid [16]byte, index int, unit []byte) ([]byte, error) {
	if len(unit) != UnitSize {
		return nil, errChunkShort
	}
	nonce := unit[:unitNonceLen]
	ct := unit[unitNonceLen:]
	return gcm.Open(nil, nonce, ct, unitAAD(uuid, index))
}

// parseUnit0 splits a decrypted unit-0 plaintext into its header fields and
// its 476-byte TLV payload slice.
func parseUnit0(plain []byte) (more bool, metaLen int, payload []byte, err error) {
	if plain[0] != formatVersion {
		return false, 0, nil, errUnitVersion
	}
	more = plain[1]&flagMore != 0
	metaLen = int(binary.BigEndian.Uint16(plain[2:4]))
	return more, metaLen, plain[unit0HdrLen:], nil
}

// DecodeInfoChunk parses a sealed info-chunk already fully in memory and
// returns the record plus the total chunk length in bytes (the offset,
// relative to the start of the info-chunk, at which content blocks begin).
// key is K_meta(uuid); uuid must be the file's UUID (it is the AAD, so a
// wrong uuid fails authentication).
func DecodeInfoChunk(key []byte, uuid [16]byte, chunk []byte) (*MetaRecord, int64, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, 0, err
	}
	if len(chunk) < UnitSize {
		return nil, 0, errChunkShort
	}
	plain0, err := openUnit(gcm, uuid, 0, chunk[:UnitSize])
	if err != nil {
		return nil, 0, fmt.Errorf("blobmeta: unit 0: %w", err)
	}
	more, metaLen, p0, err := parseUnit0(plain0)
	if err != nil {
		return nil, 0, err
	}
	n := UnitCountFor(metaLen)
	if (n > 1) != more {
		return nil, 0, errUnitCountMism
	}
	if n > MaxInfoChunkUnits {
		return nil, 0, errTooManyUnits
	}
	if len(chunk) < n*UnitSize {
		return nil, 0, errChunkShort
	}

	tlv := make([]byte, 0, metaLen)
	tlv = append(tlv, p0[:min(metaLen, unit0Payload)]...)
	for i := 1; i < n; i++ {
		pi, err := openUnit(gcm, uuid, i, chunk[i*UnitSize:(i+1)*UnitSize])
		if err != nil {
			return nil, 0, fmt.Errorf("blobmeta: unit %d: %w", i, err)
		}
		take := min(metaLen-len(tlv), unitNPayload)
		tlv = append(tlv, pi[:take]...)
	}

	rec, err := UnmarshalRecord(tlv)
	if err != nil {
		return nil, 0, err
	}
	return rec, int64(n) * UnitSize, nil
}

// ReadInfoChunk is DecodeInfoChunk over an io.ReaderAt (a blob file): it
// reads unit 0, learns the unit count, reads the remainder, and returns the
// record plus the content-start offset.
func ReadInfoChunk(key []byte, uuid [16]byte, ra io.ReaderAt) (*MetaRecord, int64, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, 0, err
	}
	buf0 := make([]byte, UnitSize)
	if _, err := readFullAt(ra, buf0, 0); err != nil {
		return nil, 0, err
	}
	plain0, err := openUnit(gcm, uuid, 0, buf0)
	if err != nil {
		return nil, 0, fmt.Errorf("blobmeta: unit 0: %w", err)
	}
	more, metaLen, p0, err := parseUnit0(plain0)
	if err != nil {
		return nil, 0, err
	}
	n := UnitCountFor(metaLen)
	if (n > 1) != more {
		return nil, 0, errUnitCountMism
	}
	if n > MaxInfoChunkUnits {
		return nil, 0, errTooManyUnits
	}
	if n == 1 {
		rec, err := UnmarshalRecord(p0[:min(metaLen, unit0Payload)])
		if err != nil {
			return nil, 0, err
		}
		return rec, UnitSize, nil
	}

	rest := make([]byte, (n-1)*UnitSize)
	if _, err := readFullAt(ra, rest, UnitSize); err != nil {
		return nil, 0, err
	}
	tlv := make([]byte, 0, metaLen)
	tlv = append(tlv, p0...)
	for i := 1; i < n; i++ {
		off := (i - 1) * UnitSize
		pi, err := openUnit(gcm, uuid, i, rest[off:off+UnitSize])
		if err != nil {
			return nil, 0, fmt.Errorf("blobmeta: unit %d: %w", i, err)
		}
		take := min(metaLen-len(tlv), unitNPayload)
		tlv = append(tlv, pi[:take]...)
	}
	rec, err := UnmarshalRecord(tlv)
	if err != nil {
		return nil, 0, err
	}
	return rec, int64(n) * UnitSize, nil
}

func readFullAt(ra io.ReaderAt, buf []byte, off int64) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := ra.ReadAt(buf[got:], off+int64(got))
		got += n
		if err != nil {
			if err == io.EOF && got == len(buf) {
				return got, nil
			}
			return got, err
		}
	}
	return got, nil
}
