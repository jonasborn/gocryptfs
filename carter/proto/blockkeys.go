package proto

import (
	"encoding/binary"
	"fmt"
)

// EncodeDeriveBlockKeyPayload builds the DERIVE_BLOCK_KEY (0x0D) command
// payload: keyId(1) || blockIndex(8,BE) || prefixLen(1) || prefix
// (FsCardClient.blockKeyPayload()).
func EncodeDeriveBlockKeyPayload(keyID byte, blockIndex uint64, usagePrefix []byte) []byte {
	payload := make([]byte, 10+len(usagePrefix))
	payload[0] = keyID
	binary.BigEndian.PutUint64(payload[1:9], blockIndex)
	payload[9] = byte(len(usagePrefix))
	copy(payload[10:], usagePrefix)
	return payload
}

// DecodeDeriveBlockKeyResponse validates and returns the single 32-byte key
// in a DERIVE_BLOCK_KEY response payload.
func DecodeDeriveBlockKeyResponse(payload []byte) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("proto: malformed DERIVE_BLOCK_KEY response (%d bytes)", len(payload))
	}
	return payload, nil
}

// EncodeDeriveBlockKeysPayload builds the DERIVE_BLOCK_KEYS (0x18) command
// payload: keyId(1) || startIndex(8,BE) || count(1) || prefixLen(1) || prefix
// (FsCardClient.deriveBlockKeys()). count must be 1..MaxBlockKeyBatch — the
// card rejects anything above that with SW_WRONG_DATA.
func EncodeDeriveBlockKeysPayload(keyID byte, startIndex uint64, count int, usagePrefix []byte) ([]byte, error) {
	if count < 1 || count > MaxBlockKeyBatch {
		return nil, fmt.Errorf("proto: count must be 1..%d (MAX_BLOCK_KEY_BATCH), got %d", MaxBlockKeyBatch, count)
	}
	payload := make([]byte, 11+len(usagePrefix))
	payload[0] = keyID
	binary.BigEndian.PutUint64(payload[1:9], startIndex)
	payload[9] = byte(count)
	payload[10] = byte(len(usagePrefix))
	copy(payload[11:], usagePrefix)
	return payload, nil
}

// DecodeDeriveBlockKeysResponse splits a DERIVE_BLOCK_KEYS response payload
// into count consecutive 32-byte keys, in order.
func DecodeDeriveBlockKeysResponse(payload []byte, count int) ([][]byte, error) {
	if len(payload) != count*32 {
		return nil, fmt.Errorf("proto: malformed DERIVE_BLOCK_KEYS response (%d bytes, want %d)", len(payload), count*32)
	}
	keys := make([][]byte, count)
	for i := 0; i < count; i++ {
		keys[i] = payload[i*32 : (i+1)*32]
	}
	return keys, nil
}
