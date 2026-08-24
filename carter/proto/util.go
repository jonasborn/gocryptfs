package proto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// b64enc/b64dec use standard (padded) base64, matching the Java reference's
// Base64.getEncoder()/getDecoder() used throughout components/115proto.
func b64enc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func b64dec(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// newUUID generates a random RFC 4122 version-4 UUID string. Only used as an
// opaque, collision-resistant messageId/requestId — no need to pull in an
// external uuid dependency for that.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("proto: reading random bytes for UUID: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
