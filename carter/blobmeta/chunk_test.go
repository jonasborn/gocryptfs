package blobmeta

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestInfoChunkSingleUnitRoundTrip(t *testing.T) {
	key := testKey(t)
	in := sampleRecord()

	chunk, err := SealInfoChunk(key, in)
	if err != nil {
		t.Fatalf("SealInfoChunk: %v", err)
	}
	if len(chunk) != UnitSize {
		t.Fatalf("expected a single %d-byte unit, got %d bytes", UnitSize, len(chunk))
	}

	out, contentOff, err := DecodeInfoChunk(key, in.FileUUID, chunk)
	if err != nil {
		t.Fatalf("DecodeInfoChunk: %v", err)
	}
	if contentOff != UnitSize {
		t.Fatalf("contentOff: got %d want %d", contentOff, UnitSize)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestInfoChunkMultiUnitRoundTrip(t *testing.T) {
	key := testKey(t)
	in := sampleRecord()
	// ~3 KiB of xattrs -> several continuation units.
	for i := 0; i < 6; i++ {
		in.Xattrs = append(in.Xattrs, Xattr{
			Name:  "user.attr" + string(rune('0'+i)),
			Value: bytes.Repeat([]byte{byte(i + 1)}, 500),
		})
	}

	chunk, err := SealInfoChunk(key, in)
	if err != nil {
		t.Fatalf("SealInfoChunk: %v", err)
	}
	if len(chunk) <= UnitSize || len(chunk)%UnitSize != 0 {
		t.Fatalf("expected a multi-unit chunk, got %d bytes", len(chunk))
	}

	out, contentOff, err := DecodeInfoChunk(key, in.FileUUID, chunk)
	if err != nil {
		t.Fatalf("DecodeInfoChunk: %v", err)
	}
	if int(contentOff) != len(chunk) {
		t.Fatalf("contentOff %d != chunk len %d", contentOff, len(chunk))
	}
	if out.Name != in.Name || len(out.Xattrs) != len(in.Xattrs) {
		t.Fatalf("multi-unit round trip mismatch: %+v", out)
	}
	for i := range in.Xattrs {
		if out.Xattrs[i].Name != in.Xattrs[i].Name || !bytes.Equal(out.Xattrs[i].Value, in.Xattrs[i].Value) {
			t.Fatalf("xattr %d mismatch", i)
		}
	}

	// ReadInfoChunk (io.ReaderAt path) must agree with DecodeInfoChunk.
	out2, off2, err := ReadInfoChunk(key, in.FileUUID, bytes.NewReader(chunk))
	if err != nil {
		t.Fatalf("ReadInfoChunk: %v", err)
	}
	if off2 != contentOff || out2.Name != out.Name || len(out2.Xattrs) != len(out.Xattrs) {
		t.Fatalf("ReadInfoChunk disagrees with DecodeInfoChunk")
	}
}

func TestInfoChunkWrongKeyFails(t *testing.T) {
	in := sampleRecord()
	chunk, err := SealInfoChunk(testKey(t), in)
	if err != nil {
		t.Fatalf("SealInfoChunk: %v", err)
	}
	if _, _, err := DecodeInfoChunk(testKey(t), in.FileUUID, chunk); err == nil {
		t.Fatal("expected DecodeInfoChunk to fail under a different key")
	}
}

func TestInfoChunkWrongUUIDFails(t *testing.T) {
	key := testKey(t)
	in := sampleRecord()
	chunk, err := SealInfoChunk(key, in)
	if err != nil {
		t.Fatalf("SealInfoChunk: %v", err)
	}
	wrong := in.FileUUID
	wrong[0] ^= 0xFF
	if _, _, err := DecodeInfoChunk(key, wrong, chunk); err == nil {
		t.Fatal("expected DecodeInfoChunk to fail with the wrong UUID (AAD)")
	}
}

func TestInfoChunkTamperDetected(t *testing.T) {
	key := testKey(t)
	in := sampleRecord()
	chunk, err := SealInfoChunk(key, in)
	if err != nil {
		t.Fatalf("SealInfoChunk: %v", err)
	}
	for _, pos := range []int{0, unitNonceLen, unitNonceLen + 5, len(chunk) - 1} {
		bad := append([]byte(nil), chunk...)
		bad[pos] ^= 0x01
		if _, _, err := DecodeInfoChunk(key, in.FileUUID, bad); err == nil {
			t.Fatalf("expected DecodeInfoChunk to detect a flipped bit at offset %d", pos)
		}
	}
}

func TestInfoChunkShortBuffer(t *testing.T) {
	key := testKey(t)
	in := sampleRecord()
	chunk, _ := SealInfoChunk(key, in)
	if _, _, err := DecodeInfoChunk(key, in.FileUUID, chunk[:UnitSize-1]); err == nil {
		t.Fatal("expected DecodeInfoChunk to reject a sub-unit buffer")
	}
}

func TestUnitCountFor(t *testing.T) {
	cases := map[int]int{
		0:                               1,
		unit0Payload:                    1,
		unit0Payload + 1:                2,
		unit0Payload + unitNPayload:     2,
		unit0Payload + unitNPayload + 1: 3,
	}
	for metaLen, want := range cases {
		if got := UnitCountFor(metaLen); got != want {
			t.Fatalf("UnitCountFor(%d) = %d, want %d", metaLen, got, want)
		}
	}
}

func TestSealRejectsBadKeyLen(t *testing.T) {
	if _, err := SealInfoChunk(make([]byte, 16), sampleRecord()); err == nil {
		t.Fatal("expected SealInfoChunk to reject a 16-byte key")
	}
}
