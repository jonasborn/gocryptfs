package externalenc

import (
	"encoding/binary"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/carter/proto"
)

// This package's Client talks to a real KS + real card (JCSW-emulated or
// physical) via ksclient/cardclient — per project rule ("Zero Mocks... NEVER
// use mocks or test doubles for external systems: card, emulator, DB"), that
// end-to-end path is verified against the live stack (service.bat test, then
// `115fs test`/a real mount — see components/115fs/AGENTS.md and the PR's
// testing notes), not faked here. What's left to unit-test in isolation is
// the pure, side-effect-free logic: the LRU caches, the directory-IV → key
// index mapping, and the DERIVE_BLOCK_KEYS batching arithmetic.

func TestNameKeyIndexClearsSignBitAndRejectsShortIV(t *testing.T) {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint64(iv, 0xFFFFFFFFFFFFFFFF)
	idx, err := nameKeyIndex(iv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx>>63 != 0 {
		t.Fatalf("sign bit not cleared: %x", idx)
	}
	if idx != 0x7FFFFFFFFFFFFFFF {
		t.Fatalf("unexpected index: %x", idx)
	}

	if _, err := nameKeyIndex(iv[:4]); err == nil {
		t.Fatal("expected error for a directory IV shorter than 8 bytes")
	}
}

func TestKeyIDHex(t *testing.T) {
	if got := keyIDHex(0x52); got != "52" {
		t.Errorf("keyIDHex(0x52) = %q, want %q", got, "52")
	}
	if got := keyIDHex(0x00); got != "00" {
		t.Errorf("keyIDHex(0x00) = %q, want %q", got, "00")
	}
}

func TestUntrustedBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://192.168.2.223:9443": "http://192.168.2.223:9080",
		"https://127.0.0.1:9443":     "http://127.0.0.1:9080",
	}
	for in, want := range cases {
		if got := untrustedBaseURL(in); got != want {
			t.Errorf("untrustedBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// wantBatches computes the expected batch plan for (start, count) generically
// against proto.MaxBlockKeyBatch, so this test doesn't need updating every
// time that constant changes (it changed once already — see its own comment
// on the 5->3 reduction after live overflow testing against the real card).
func wantBatches(start uint64, count int) []keyBatch {
	if count <= 0 {
		return nil
	}
	var batches []keyBatch
	remaining := count
	idx := start
	for remaining > 0 {
		b := remaining
		if b > proto.MaxBlockKeyBatch {
			b = proto.MaxBlockKeyBatch
		}
		batches = append(batches, keyBatch{start: idx, count: b})
		idx += uint64(b)
		remaining -= b
	}
	return batches
}

func TestPlanKeyBatchesRespectsCardHardLimit(t *testing.T) {
	cases := []struct {
		start uint64
		count int
		want  []keyBatch
	}{
		{0, 0, nil},
		{0, 1, []keyBatch{{0, 1}}},
		{0, proto.MaxBlockKeyBatch, []keyBatch{{0, proto.MaxBlockKeyBatch}}},
		{0, proto.MaxBlockKeyBatch + 1, []keyBatch{{0, proto.MaxBlockKeyBatch}, {proto.MaxBlockKeyBatch, 1}}},
		{10, 64, wantBatches(10, 64)},
	}
	for _, tc := range cases {
		got := planKeyBatches(tc.start, tc.count)
		if len(got) != len(tc.want) {
			t.Fatalf("planKeyBatches(%d, %d) = %+v, want %+v", tc.start, tc.count, got, tc.want)
		}
		total := 0
		for i, b := range got {
			if b != tc.want[i] {
				t.Fatalf("planKeyBatches(%d, %d)[%d] = %+v, want %+v", tc.start, tc.count, i, b, tc.want[i])
			}
			if b.count > proto.MaxBlockKeyBatch {
				t.Fatalf("batch %+v exceeds MaxBlockKeyBatch=%d", b, proto.MaxBlockKeyBatch)
			}
			total += b.count
		}
		if total != tc.count {
			t.Fatalf("planKeyBatches(%d, %d) covers %d keys, want %d", tc.start, tc.count, total, tc.count)
		}
	}
}

func TestSmartAEADCacheEvictsLRUAndZeroesKeyMaterial(t *testing.T) {
	c := newSmartAEADCache(2)
	key0 := make([]byte, 32)
	key0[0] = 0xAA
	key1 := make([]byte, 32)
	key1[0] = 0xBB
	key2 := make([]byte, 32)
	key2[0] = 0xCC

	if _, err := c.put(0, key0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.put(1, key1); err != nil {
		t.Fatal(err)
	}
	// Touch 0 so it's most-recently-used; 1 becomes the eviction target.
	if _, _, ok := c.get(0); !ok {
		t.Fatal("expected block 0 to be cached")
	}
	if _, err := c.put(2, key2); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.get(1); ok {
		t.Fatal("expected block 1 to have been evicted (least recently used)")
	}
	if _, _, ok := c.get(0); !ok {
		t.Fatal("expected block 0 to still be cached")
	}
	if _, _, ok := c.get(2); !ok {
		t.Fatal("expected block 2 to be cached")
	}

	c.purge()
	if _, _, ok := c.get(0); ok {
		t.Fatal("expected cache to be empty after purge")
	}
	if len(c.items) != 0 {
		t.Fatalf("expected 0 items after purge, got %d", len(c.items))
	}
}

func TestSmartEMECacheEvictsLRU(t *testing.T) {
	c := newSmartEMECache(1)
	key0 := make([]byte, 32)
	key1 := make([]byte, 32)

	if _, err := c.put(100, key0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.put(200, key1); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.get(100); ok {
		t.Fatal("expected directory 100's key to have been evicted")
	}
	if _, ok := c.get(200); !ok {
		t.Fatal("expected directory 200's key to still be cached")
	}
}
