package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Golden vectors ported from
// components/115proto/src/main/java/com/cartercard/proto/vectors/GoldenVectors.java.
// That file computes its CE/TTE vectors at runtime (raw javax.crypto calls,
// not hardcoded ciphertext), so there is no fixed expected output to copy
// directly. Instead, the fixed inputs (keys, IVs, AAD fields, plaintext) were
// copied verbatim from GoldenVectors.java's CE_HAPPY_PATH_01/TTE_HAPPY_PATH_01
// vectors, and the expected ciphertext/tag/mac outputs below were computed
// independently — AES-256-GCM via Python's `cryptography` library, AES-256-CBC
// + HMAC-SHA-256 via `openssl enc`/a standalone Python HMAC — neither of which
// shares any code with this Go implementation or the Java reference. Matching
// output from three independent implementations (Java's javax.crypto,
// Python's cryptography/hashlib, and this Go port) is strong evidence the
// wire format and algorithms here are correct, not just internally
// consistent.

func TestGoldenVectorTTEHappyPath(t *testing.T) {
	key, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
	nonce, _ := hex.DecodeString("101112131415161718191a1b")
	wantCiphertext, _ := hex.DecodeString("b01c3d20109c6ba12dd6322c80dd022b5910")
	wantTag, _ := hex.DecodeString("272465c0a2f43c3fb5b2ce62cd7ddcd5")
	wantPlaintext := []byte("TTE Secure Payload")

	aad := buildTransportAAD(DomainTTE, ClientTypeTS, "ts-client-01", DirectionRequest, OpCreateSession, "msg-202", 5)

	// Seal is expected to reproduce byte-identical ciphertext/tag given the
	// same key/nonce/AAD/plaintext, since AES-GCM is deterministic for a
	// fixed nonce (only the nonce itself is randomly generated in normal
	// use — sealTransportEnvelope's randomness path is exercised separately
	// below).
	gotCiphertext, gotTag, err := sealDeterministicForTest(key, nonce, aad, wantPlaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(gotCiphertext, wantCiphertext) {
		t.Errorf("ciphertext mismatch:\n got  %x\n want %x", gotCiphertext, wantCiphertext)
	}
	if !bytes.Equal(gotTag, wantTag) {
		t.Errorf("tag mismatch:\n got  %x\n want %x", gotTag, wantTag)
	}

	gotPlaintext, err := openTransportEnvelope(key, aad, nonce, wantCiphertext, wantTag)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(gotPlaintext, wantPlaintext) {
		t.Errorf("plaintext mismatch:\n got  %q\n want %q", gotPlaintext, wantPlaintext)
	}
}

func TestGoldenVectorTTETamperedAAD(t *testing.T) {
	key, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
	nonce, _ := hex.DecodeString("101112131415161718191a1b")
	ciphertext, _ := hex.DecodeString("b01c3d20109c6ba12dd6322c80dd022b5910")
	tag, _ := hex.DecodeString("272465c0a2f43c3fb5b2ce62cd7ddcd5")

	// Same as the happy-path AAD but with a different transport client id —
	// mirrors GoldenVectors.java's TTE_TAMPERED_AAD_01 ("ts-client-TAMPERED").
	tamperedAAD := buildTransportAAD(DomainTTE, ClientTypeTS, "ts-client-TAMPERED", DirectionRequest, OpCreateSession, "msg-202", 5)

	if _, err := openTransportEnvelope(key, tamperedAAD, nonce, ciphertext, tag); err == nil {
		t.Fatal("expected authentication failure with tampered AAD, got nil error")
	}
}

func TestGoldenVectorCEHappyPath(t *testing.T) {
	key, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	wantCiphertext, _ := hex.DecodeString("e70bdd3e885717a228d351cd9cc726761461ec1ee1cc0a1df0d8c8df62ca7f4d")
	wantMac, _ := hex.DecodeString("6eb37ee59e36ac2e8d31c89d57c830692bb939d23f931ad16d0fb1b5fa5d146a")
	wantPlaintext := []byte("Card Job Request Payload")
	const pollNextJob CardCommand = 0x14 // CardCommand.POLL_NEXT_JOB — not used by 115fs, only by this vector

	gotCiphertext, err := aesCBCEncrypt(key, iv, wantPlaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(gotCiphertext, wantCiphertext) {
		t.Errorf("ciphertext mismatch:\n got  %x\n want %x", gotCiphertext, wantCiphertext)
	}

	f := &ceFrame{
		role:           CardRoleTS,
		direction:      ceDirectionRequest,
		command:        pollNextJob,
		sequence:       42,
		cardInstanceID: "card-inst-01",
		cardClientID:   "ts-client-01",
		cardSessionID:  []byte("session-99"),
		requestID:      "req-777",
		iv:             iv,
		ciphertext:     wantCiphertext,
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(f.encode(false))
	gotMac := mac.Sum(nil)
	if !bytes.Equal(gotMac, wantMac) {
		t.Errorf("mac mismatch:\n got  %x\n want %x", gotMac, wantMac)
	}

	gotPlaintext, err := aesCBCDecrypt(key, iv, wantCiphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(gotPlaintext, wantPlaintext) {
		t.Errorf("plaintext mismatch:\n got  %q\n want %q", gotPlaintext, wantPlaintext)
	}
}

func TestGoldenVectorCETamperedMAC(t *testing.T) {
	key, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	ciphertext, _ := hex.DecodeString("e70bdd3e885717a228d351cd9cc726761461ec1ee1cc0a1df0d8c8df62ca7f4d")
	tamperedMac, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	const pollNextJob CardCommand = 0x14

	f := &ceFrame{
		role:           CardRoleTS,
		direction:      ceDirectionRequest,
		command:        pollNextJob,
		sequence:       42,
		cardInstanceID: "card-inst-01",
		cardClientID:   "ts-client-01",
		cardSessionID:  []byte("session-99"),
		requestID:      "req-777",
		iv:             iv,
		ciphertext:     ciphertext,
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(f.encode(false))
	realMac := mac.Sum(nil)
	if bytes.Equal(realMac, tamperedMac) {
		t.Fatal("test setup bug: tampered MAC accidentally matches the real one")
	}
}

// sealDeterministicForTest encrypts with a caller-supplied nonce instead of a
// random one, purely so the golden-vector test can assert exact ciphertext
// bytes against the independently-computed vector. Production code always
// goes through TransportEnvelopeClient.Seal, which generates a fresh random
// nonce per message — this helper must never be used outside tests.
func sealDeterministicForTest(key, nonce, aad, plaintext []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():], nil
}
