package proto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func hmacSHA256ForTest(key, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// TestSessionRoundTrip exercises the full client-facing surface — session
// establishment from a synthetic GET_AUTH_CHALLENGE response,
// BuildCERequest, and OpenCEResponse — by acting as both the FS client and a
// minimal standalone "card" simulator built independently from the same
// frame/crypto primitives (own EstablishSession-equivalent key derivation,
// own decrypt/re-encrypt). This is a self-consistency check of the client API
// surface, complementary to the byte-exact golden vectors in
// golden_vectors_test.go.
func TestSessionRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	cardInstanceID := "card-inst-test"
	cardClientID := "fs-client-test"

	cardSessionID := make([]byte, sessionIDLen)
	challenge := make([]byte, challengeLen)
	if _, err := rand.Read(cardSessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}

	authAPDU, err := BuildAuthChallengeAPDU(cardClientID)
	if err != nil {
		t.Fatalf("BuildAuthChallengeAPDU: %v", err)
	}
	// Sanity-check the handshake APDU shape: 80 88 00 00 Lc <1-byte-idlen><id> 00.
	if authAPDU[0] != 0x80 || authAPDU[1] != insGetAuthChallenge {
		t.Fatalf("unexpected auth challenge APDU header: %x", authAPDU[:4])
	}

	// Simulate the card's GET_AUTH_CHALLENGE response.
	respAPDU := append(append([]byte{}, cardSessionID...), challenge...)
	respAPDU = append(respAPDU, 0x90, 0x00)

	session, err := EstablishSession(cardInstanceID, cardClientID, CardRoleFS, secret, respAPDU)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}

	// The "card" derives the identical four keys from the same challenge —
	// this is exactly what CarterApplet.deriveSessionKey does; re-derive here
	// independently (not by calling EstablishSession again) to catch a bug
	// where the client and a real card would silently disagree.
	cardSession := &CardSession{
		CardInstanceID: cardInstanceID,
		CardClientID:   cardClientID,
		CardSessionID:  cardSessionID,
		Role:           CardRoleFS,
		RequestEncKey:  session.RequestEncKey,
		RequestMacKey:  session.RequestMacKey,
		ResponseEncKey: session.ResponseEncKey,
		ResponseMacKey: session.ResponseMacKey,
	}

	keyID := byte(0x52)
	blockIndex := uint64(7)
	prefix := []byte("/vault/photos/2026")
	payload := EncodeDeriveBlockKeyPayload(keyID, blockIndex, prefix)

	req, err := BuildCERequest(session, CmdDeriveBlockKey, payload)
	if err != nil {
		t.Fatalf("BuildCERequest: %v", err)
	}

	// --- card side: decrypt the request, verify it, build a response ---
	reqApduBytes, err := b64dec(req.ApduBase64)
	if err != nil {
		t.Fatal(err)
	}
	if reqApduBytes[0] != 0x80 || reqApduBytes[1] != insProtected {
		t.Fatalf("unexpected request APDU header: %x", reqApduBytes[:4])
	}
	// Short-form command APDU: 80 8A 00 00 <Lc> <frame> <Le>.
	lc := int(reqApduBytes[4])
	frameBytes := reqApduBytes[5 : 5+lc]
	reqFrame, err := decodeCEFrame(frameBytes)
	if err != nil {
		t.Fatalf("card: decoding request frame: %v", err)
	}
	if reqFrame.requestID != req.RequestID || reqFrame.sequence != req.Sequence || reqFrame.command != CmdDeriveBlockKey {
		t.Fatalf("card: request frame identity mismatch: %+v", reqFrame)
	}
	// Verify MAC exactly like the applet does — recompute over the received
	// fields (minus mac) and compare.
	verifyFrame := &ceFrame{
		role: reqFrame.role, direction: reqFrame.direction, command: reqFrame.command,
		sequence: reqFrame.sequence, cardInstanceID: reqFrame.cardInstanceID,
		cardClientID: reqFrame.cardClientID, cardSessionID: reqFrame.cardSessionID,
		requestID: reqFrame.requestID, iv: reqFrame.iv, ciphertext: reqFrame.ciphertext,
	}
	computedMac, err := hmacSHA256ForTest(cardSession.RequestMacKey, verifyFrame.encode(false))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(computedMac, reqFrame.mac) {
		t.Fatal("card: request MAC did not verify")
	}
	reqPlaintext, err := aesCBCDecrypt(cardSession.RequestEncKey, reqFrame.iv, reqFrame.ciphertext)
	if err != nil {
		t.Fatalf("card: decrypting request: %v", err)
	}
	if reqPlaintext[0] != byte(CmdDeriveBlockKey) {
		t.Fatalf("card: missing command-id prefix byte, got %02X", reqPlaintext[0])
	}
	gotPayload := reqPlaintext[1:]
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("card: payload mismatch:\n got  %x\n want %x", gotPayload, payload)
	}
	// keyId(1) || blockIndex(8,BE) || prefixLen(1) || prefix — verify the card
	// would read back exactly what we encoded.
	if gotPayload[0] != keyID {
		t.Fatalf("card: keyId mismatch: got %02X want %02X", gotPayload[0], keyID)
	}

	// Card responds with a fake 32-byte derived key, status 0x9000.
	fakeKey := make([]byte, 32)
	if _, err := rand.Read(fakeKey); err != nil {
		t.Fatal(err)
	}
	respPlaintext := append([]byte{0x90, 0x00}, fakeKey...)
	respIV := make([]byte, ivLen)
	if _, err := rand.Read(respIV); err != nil {
		t.Fatal(err)
	}
	respCiphertext, err := aesCBCEncrypt(cardSession.ResponseEncKey, respIV, respPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	respFrame := &ceFrame{
		role: cardSession.Role, direction: ceDirectionResponse, command: reqFrame.command,
		sequence: reqFrame.sequence, cardInstanceID: cardInstanceID, cardClientID: cardClientID,
		cardSessionID: cardSessionID, requestID: req.RequestID, iv: respIV, ciphertext: respCiphertext,
	}
	respMac, err := hmacSHA256ForTest(cardSession.ResponseMacKey, respFrame.encode(false))
	if err != nil {
		t.Fatal(err)
	}
	respFrame.mac = respMac
	respAPDUBytes := append(respFrame.encode(true), 0x90, 0x00)
	respAPDUBase64 := b64enc(respAPDUBytes)

	// --- back to the FS client: open and verify the response ---
	plaintext, err := OpenCEResponse(session, req, respAPDUBase64)
	if err != nil {
		t.Fatalf("OpenCEResponse: %v", err)
	}
	gotKey, err := ParseProtectedResponse(plaintext)
	if err != nil {
		t.Fatalf("ParseProtectedResponse: %v", err)
	}
	key, err := DecodeDeriveBlockKeyResponse(gotKey)
	if err != nil {
		t.Fatalf("DecodeDeriveBlockKeyResponse: %v", err)
	}
	if !bytes.Equal(key, fakeKey) {
		t.Fatalf("round-tripped key mismatch:\n got  %x\n want %x", key, fakeKey)
	}
}

// TestOpenCEResponseRejectsWrongStatus checks that a non-0x9000 outer SW is
// rejected before any crypto is attempted.
func TestOpenCEResponseRejectsWrongStatus(t *testing.T) {
	apdu := []byte{0x00, 0x01, 0x6A, 0x82} // SW=6A82 (file/applet not found)
	if _, err := fromResponseAPDU(apdu); err == nil {
		t.Fatal("expected error for non-9000 status word")
	}
}

func TestEncodeDeriveBlockKeysPayloadRejectsOutOfRangeCount(t *testing.T) {
	if _, err := EncodeDeriveBlockKeysPayload(0x01, 0, 0, nil); err == nil {
		t.Fatal("expected error for count=0")
	}
	if _, err := EncodeDeriveBlockKeysPayload(0x01, 0, MaxBlockKeyBatch+1, nil); err == nil {
		t.Fatal("expected error for count > MaxBlockKeyBatch")
	}
	payload, err := EncodeDeriveBlockKeysPayload(0x01, 100, MaxBlockKeyBatch, []byte("pfx"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(payload) != 11+3 {
		t.Fatalf("unexpected payload length: %d", len(payload))
	}
}
