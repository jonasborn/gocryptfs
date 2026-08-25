package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// CardRole identifies who is talking to the card inside a Card Envelope
// session (card/CardRole.java). Values match CarterApplet's ROLE_* constants
// exactly — a client that gets this wrong is rejected by the card's own role
// gating (e.g. DERIVE_BLOCK_KEY(S) requires ROLE_KS or ROLE_FS).
type CardRole byte

const (
	CardRoleAdmin CardRole = 0x01
	CardRoleKS    CardRole = 0x02
	CardRoleTS    CardRole = 0x03
	CardRoleFS    CardRole = 0x04
)

// CardCommand is the protected-command INS byte carried inside a Card
// Envelope (card/CardCommand.java / CarterApplet's CMD_* constants). Only the
// two commands 115fs actually issues are defined here.
type CardCommand byte

const (
	CmdDeriveBlockKey  CardCommand = 0x0D
	CmdDeriveBlockKeys CardCommand = 0x18
)

// MaxBlockKeyBatch is the card's hard limit (MAX_BLOCK_KEY_BATCH,
// CarterApplet.java) on how many keys a single DERIVE_BLOCK_KEYS request may
// return — a request above this is rejected on the card with SW_WRONG_DATA.
//
// Was 5; reduced to 3 after live testing found the response frame (real
// cardInstanceId/cardClientId lengths plus a UUID requestId) overflows the
// APDU response buffer above that, regardless of the requested count's own
// plaintext-only size check — see CarterApplet's MAX_RESPONSE_PLAIN_LEN
// comment and sendEncryptedResponse's total-frame-size guard.
const MaxBlockKeyBatch = 3

const (
	insGetAuthChallenge = 0x88
	insProtected        = 0x8A

	frameMagic0   = 0xC5
	frameMagic1   = 0x02
	frameVersion1 = 0x01

	ceDirectionRequest  = 0x00
	ceDirectionResponse = 0x01

	sessionIDLen  = 8
	challengeLen  = 16
	ivLen         = 16
	macLen        = 32
	deviceSecLen  = 32
	aesBlockLen   = 16
	sessionKDFTag = "Carter Card v2.0"

	labelReqEnc  = 0x11
	labelReqMac  = 0x12
	labelRespEnc = 0x21
	labelRespMac = 0x22
)

// CardSession holds one established CE v2 session's identity and its four
// per-direction keys, derived once by EstablishSession from a real
// GET_AUTH_CHALLENGE round trip — see CardSessionEstablisher.java /
// CarterApplet.deriveSessionKey for the exact derivation this mirrors.
type CardSession struct {
	CardInstanceID string
	CardClientID   string
	CardSessionID  []byte // raw 8 bytes, never a UTF-8 string
	Role           CardRole

	RequestEncKey  []byte
	RequestMacKey  []byte
	ResponseEncKey []byte
	ResponseMacKey []byte

	sequence int64
}

// NextSequence returns the next strictly-increasing per-session sequence
// number, starting at 0 (matching CardSession.nextSequence() /
// AtomicLong.getAndIncrement() in the Java reference). Only the low 16 bits
// are meaningful to the card (its session counters are `short`), but the
// wire field is a fixed 8 bytes regardless.
func (s *CardSession) NextSequence() int64 {
	seq := s.sequence
	s.sequence++
	return seq
}

// BuildAuthChallengeAPDU builds the GET_AUTH_CHALLENGE (0x88) command APDU
// for cardClientID, mirroring CardSessionEstablisher.buildAuthChallengeApdu().
func BuildAuthChallengeAPDU(cardClientID string) ([]byte, error) {
	id := []byte(cardClientID)
	if len(id) < 1 || len(id) > 16 {
		return nil, fmt.Errorf("proto: cardClientId must be 1..16 UTF-8 bytes, got %d", len(id))
	}
	payload := make([]byte, 1+len(id))
	payload[0] = byte(len(id))
	copy(payload[1:], id)

	apdu := make([]byte, 6+len(payload))
	apdu[0] = 0x80
	apdu[1] = insGetAuthChallenge
	apdu[2] = 0x00
	apdu[3] = 0x00
	apdu[4] = byte(len(payload))
	copy(apdu[5:], payload)
	apdu[len(apdu)-1] = 0x00 // Le = 256
	return apdu, nil
}

// EstablishSession parses a GET_AUTH_CHALLENGE response
// (cardSessionId(8) || challenge(16) || SW1SW2) and derives the four session
// keys, mirroring CardSessionEstablisher.establish().
func EstablishSession(cardInstanceID, cardClientID string, role CardRole, secret []byte, authChallengeResponseAPDU []byte) (*CardSession, error) {
	if len(secret) != deviceSecLen {
		return nil, fmt.Errorf("proto: card client secret must be %d bytes, got %d", deviceSecLen, len(secret))
	}
	if len(authChallengeResponseAPDU) < sessionIDLen+challengeLen+2 {
		return nil, fmt.Errorf("proto: malformed GET_AUTH_CHALLENGE response (%d bytes)", len(authChallengeResponseAPDU))
	}
	n := len(authChallengeResponseAPDU)
	sw1, sw2 := authChallengeResponseAPDU[n-2], authChallengeResponseAPDU[n-1]
	if sw1 != 0x90 || sw2 != 0x00 {
		return nil, fmt.Errorf("proto: GET_AUTH_CHALLENGE failed, SW=%02X%02X", sw1, sw2)
	}
	data := authChallengeResponseAPDU[:n-2]
	if len(data) != sessionIDLen+challengeLen {
		return nil, fmt.Errorf("proto: malformed GET_AUTH_CHALLENGE response data (%d bytes)", len(data))
	}
	cardSessionID := append([]byte{}, data[:sessionIDLen]...)
	challenge := append([]byte{}, data[sessionIDLen:]...)
	deviceID := []byte(cardClientID)

	derive := func(label byte) []byte {
		h := sha256.New()
		h.Write([]byte{label})
		h.Write([]byte{byte(role)})
		h.Write([]byte(sessionKDFTag))
		h.Write(secret)
		h.Write(deviceID)
		h.Write(cardSessionID)
		h.Write(challenge)
		return h.Sum(nil)
	}

	return &CardSession{
		CardInstanceID: cardInstanceID,
		CardClientID:   cardClientID,
		CardSessionID:  cardSessionID,
		Role:           role,
		RequestEncKey:  derive(labelReqEnc),
		RequestMacKey:  derive(labelReqMac),
		ResponseEncKey: derive(labelRespEnc),
		ResponseMacKey: derive(labelRespMac),
	}, nil
}

// ceFrame is the parsed/unparsed form of one Card Envelope frame
// (card/CardEnvelopeContainer.java + the layout CardEnvelopeApduCodec.java
// reads/writes). All fields are exactly what a CE encrypt/decrypt call
// consumes or produces — nothing more.
type ceFrame struct {
	role           CardRole
	direction      byte
	command        CardCommand
	sequence       int64
	cardInstanceID string
	cardClientID   string
	cardSessionID  []byte
	requestID      string
	iv             []byte
	ciphertext     []byte
	mac            []byte // nil while computing the MAC input itself
}

func writeLP(buf *bytes.Buffer, data []byte) {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	buf.Write(lenBuf[:])
	buf.Write(data)
}

// encode serializes the frame exactly as CardEnvelopeApduCodec.toFrame() /
// toFrameWithoutMac() do: a 14-byte fixed header followed by 6 (or 7, with
// includeMac) length-prefixed fields. The HMAC is computed over the
// includeMac=false encoding; the wire frame sent/received always has
// includeMac=true.
func (f *ceFrame) encode(includeMac bool) []byte {
	var buf bytes.Buffer
	buf.WriteByte(frameMagic0)
	buf.WriteByte(frameMagic1)
	buf.WriteByte(frameVersion1)
	buf.WriteByte(byte(f.role))
	buf.WriteByte(f.direction)
	buf.WriteByte(byte(f.command))
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], uint64(f.sequence))
	buf.Write(seqBuf[:])

	writeLP(&buf, []byte(f.cardInstanceID))
	writeLP(&buf, []byte(f.cardClientID))
	writeLP(&buf, f.cardSessionID)
	writeLP(&buf, []byte(f.requestID))
	writeLP(&buf, f.iv)
	writeLP(&buf, f.ciphertext)
	if includeMac {
		writeLP(&buf, f.mac)
	}
	return buf.Bytes()
}

// decodeCEFrame parses a wire frame (always includes the trailing mac field
// — that's the only form ever sent over the wire), mirroring
// CardEnvelopeApduCodec.fromFrame().
func decodeCEFrame(data []byte) (*ceFrame, error) {
	const headerSize = 14
	if len(data) < headerSize {
		return nil, fmt.Errorf("proto: CE frame too short (%d bytes)", len(data))
	}
	if data[0] != frameMagic0 || data[1] != frameMagic1 {
		return nil, fmt.Errorf("proto: bad CE frame magic %02X%02X", data[0], data[1])
	}
	if data[2] != frameVersion1 {
		return nil, fmt.Errorf("proto: unsupported CE frame version %02X", data[2])
	}
	f := &ceFrame{
		role:      CardRole(data[3]),
		direction: data[4],
		command:   CardCommand(data[5]),
		sequence:  int64(binary.BigEndian.Uint64(data[6:14])),
	}
	off := headerSize
	readLP := func() ([]byte, error) {
		if off+2 > len(data) {
			return nil, fmt.Errorf("proto: CE frame truncated reading length prefix at offset %d", off)
		}
		l := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+l > len(data) {
			return nil, fmt.Errorf("proto: CE frame truncated reading %d bytes at offset %d", l, off)
		}
		v := data[off : off+l]
		off += l
		return v, nil
	}
	instanceID, err := readLP()
	if err != nil {
		return nil, err
	}
	clientID, err := readLP()
	if err != nil {
		return nil, err
	}
	sessionID, err := readLP()
	if err != nil {
		return nil, err
	}
	requestID, err := readLP()
	if err != nil {
		return nil, err
	}
	iv, err := readLP()
	if err != nil {
		return nil, err
	}
	ciphertext, err := readLP()
	if err != nil {
		return nil, err
	}
	mac, err := readLP()
	if err != nil {
		return nil, err
	}
	f.cardInstanceID = string(instanceID)
	f.cardClientID = string(clientID)
	f.cardSessionID = append([]byte{}, sessionID...)
	f.requestID = string(requestID)
	f.iv = append([]byte{}, iv...)
	f.ciphertext = append([]byte{}, ciphertext...)
	f.mac = append([]byte{}, mac...)
	return f, nil
}

func pkcs7Pad(data []byte) []byte {
	pad := aesBlockLen - (len(data) % aesBlockLen)
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aesBlockLen != 0 {
		return nil, fmt.Errorf("proto: invalid PKCS7 payload length %d", len(data))
	}
	pad := int(data[len(data)-1])
	if pad < 1 || pad > aesBlockLen || pad > len(data) {
		return nil, fmt.Errorf("proto: invalid PKCS7 padding byte %d", pad)
	}
	return data[:len(data)-pad], nil
}

func aesCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aesBlockLen != 0 {
		return nil, fmt.Errorf("proto: CE ciphertext length %d not a multiple of the AES block size", len(ciphertext))
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return pkcs7Unpad(out)
}

// CardRequest is the result of building a CE command: the base64 command
// APDU ready to relay, plus what's needed to validate the matching response
// (card/CardRequest.java).
type CardRequest struct {
	ApduBase64 string
	Sequence   int64
	RequestID  string
	Command    CardCommand
}

// BuildCERequest encrypts+MACs plaintext as command for session, and frames
// it as a base64 command APDU ready to relay through the KS
// (card/CardEnvelopeClient.buildRequest + CardEnvelopeApduCodec.toCommandApdu).
func BuildCERequest(session *CardSession, command CardCommand, plaintext []byte) (*CardRequest, error) {
	seq := session.NextSequence()
	requestID := newUUID()

	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("proto: generating CE IV: %w", err)
	}

	// The applet always treats decrypted plaintext[0] as a redundant leading
	// commandId byte (params start at plaintext[1]) — omitting this prefix
	// would silently shift every param byte by one on the card.
	framed := make([]byte, 1+len(plaintext))
	framed[0] = byte(command)
	copy(framed[1:], plaintext)

	ciphertext, err := aesCBCEncrypt(session.RequestEncKey, iv, framed)
	if err != nil {
		return nil, fmt.Errorf("proto: encrypting CE request: %w", err)
	}

	f := &ceFrame{
		role:           session.Role,
		direction:      ceDirectionRequest,
		command:        command,
		sequence:       seq,
		cardInstanceID: session.CardInstanceID,
		cardClientID:   session.CardClientID,
		cardSessionID:  session.CardSessionID,
		requestID:      requestID,
		iv:             iv,
		ciphertext:     ciphertext,
	}
	mac := hmac.New(sha256.New, session.RequestMacKey)
	mac.Write(f.encode(false))
	f.mac = mac.Sum(nil)

	apdu, err := toCommandAPDU(f.encode(true))
	if err != nil {
		return nil, err
	}

	return &CardRequest{
		ApduBase64: b64enc(apdu),
		Sequence:   seq,
		RequestID:  requestID,
		Command:    command,
	}, nil
}

// OpenCEResponse decrypts and verifies the card's sealed CE response to
// request, mirroring CardEnvelopeClient.openResponse(): it checks the
// response is bound to the same requestId/command/session/instance, verifies
// the HMAC (MAC-then-decrypt — never trust ciphertext before the MAC is
// checked), and returns the decrypted plaintext.
func OpenCEResponse(session *CardSession, request *CardRequest, responseApduBase64 string) ([]byte, error) {
	apdu, err := b64dec(responseApduBase64)
	if err != nil {
		return nil, fmt.Errorf("proto: decoding response APDU: %w", err)
	}
	frameBytes, err := fromResponseAPDU(apdu)
	if err != nil {
		return nil, err
	}
	f, err := decodeCEFrame(frameBytes)
	if err != nil {
		return nil, err
	}
	if f.requestID != request.RequestID {
		return nil, fmt.Errorf("proto: CE response requestId mismatch (got %q, want %q)", f.requestID, request.RequestID)
	}
	if f.command != request.Command {
		return nil, fmt.Errorf("proto: CE response command mismatch (got %02X, want %02X)", f.command, request.Command)
	}
	if f.sequence != request.Sequence {
		return nil, fmt.Errorf("proto: CE response sequence mismatch (got %d, want %d)", f.sequence, request.Sequence)
	}
	if !bytes.Equal(f.cardSessionID, session.CardSessionID) {
		return nil, fmt.Errorf("proto: CE response cardSessionId mismatch")
	}
	if f.cardInstanceID != session.CardInstanceID {
		return nil, fmt.Errorf("proto: CE response cardInstanceId mismatch (got %q, want %q)", f.cardInstanceID, session.CardInstanceID)
	}

	expected := &ceFrame{
		role:           session.Role,
		direction:      ceDirectionResponse,
		command:        f.command,
		sequence:       f.sequence,
		cardInstanceID: f.cardInstanceID,
		cardClientID:   session.CardClientID,
		cardSessionID:  f.cardSessionID,
		requestID:      f.requestID,
		iv:             f.iv,
		ciphertext:     f.ciphertext,
	}
	mac := hmac.New(sha256.New, session.ResponseMacKey)
	mac.Write(expected.encode(false))
	computedMac := mac.Sum(nil)
	if subtle.ConstantTimeCompare(computedMac, f.mac) != 1 {
		return nil, fmt.Errorf("proto: CE response MAC verification failed")
	}

	plaintext, err := aesCBCDecrypt(session.ResponseEncKey, f.iv, f.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("proto: decrypting CE response: %w", err)
	}
	return plaintext, nil
}

// toCommandAPDU frames a CE frame as an INS_PROTECTED (0x8A) command APDU,
// always in extended form for both Lc and Le (CardEnvelopeApduCodec.toCommandApdu()).
//
// Both fields are always extended, even when the frame would fit a short-form
// Lc: ISO 7816-4 case 4 has no valid encoding pairing a short-form Lc with an
// extended-form Le in one APDU, and Le must always be extended here (see
// below), so Lc has to be extended too for the APDU to parse unambiguously.
// Le is always present and always extended (0x00 0x00, Ne=65536) because this
// is genuinely a case 4 command: the card always sends a response frame back
// for INS_PROTECTED, and a short-form Le=0x00 (Ne=256) capped that response
// at 256 bytes -- which the CE response frame (header + 7 length-prefixed
// fields incl. ciphertext and a 32-byte MAC) routinely exceeds.
func toCommandAPDU(frame []byte) ([]byte, error) {
	if len(frame) == 0 {
		return nil, fmt.Errorf("proto: CE frame must not be empty")
	}
	if len(frame) > 0xFFFF {
		return nil, fmt.Errorf("proto: CE frame too large for extended APDU (%d bytes)", len(frame))
	}
	apdu := make([]byte, 7+len(frame)+2)
	apdu[0] = 0x80
	apdu[1] = insProtected
	apdu[2] = 0x00
	apdu[3] = 0x00
	apdu[4] = 0x00
	binary.BigEndian.PutUint16(apdu[5:7], uint16(len(frame)))
	copy(apdu[7:], frame)
	// Trailing 2 bytes are the extended Le (0x00 0x00, Ne=65536) -- left as
	// Go's zero value, matching make()'s zero-initialized backing array.
	return apdu, nil
}

// fromResponseAPDU strips and validates the trailing SW1SW2 (must be 0x9000)
// from a response APDU, returning the CE frame bytes that precede it
// (CardEnvelopeApduCodec.parseResponseApdu()).
func fromResponseAPDU(apdu []byte) ([]byte, error) {
	if len(apdu) < 2 {
		return nil, fmt.Errorf("proto: response APDU too short (%d bytes)", len(apdu))
	}
	sw1, sw2 := apdu[len(apdu)-2], apdu[len(apdu)-1]
	if sw1 != 0x90 || sw2 != 0x00 {
		return nil, fmt.Errorf("proto: CE command failed, SW=%02X%02X", sw1, sw2)
	}
	return apdu[:len(apdu)-2], nil
}

// ProtectedCommandError is returned by ParseProtectedResponse when the CE
// plaintext's inner status is not 0x9000 — a second, CE-plaintext-internal
// status layer independent of the outer command APDU's SW1SW2
// (card/ProtectedResponse.java).
type ProtectedCommandError struct {
	Status  uint16
	Payload []byte
}

func (e *ProtectedCommandError) Error() string {
	return fmt.Sprintf("proto: protected command failed, status=%04X", e.Status)
}

// ParseProtectedResponse reads the status(2, big-endian) || payload layout
// every CE response plaintext carries, returning payload only when
// status == 0x9000 (card/ProtectedResponse.java).
func ParseProtectedResponse(plaintext []byte) ([]byte, error) {
	if len(plaintext) < 2 {
		return nil, fmt.Errorf("proto: protected response too short (%d bytes)", len(plaintext))
	}
	status := binary.BigEndian.Uint16(plaintext[:2])
	payload := plaintext[2:]
	if status != 0x9000 {
		return nil, &ProtectedCommandError{Status: status, Payload: payload}
	}
	return payload, nil
}
