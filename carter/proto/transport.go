// Package proto is a byte-exact Go port of the 115 Trust Network v2 wire
// protocol (Transport Envelope / TTE-UTE and Card Envelope / CE v2) defined
// in CON-2 v2 binding specification and implemented in Java by
// components/115proto (com.cartercard.proto.transport / .card). It exists so
// 115fs can be a first-class card client (CON-3): it talks CE directly to
// 115cos, and the keyserver (115ks) only ever relays opaque bytes inside a
// TTE — it never derives or sees FS block keys.
//
// Every constant, byte offset, and algorithm choice here was verified against
// both the Java reference client (components/115proto) and the card applet
// (components/115cos/src/com/cartercard/applet/CarterApplet.java) — do not
// change any of it without re-checking both sides; a mismatch means this
// client silently stops interoperating with the real card/server.
package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

// ProtocolVersion is always "v2.0" for the current wire protocol
// (ProtocolVersion.V2_0.getVersionString() in the Java reference).
const ProtocolVersion = "v2.0"

// EnvelopeDomain distinguishes the Untrusted, Trusted, and Card envelope
// domains — bound into every AAD/MAC so a ciphertext from one domain can
// never be replayed as if it were from another (transport/EnvelopeDomain.java).
type EnvelopeDomain string

const (
	DomainUTE EnvelopeDomain = "115-UTE-v2"
	DomainTTE EnvelopeDomain = "115-TTE-v2"
	DomainCE  EnvelopeDomain = "115-CE-v2"
)

// ClientType identifies the transport client kind bound into the TTE/UTE AAD
// (transport/ClientType.java). 115fs is always ClientTypeFS.
type ClientType string

const (
	ClientTypeFS ClientType = "fs"
	ClientTypeTS ClientType = "ts"
)

// MessageDirection is bound into the AAD so a REQUEST ciphertext can never be
// replayed back as a RESPONSE or vice versa (transport/MessageDirection.java).
type MessageDirection string

const (
	DirectionRequest  MessageDirection = "request"
	DirectionResponse MessageDirection = "response"
)

// TransportOperation names the logical operation a Transport Envelope
// carries, bound into the AAD (transport/TransportOperation.java).
type TransportOperation string

const (
	OpCreateSession TransportOperation = "create-session"
	OpCardRelay     TransportOperation = "card-relay"
	OpLogs          TransportOperation = "logs"
	OpHealth        TransportOperation = "health"
	OpIdentity      TransportOperation = "identity"
)

// TransportEnvelopeMessage is the JSON wire form of a Transport Envelope
// (UTE/TTE) — see transport/TransportEnvelopeMessage.java. Field names and
// casing must match exactly; the server decodes this with the same DTO.
type TransportEnvelopeMessage struct {
	TransportClientID string `json:"transportClientId"`
	ClientType        string `json:"clientType"`
	// Direction here is the literal uppercase "REQUEST"/"RESPONSE" — a
	// separate, informational-only field from the lowercase AAD direction
	// identifier used inside buildTransportAAD.
	Direction  string `json:"direction"`
	MessageID  string `json:"messageId"`
	Sequence   int64  `json:"sequence"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	AuthTag    string `json:"authTag"`
}

// buildTransportAAD reproduces TransportAadTemplate.buildCanonicalAadBytes():
// 8 colon-joined fields, each string field length-prefixed as "len:value"
// (UTF-8 byte length), the trailing sequence number left bare.
func buildTransportAAD(domain EnvelopeDomain, clientType ClientType, clientID string,
	direction MessageDirection, op TransportOperation, messageID string, sequence int64) []byte {
	lp := func(s string) string {
		return strconv.Itoa(len(s)) + ":" + s
	}
	parts := []string{
		lp(ProtocolVersion),
		lp(string(domain)),
		lp(string(clientType)),
		lp(clientID),
		lp(string(direction)),
		lp(string(op)),
		lp(messageID),
	}
	return []byte(strings.Join(parts, ":") + ":" + strconv.FormatInt(sequence, 10))
}

// sealTransportEnvelope AES-256-GCM-encrypts plaintext under key with a fresh
// random 12-byte nonce and the canonical AAD, mirroring
// DefaultTransportEnvelopeCodec.encrypt(). key must be 16 or 32 bytes.
func sealTransportEnvelope(key []byte, aad []byte, plaintext []byte) (nonce, ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	ciphertext = sealed[:len(sealed)-gcm.Overhead()]
	tag = sealed[len(sealed)-gcm.Overhead():]
	return nonce, ciphertext, tag, nil
}

// openTransportEnvelope reverses sealTransportEnvelope, mirroring
// DefaultTransportEnvelopeCodec.decrypt(). Authentication happens before any
// other state is touched by the caller — GCM.Open fails closed on a bad tag.
func openTransportEnvelope(key []byte, aad []byte, nonce, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combined := append(append([]byte{}, ciphertext...), tag...)
	return gcm.Open(nil, nonce, combined, aad)
}

// TransportEnvelopeClient is the FS/TS side of the Transport Envelope: seals
// outbound REQUESTs under the shared transport key and opens the KS's sealed
// RESPONSEs, mirroring transport/TransportEnvelopeClient.java. Sequence
// numbers are strictly increasing per instance, starting at 1.
type TransportEnvelopeClient struct {
	clientID   string
	clientType ClientType
	domain     EnvelopeDomain
	sequence   int64
}

// NewTransportEnvelopeClient constructs a client for one transport identity.
// domain is DomainTTE for the trusted (post-pairing) listener or DomainUTE
// for the untrusted bootstrap listener.
func NewTransportEnvelopeClient(clientID string, clientType ClientType, domain EnvelopeDomain) *TransportEnvelopeClient {
	return &TransportEnvelopeClient{clientID: clientID, clientType: clientType, domain: domain}
}

// Seal encrypts payload (JSON-marshaled by the caller) as a REQUEST under
// transportKey for the given operation.
func (c *TransportEnvelopeClient) Seal(transportKey []byte, op TransportOperation, payload []byte) (*TransportEnvelopeMessage, error) {
	seq := atomic.AddInt64(&c.sequence, 1)
	messageID := newUUID()
	aad := buildTransportAAD(c.domain, c.clientType, c.clientID, DirectionRequest, op, messageID, seq)
	nonce, ciphertext, tag, err := sealTransportEnvelope(transportKey, aad, payload)
	if err != nil {
		return nil, fmt.Errorf("proto: sealing transport envelope: %w", err)
	}
	return &TransportEnvelopeMessage{
		TransportClientID: c.clientID,
		ClientType:        string(c.clientType),
		Direction:         "REQUEST",
		MessageID:         messageID,
		Sequence:          seq,
		Nonce:             b64enc(nonce),
		Ciphertext:        b64enc(ciphertext),
		AuthTag:           b64enc(tag),
	}, nil
}

// OpenResponse decrypts the KS's sealed RESPONSE to a prior request built by
// Seal, reconstructing the AAD from the original request's messageId/sequence
// (RESPONSE direction) so a forged or mismatched response will not open.
func (c *TransportEnvelopeClient) OpenResponse(transportKey []byte, op TransportOperation,
	request *TransportEnvelopeMessage, response *TransportEnvelopeMessage) ([]byte, error) {
	aad := buildTransportAAD(c.domain, c.clientType, c.clientID, DirectionResponse, op, request.MessageID, request.Sequence)
	nonce, err := b64dec(response.Nonce)
	if err != nil {
		return nil, fmt.Errorf("proto: decoding response nonce: %w", err)
	}
	ciphertext, err := b64dec(response.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("proto: decoding response ciphertext: %w", err)
	}
	tag, err := b64dec(response.AuthTag)
	if err != nil {
		return nil, fmt.Errorf("proto: decoding response authTag: %w", err)
	}
	plaintext, err := openTransportEnvelope(transportKey, aad, nonce, ciphertext, tag)
	if err != nil {
		return nil, fmt.Errorf("proto: opening transport envelope response: %w", err)
	}
	return plaintext, nil
}
