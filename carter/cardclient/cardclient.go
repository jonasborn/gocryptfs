// Package cardclient makes 115fs a first-class card client (CON-3): it opens
// its own Card Envelope (CE v2) session with 115cos and drives
// DERIVE_BLOCK_KEY(S) end-to-end through the KS's opaque relay. The KS
// authenticates the caller and forwards bytes; it never decrypts, forges, or
// derives an FS block key — mirroring
// components/115fs-emu/src/main/java/com/cartercard/fs/card/FsCardClient.java.
package cardclient

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/rfjakob/gocryptfs/v2/carter/ksclient"
	"github.com/rfjakob/gocryptfs/v2/carter/proto"
)

// cardRelayRequest/cardRelayResponse are the JSON payloads sealed inside a
// Transport Envelope on the card-relay path — never sent in the clear (see
// carter-keyserver.yaml's CardRelayRequest/CardRelayResponse schemas).
type cardRelayRequest struct {
	RelayRequestID string `json:"relayRequestId"`
	CardEnvelope   string `json:"cardEnvelope"`
}

type cardRelayResponse struct {
	RelayRequestID       string `json:"relayRequestId"`
	CardEnvelopeResponse string `json:"cardEnvelopeResponse"`
	Status               string `json:"status"`
}

// Client drives one FS card identity end-to-end through one KS transport
// identity. Both identities are independent (CON-2 §5.1, §11.5, §14): the
// transport key authenticates FS to the KS, the card secret authenticates FS
// to 115cos, and the KS never sees the card secret or any key derived from a
// Card Envelope session established with it.
type Client struct {
	ks       *ksclient.Client
	envelope *proto.TransportEnvelopeClient

	transportClientID string
	transportKey      []byte

	cardInstanceID   string
	cardClientID     string
	cardClientSecret []byte

	transportSessionID string
}

// New constructs a Client for one KS connection and one FS card identity.
// transportKey and cardClientSecret are retained by reference (32 bytes
// each, AES-256-GCM transport key and raw device secret respectively) — the
// caller must not mutate them afterward.
func New(ks *ksclient.Client, transportClientID string, transportKey []byte,
	cardInstanceID, cardClientID string, cardClientSecret []byte) *Client {
	return &Client{
		ks:                ks,
		envelope:          proto.NewTransportEnvelopeClient(transportClientID, proto.ClientTypeFS, proto.DomainTTE),
		transportClientID: transportClientID,
		transportKey:      transportKey,
		cardInstanceID:    cardInstanceID,
		cardClientID:      cardClientID,
		cardClientSecret:  cardClientSecret,
	}
}

// EstablishSession opens a transport session (POST /api/v1/fs/transport-sessions)
// and then performs the real GET_AUTH_CHALLENGE handshake through the relay,
// deriving the four CE session keys locally. Nothing about the resulting
// session is fabricated: the challenge and cardSessionId come from the live
// card, exactly as for the KS's own admin/host sessions.
//
// Opening the transport session first is required because TTE replay state is
// scoped to the returned transportSessionId. A fresh process can start its
// sequence at 1 without lowering any previous session's replay watermark.
func (c *Client) EstablishSession() (*proto.CardSession, error) {
	sess, err := c.ks.OpenTransportSession(c.transportClientID, c.transportKey)
	if err != nil {
		return nil, fmt.Errorf("cardclient: opening transport session: %w", err)
	}
	c.transportSessionID = sess.TransportSessionID
	if err := c.envelope.SetTransportSessionID(sess.TransportSessionID); err != nil {
		return nil, fmt.Errorf("cardclient: binding transport session: %w", err)
	}

	challengeAPDU, err := proto.BuildAuthChallengeAPDU(c.cardClientID)
	if err != nil {
		return nil, fmt.Errorf("cardclient: building auth challenge APDU: %w", err)
	}
	responseAPDUBase64, err := c.relay(base64.StdEncoding.EncodeToString(challengeAPDU))
	if err != nil {
		return nil, fmt.Errorf("cardclient: GET_AUTH_CHALLENGE relay failed: %w", err)
	}
	responseAPDU, err := base64.StdEncoding.DecodeString(responseAPDUBase64)
	if err != nil {
		return nil, fmt.Errorf("cardclient: decoding auth challenge response: %w", err)
	}
	session, err := proto.EstablishSession(c.cardInstanceID, c.cardClientID, proto.CardRoleFS, c.cardClientSecret, responseAPDU)
	if err != nil {
		return nil, fmt.Errorf("cardclient: establishing session: %w", err)
	}
	return session, nil
}

// Close deregisters this client's transport session
// (DELETE /api/v1/fs/transport-sessions/{id}), if one was opened. Safe to
// call even if EstablishSession was never called or already failed.
func (c *Client) Close() error {
	if c.transportSessionID == "" {
		return nil
	}
	err := c.ks.CloseTransportSession(c.transportSessionID, c.transportClientID, c.transportKey)
	c.transportSessionID = ""
	return err
}

// DeriveBlockKey derives a single 32-byte block key for keyId/blockIndex.
func (c *Client) DeriveBlockKey(session *proto.CardSession, keyID byte, blockIndex uint64, usagePrefix []byte) ([]byte, error) {
	payload := proto.EncodeDeriveBlockKeyPayload(keyID, blockIndex, usagePrefix)
	respPayload, err := c.deriveRaw(session, proto.CmdDeriveBlockKey, payload)
	if err != nil {
		return nil, err
	}
	return proto.DecodeDeriveBlockKeyResponse(respPayload)
}

// DeriveBlockKeys derives count consecutive block keys starting at
// startIndex in one round trip. count must be 1..proto.MaxBlockKeyBatch —
// the card enforces this hard limit itself.
func (c *Client) DeriveBlockKeys(session *proto.CardSession, keyID byte, startIndex uint64, count int, usagePrefix []byte) ([][]byte, error) {
	payload, err := proto.EncodeDeriveBlockKeysPayload(keyID, startIndex, count, usagePrefix)
	if err != nil {
		return nil, err
	}
	respPayload, err := c.deriveRaw(session, proto.CmdDeriveBlockKeys, payload)
	if err != nil {
		return nil, err
	}
	return proto.DecodeDeriveBlockKeysResponse(respPayload, count)
}

func (c *Client) deriveRaw(session *proto.CardSession, command proto.CardCommand, payload []byte) ([]byte, error) {
	req, err := proto.BuildCERequest(session, command, payload)
	if err != nil {
		return nil, fmt.Errorf("cardclient: building CE request: %w", err)
	}
	responseAPDUBase64, err := c.relay(req.ApduBase64)
	if err != nil {
		return nil, fmt.Errorf("cardclient: relay failed: %w", err)
	}
	plaintext, err := proto.OpenCEResponse(session, req, responseAPDUBase64)
	if err != nil {
		return nil, fmt.Errorf("cardclient: opening CE response: %w", err)
	}
	return proto.ParseProtectedResponse(plaintext)
}

// relay wraps an opaque APDU (handshake or Card Envelope) in a Transport
// Envelope, sends it through the KS's card-relay route, and returns the raw
// response APDU (base64). Every relayed byte string is opaque to the KS —
// only CLA/INS distinguish a handshake from CE traffic, and the KS never
// reads either.
func (c *Client) relay(opaqueAPDUBase64 string) (string, error) {
	inner := cardRelayRequest{RelayRequestID: newRelayRequestID(), CardEnvelope: opaqueAPDUBase64}
	innerJSON, err := json.Marshal(inner)
	if err != nil {
		return "", err
	}
	request, err := c.envelope.Seal(c.transportKey, proto.OpCardRelay, innerJSON)
	if err != nil {
		return "", fmt.Errorf("sealing transport envelope: %w", err)
	}
	response, err := c.ks.CardRelay(request)
	if err != nil {
		return "", fmt.Errorf("KS card-relay request failed: %w", err)
	}
	responsePlaintext, err := c.envelope.OpenResponse(c.transportKey, proto.OpCardRelay, request, response)
	if err != nil {
		return "", fmt.Errorf("opening transport envelope response: %w", err)
	}
	var out cardRelayResponse
	if err := json.Unmarshal(responsePlaintext, &out); err != nil {
		return "", fmt.Errorf("decoding card relay response: %w", err)
	}
	if out.Status != "ok" || out.CardEnvelopeResponse == "" {
		return "", fmt.Errorf("card relay failed with status %q", out.Status)
	}
	return out.CardEnvelopeResponse, nil
}

// newRelayRequestID generates a random hex identifier for one card-relay
// round trip — only used for tracking/idempotency on the KS side, no
// structural requirement on its format.
func newRelayRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cardclient: reading random bytes for relay request id: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
