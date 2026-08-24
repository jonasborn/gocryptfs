// Package ksclient implements the FS-facing HTTP routes of the real,
// currently-running 115ks server — /api/v1/fs/health, /api/v1/fs/transport-sessions,
// /api/v1/fs/card-relay, /api/v1/fs/logs — exactly as specified in
// components/115ks/openapi/carter-keyserver.yaml and implemented server-side
// by FSServices.java. It deliberately does not implement the older
// pairing/session/block-password routes that used to live in
// components/115fs/openapi.yaml: that document described an HTTP API the
// real server no longer serves at all (CON-3 replaced it with this opaque
// Card Envelope relay design).
//
// TLS certificate pinning is the caller's responsibility (see the shared
// gocryptfs/pinning package) — this package only speaks HTTP/JSON against
// whatever *http.Client it's given.
package ksclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/carter/proto"
)

// Client is a thin JSON/HTTP client for one 115ks server's FS routes.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client. httpClient's TLS configuration (certificate pinning)
// is entirely the caller's concern — see main.go's verifyAndPinTLSCertificate
// for the interactive pinning flow this project uses everywhere else.
func New(baseURL string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// HealthResponse is FSServices' GET /api/v1/fs/health response.
type HealthResponse struct {
	Service        string `json:"service"`
	Status         string `json:"status"`
	ActiveSessions int    `json:"activeSessions"`
	Timestamp      string `json:"timestamp"`
}

// Health calls GET /api/v1/fs/health. This endpoint is plaintext (no
// envelope) and does not require a transport session.
func (c *Client) Health() (*HealthResponse, error) {
	resp, err := c.http.Get(c.baseURL + "/api/v1/fs/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ksclient: fs/health returned status %d: %s", resp.StatusCode, body)
	}
	var h HealthResponse
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, fmt.Errorf("ksclient: decoding fs/health response: %w", err)
	}
	return &h, nil
}

// TransportSessionResponse is FSServices' POST /api/v1/fs/transport-sessions
// response.
type TransportSessionResponse struct {
	TransportSessionID string `json:"transportSessionId"`
	TransportClientID  string `json:"transportClientId"`
	ClientType         string `json:"clientType"`
	CreatedAt          string `json:"createdAt"`
}

// errorResponse mirrors carter-keyserver.yaml's ErrorResponse schema
// ({errorCode, message}), used across every FS route's error paths.
type errorResponse struct {
	ErrorCode string `json:"errorCode"`
	Message   string `json:"message"`
}

// OpenTransportSession registers a transport session for transportClientID
// via POST /api/v1/fs/transport-sessions. The body is plaintext JSON —
// cryptographic proof of the transport key is only exercised later, on the
// card-relay path.
func (c *Client) OpenTransportSession(transportClientID string) (*TransportSessionResponse, error) {
	reqBody, err := json.Marshal(map[string]string{"transportClientId": transportClientID})
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Post(c.baseURL+"/api/v1/fs/transport-sessions", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("ksclient: opening transport session: %s", describeError(resp.StatusCode, body))
	}
	var out TransportSessionResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ksclient: decoding transport session response: %w", err)
	}
	return &out, nil
}

// CloseTransportSession deregisters a transport session via
// DELETE /api/v1/fs/transport-sessions/{sessionId}. A 404 (session already
// gone) is not treated as an error — the caller's intent (no active session
// under this id) is already satisfied.
func (c *Client) CloseTransportSession(transportSessionID string) error {
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+"/api/v1/fs/transport-sessions/"+transportSessionID, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("ksclient: closing transport session: %s", describeError(resp.StatusCode, body))
}

// CardRelay relays one opaque Card Envelope round trip through the KS via
// POST /api/v1/fs/card-relay: the request body IS a Transport Envelope (TTE)
// sealing an inner CardRelayRequest, and the response is a TTE sealing an
// inner CardRelayResponse. The KS authenticates the caller by opening the
// envelope under its provisioned transport key and never reads or forges the
// opaque Card Envelope inside — see FSServices.java's javadoc and CON-3.
func (c *Client) CardRelay(request *proto.TransportEnvelopeMessage) (*proto.TransportEnvelopeMessage, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Post(c.baseURL+"/api/v1/fs/card-relay", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ksclient: card relay: %s", describeError(resp.StatusCode, body))
	}
	var out proto.TransportEnvelopeMessage
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ksclient: decoding card relay response: %w", err)
	}
	return &out, nil
}

// SubmitLog records one client log line via POST /api/v1/fs/logs. level must
// be one of debug/info/warn/error (unrecognised spellings such as
// warning/err/fatal/critical are normalised server-side, but anything else is
// rejected with 400 logLevelInvalid).
func (c *Client) SubmitLog(level, title, message, source string) error {
	reqBody, err := json.Marshal(map[string]string{
		"level": level, "title": title, "message": message, "source": source,
	})
	if err != nil {
		return err
	}
	resp, err := c.http.Post(c.baseURL+"/api/v1/fs/logs", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("ksclient: submitting log: %s", describeError(resp.StatusCode, body))
}

// SubmitUntrustedLog records one client log line via the untrusted HTTP
// listener's POST /api/v1/untrusted/logs — the plaintext bootstrap channel
// for the window before this client can treat the keyserver's TLS
// certificate as trusted (see UntrustedRoutes.java). Same request/response
// shape as SubmitLog; only the route (and therefore usually the client/base
// URL, plain HTTP not pinned HTTPS) differs.
func (c *Client) SubmitUntrustedLog(level, title, message, source string) error {
	reqBody, err := json.Marshal(map[string]string{
		"level": level, "title": title, "message": message, "source": source,
	})
	if err != nil {
		return err
	}
	resp, err := c.http.Post(c.baseURL+"/api/v1/untrusted/logs", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("ksclient: submitting untrusted log: %s", describeError(resp.StatusCode, body))
}

func describeError(statusCode int, body []byte) string {
	var e errorResponse
	if json.Unmarshal(body, &e) == nil && e.ErrorCode != "" {
		return fmt.Sprintf("HTTP %d %s: %s", statusCode, e.ErrorCode, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", statusCode, string(body))
}
