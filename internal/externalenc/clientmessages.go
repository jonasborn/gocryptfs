package externalenc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// heartbeatInterval is deliberately long — a liveness signal, not a status
// feed — so it never fires during a normal test run.
const heartbeatInterval = 10 * time.Minute

// ClientMessagePayload is the inner (encrypted) body of a client-messages
// submission — see openapi.yaml's ClientMessagePayload schema. "category"
// distinguishes background diagnostics ("log") from messages meant to be
// shown prominently to a human ("userMessage"). Per the server's own
// documentation and AGENTS.md: Message/Details must never contain secrets —
// that's what makes it safe to send this over an unauthenticated transport
// (the less-secure channel) in the first place.
type ClientMessagePayload struct {
	Category string                 `json:"category"`
	Level    string                 `json:"level,omitempty"`
	Title    string                 `json:"title,omitempty"`
	Message  string                 `json:"message"`
	Source   string                 `json:"source,omitempty"`
	At       string                 `json:"at,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// clientLogEnvelope is the outer (unencrypted) request body for both
// /api/v1/client-messages and /api/v1/less-secure/client-messages. There is
// no clientKey field — the server selects the stored key by clientId and
// treats successful AES-GCM authentication as proof, so the secret itself
// never crosses either channel.
type clientLogEnvelope struct {
	ClientId   string `json:"clientId"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// lessSecureBaseURL derives the HTTP-only bootstrap listener's base URL from
// the HTTPS one: same host, port 9080 — openapi.yaml's "servers" list always
// pairs a :9443 HTTPS entry with a :9080 HTTP one for the same host.
func lessSecureBaseURL(secureBaseURL string) string {
	u, err := url.Parse(secureBaseURL)
	if err != nil || u.Hostname() == "" {
		return secureBaseURL
	}
	return "http://" + u.Hostname() + ":9080"
}

// sendClientMessage posts a diagnostic or user-facing message to the key
// server, encrypted with the client's long-term ClientKey exactly like the
// pairing/session envelopes (AES-256-GCM, AAD "clientMessage:{clientId}" or
// "lessSecureClientMessage:{clientId}").
//
// lessSecure selects the HTTP-only bootstrap channel. Per AGENTS.md, that
// channel is reserved for exactly three cases: this client cannot yet trust
// the server's TLS certificate, a startup announcement, and a liveness
// heartbeat (see reportTLSTrustIssue, reportStarted, startHeartbeat below).
// Everything else should go over the secure HTTPS channel (lessSecure=false)
// via LogSecure, which is the default for normal diagnostics.
//
// This is fire-and-forget: a broken or unreachable client-messages endpoint
// must never affect mounting, reading, or writing, so failures are logged
// locally at Debug level and otherwise swallowed.
func (c *Client) sendClientMessage(lessSecure bool, payload ClientMessagePayload) {
	if len(c.ClientKey) == 0 || c.ClientId == "" {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	aad := "clientMessage:" + c.ClientId
	if lessSecure {
		aad = "lessSecureClientMessage:" + c.ClientId
	}
	nonce, ciphertext, err := encryptEnvelope(body, c.ClientKey, aad)
	if err != nil {
		tlog.Debug.Printf("externalenc: could not encrypt client message: %v", err)
		return
	}
	env := clientLogEnvelope{
		ClientId:   c.ClientId,
		Algorithm:  "AES-256-GCM",
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	reqBody, err := json.Marshal(env)
	if err != nil {
		return
	}

	targetURL := c.BaseURL + "/api/v1/client-messages"
	httpClient := c.HTTPClient
	if lessSecure {
		base := c.LessSecureBaseURL
		if base == "" {
			base = lessSecureBaseURL(c.BaseURL)
		}
		targetURL = base + "/api/v1/less-secure/client-messages"
		httpClient = &http.Client{Timeout: 5 * time.Second} // plain HTTP, nothing to pin
	}

	// Sent in the background: a slow or unreachable client-messages endpoint
	// (quite likely exactly when reportTLSTrustIssue is calling this) must
	// never add latency to mounting, pairing, or key fetches.
	go func() {
		resp, err := httpClient.Post(targetURL, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			tlog.Debug.Printf("externalenc: client-message post to %s failed: %v", targetURL, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			tlog.Debug.Printf("externalenc: client-message to %s rejected: status %d", targetURL, resp.StatusCode)
		}
	}()
}

// LogSecure sends a diagnostic message over the trusted HTTPS channel. Use
// this for everything except the three less-secure cases documented on
// sendClientMessage — it's the default for normal operation.
func (c *Client) LogSecure(level, title, message string, details map[string]interface{}) {
	c.sendClientMessage(false, ClientMessagePayload{
		Category: "log",
		Level:    level,
		Title:    title,
		Message:  message,
		Source:   "externalenc",
		Details:  details,
	})
}

// reportTLSTrustIssue sends a less-secure "userMessage" about a TLS
// certificate problem — the one case where, by definition, this client does
// not yet trust the server enough to use the HTTPS client-messages endpoint.
func (c *Client) reportTLSTrustIssue(message string) {
	c.sendClientMessage(true, ClientMessagePayload{
		Category: "userMessage",
		Level:    "error",
		Title:    "TLS certificate not trusted",
		Message:  message,
		Source:   "externalenc",
	})
}

// reportStarted sends a less-secure "I've started, what's up" announcement,
// sent before pairing/session establishment — by definition there is no
// trusted session yet to use the secure channel with.
func (c *Client) reportStarted() {
	c.sendClientMessage(true, ClientMessagePayload{
		Category: "log",
		Level:    "info",
		Title:    "115fs client started",
		Message:  fmt.Sprintf("Initializing session with %s (keyName=%s)", c.BaseURL, c.KeyName),
		Source:   "externalenc",
	})
}

// startHeartbeat runs until stopCh is closed, periodically sending a
// less-secure "I'm still alive" message. It always uses the less-secure
// channel — a heartbeat is meant to work as an out-of-band liveness signal
// even when something else about the session or TLS trust is broken.
func (c *Client) startHeartbeat(stopCh <-chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.sendClientMessage(true, ClientMessagePayload{
				Category: "log",
				Level:    "debug",
				Title:    "115fs client heartbeat",
				Message:  "still alive",
				Source:   "externalenc",
			})
		}
	}
}
