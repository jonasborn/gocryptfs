package externalenc

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rfjakob/gocryptfs/v2/carter/ksclient"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// heartbeatInterval is deliberately long — a liveness signal, not a status
// feed — so it never fires during a normal test run.
const heartbeatInterval = 10 * time.Minute

// untrustedBaseURL derives the untrusted HTTP bootstrap listener's base URL
// from the trusted HTTPS one: same host, port 9080 — carter-keyserver.yaml's
// "servers" list always pairs a :9443 HTTPS entry with a :9080 HTTP one for
// the same host.
func untrustedBaseURL(trustedBaseURL string) string {
	u, err := url.Parse(trustedBaseURL)
	if err != nil || u.Hostname() == "" {
		return trustedBaseURL
	}
	return "http://" + u.Hostname() + ":9080"
}

// untrustedClient lazily builds a plain-HTTP client for the untrusted
// bootstrap listener (nothing to pin — that's the whole point of this
// channel) pointed at c.LessSecureBaseURL or, if unset, untrustedBaseURL of
// c.BaseURL.
func (c *Client) untrustedClient() *ksclient.Client {
	base := c.LessSecureBaseURL
	if base == "" {
		base = untrustedBaseURL(c.BaseURL)
	}
	return ksclient.New(base, &http.Client{Timeout: 5 * time.Second})
}

// sendLog submits a diagnostic or user-facing log line, fire-and-forget: a
// broken or unreachable logs endpoint must never affect mounting, reading, or
// writing, so failures are only logged locally at Debug level.
//
// untrusted selects the plain-HTTP bootstrap listener. Per AGENTS.md, that
// channel is reserved for exactly three cases: this client cannot yet trust
// the server's TLS certificate, a startup announcement, and a liveness
// heartbeat (see reportTLSTrustIssue, reportStarted, startHeartbeat below).
// Everything else should go over the trusted HTTPS channel (untrusted=false)
// via LogSecure, the default for normal diagnostics.
func (c *Client) sendLog(untrusted bool, level, title, message string) {
	go func() {
		var err error
		if untrusted {
			err = c.untrustedClient().SubmitUntrustedLog(level, title, message, "externalenc")
		} else if c.ks != nil {
			err = c.ks.SubmitLog(level, title, message, "externalenc")
		}
		if err != nil {
			tlog.Debug.Printf("externalenc: log submission failed: %v", err)
		}
	}()
}

// LogSecure sends a diagnostic message over the trusted HTTPS channel. Use
// this for everything except the three less-secure cases documented on
// sendLog — it's the default for normal operation.
func (c *Client) LogSecure(level, title, message string, _ map[string]interface{}) {
	c.sendLog(false, level, title, message)
}

// reportTLSTrustIssue sends an untrusted-channel message about a TLS
// certificate problem — the one case where, by definition, this client does
// not yet trust the server enough to use the HTTPS logs endpoint.
func (c *Client) reportTLSTrustIssue(message string) {
	c.sendLog(true, "error", "TLS certificate not trusted", message)
}

// reportStarted sends an untrusted-channel "I've started, what's up"
// announcement, sent before the transport/card session is established — by
// definition there is no trusted session yet to use the secure channel with.
func (c *Client) reportStarted() {
	c.sendLog(true, "info", "115fs client started",
		"Initializing "+strings.TrimSpace(c.BaseURL)+" (keyId="+keyIDHex(c.KeyID)+")")
}

// startHeartbeat runs until stopCh is closed, periodically sending an
// untrusted-channel "I'm still alive" message. It always uses the untrusted
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
			c.sendLog(true, "debug", "115fs client heartbeat", "still alive")
		}
	}
}
