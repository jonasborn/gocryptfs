// Package pinning implements TLS certificate fingerprint pinning: computing a
// certificate's SHA256 fingerprint, comparing it against a pinned value with
// no bypass and no partial (prefix) match, rendering a Drunken-Bishop visual
// fingerprint, and reading an operator-entered fingerprint from the
// controlling terminal.
//
// It exists so this logic is implemented exactly once. It used to be
// duplicated independently in 115fs's main.go (for the wrapper's pre-flight
// health check) and in gocryptfs's internal/externalenc package (for the
// actual key-server connection) — two copies of the same security-sensitive
// comparison meant a fix to one (e.g. removing the prefix-match acceptance)
// was easy to forget in the other.
package pinning

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// FingerprintBytes returns the raw SHA256 digest of a certificate (as found
// in tls.ConnectionState.PeerCertificates[i].Raw or VerifyPeerCertificate's
// rawCerts[0]). Use this (not the hex string from Fingerprint) as input to
// DrunkenBishop, which visualizes the digest bytes themselves.
func FingerprintBytes(rawCert []byte) [sha256.Size]byte {
	return sha256.Sum256(rawCert)
}

// Fingerprint returns the lowercase hex-encoded SHA256 hash of a raw
// certificate (as found in tls.ConnectionState.PeerCertificates[i].Raw or
// VerifyPeerCertificate's rawCerts[0]).
func Fingerprint(rawCert []byte) string {
	fp := FingerprintBytes(rawCert)
	return hex.EncodeToString(fp[:])
}

// Matches reports whether actual matches the pinned fingerprint. Comparison
// is exact (case-insensitive only) — there is deliberately no prefix/partial
// match, since accepting one would let a truncated pin (copy-paste error, a
// user shortening it "for convenience") silently accept any certificate
// sharing that prefix.
func Matches(pinned, actual string) bool {
	if pinned == "" {
		return false
	}
	return strings.EqualFold(pinned, actual)
}

// ProbeCertificate dials host (host:port) over TLS and returns the raw leaf
// certificate the server presents, without validating it against any trust
// store — verification is the caller's job, done via Fingerprint/Matches
// against a pinned value. host must already include a port; DialHostPort
// below normalizes a bare provider URL into that form.
func ProbeCertificate(host string, timeout time.Duration) ([]byte, error) {
	var serverCert []byte
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) > 0 {
				serverCert = rawCerts[0]
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection error to %s: %w", host, err)
	}
	conn.Close()
	if len(serverCert) == 0 {
		return nil, fmt.Errorf("no server certificate presented")
	}
	return serverCert, nil
}

// DialHostPort normalizes a provider URL/host into a "host:port" string
// suitable for ProbeCertificate, defaulting to :443.
func DialHostPort(providerURL string) string {
	host := providerURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	return host
}

// PromptFingerprint reads an operator-entered certificate fingerprint from
// the controlling terminal (preferring /dev/tty so it still works when
// stdin/stdout are piped, e.g. under 115fs's own subprocess wrapping).
func PromptFingerprint() string {
	fmt.Printf("Enter server certificate SHA256 hash: ")
	var input string
	if tty, err := os.Open("/dev/tty"); err == nil {
		reader := bufio.NewReader(tty)
		input, _ = reader.ReadString('\n')
		tty.Close()
	} else {
		reader := bufio.NewReader(os.Stdin)
		input, _ = reader.ReadString('\n')
	}
	return strings.TrimSpace(input)
}

// DrunkenBishop generates an OpenSSH-style ASCII-art random-walk visualization
// of a fingerprint, using digits only (0-9) instead of the usual mixed
// character set, so it renders identically everywhere. The algorithm mirrors
// db.js, which independently reimplements this same visualization in
// JavaScript for a browser-side Web UI — that duplication is intentional
// (different language/runtime), unlike the Go copies this package replaces.
func DrunkenBishop(data []byte, title string) string {
	const width = 17
	const height = 9

	startX := width / 2  // 8
	startY := height / 2 // 4

	var board [height + 1][width + 1]int
	x := startX
	y := startY

	isValidMove := func(mx, my int) bool {
		return mx >= 0 && mx <= width && my >= 0 && my <= height
	}

	for _, b := range data {
		for c := 0; c < 8; c += 2 {
			bit0 := (b >> c) & 1
			bit1 := (b >> (c + 1)) & 1
			move := fmt.Sprintf("%d%d", bit1, bit0)

			switch move {
			case "00":
				if isValidMove(x-1, y-1) {
					x--
					y--
				} else if isValidMove(x-1, y) {
					x--
				} else if isValidMove(x, y-1) {
					y--
				}
			case "01":
				if isValidMove(x+1, y-1) {
					x++
					y--
				} else if isValidMove(x+1, y) {
					x++
				} else if isValidMove(x, y-1) {
					y--
				}
			case "10":
				if isValidMove(x-1, y+1) {
					x--
					y++
				} else if isValidMove(x-1, y) {
					x--
				} else if isValidMove(x, y+1) {
					y++
				}
			case "11":
				if isValidMove(x+1, y+1) {
					x++
					y++
				} else if isValidMove(x+1, y) {
					x++
				} else if isValidMove(x, y+1) {
					y++
				}
			}

			board[y][x]++
		}
	}

	endX, endY := x, y

	numChars := []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}

	var buf bytes.Buffer
	buf.WriteString("+---[" + title + "]---+\n")
	for r := 0; r <= height; r++ {
		buf.WriteString("|")
		for c := 0; c <= width; c++ {
			if r == startY && c == startX {
				buf.WriteRune('S')
			} else if r == endY && c == endX {
				buf.WriteRune('E')
			} else {
				val := board[r][c]
				if val == 0 {
					buf.WriteRune(' ')
				} else {
					idx := (val - 1) % len(numChars)
					buf.WriteRune(numChars[idx])
				}
			}
		}
		buf.WriteString("|\n")
	}
	buf.WriteString("+-------------------+\n")
	return buf.String()
}
