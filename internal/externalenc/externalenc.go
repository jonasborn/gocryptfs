package externalenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"github.com/rfjakob/gocryptfs/v2/pinning"
)

const (
	DefaultServerURL = "https://192.168.2.223:9443"
	DefaultKeyName   = "default"
	DefaultBlockSize = 64
)

// Smart LRU Key & AEAD Cipher Cache with explicit memory zeroing
type lruEntry struct {
	blockIndex uint64
	key        []byte
	aead       cipher.AEAD
	prev, next *lruEntry
}

type smartAEADCache struct {
	capacity int
	items    map[uint64]*lruEntry
	head     *lruEntry
	tail     *lruEntry
}

func newSmartAEADCache(capacity int) *smartAEADCache {
	if capacity <= 0 {
		capacity = 4096 // Default 4096 blocks = 16 MB active window
	}
	return &smartAEADCache{
		capacity: capacity,
		items:    make(map[uint64]*lruEntry),
	}
}

// zeroEntry explicitly overwrites the secret key slice bytes in memory with zeros before dropping reference
func (c *smartAEADCache) zeroEntry(e *lruEntry) {
	if e == nil {
		return
	}
	if e.key != nil {
		for i := range e.key {
			e.key[i] = 0
		}
		e.key = nil
	}
	e.aead = nil
}

func (c *smartAEADCache) removeEntry(e *lruEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	delete(c.items, e.blockIndex)
	c.zeroEntry(e)
}

func (c *smartAEADCache) get(blockIndex uint64) (cipher.AEAD, []byte, bool) {
	e, ok := c.items[blockIndex]
	if !ok {
		return nil, nil, false
	}
	// Move entry to head (most recently used)
	if e != c.head {
		if e.prev != nil {
			e.prev.next = e.next
		}
		if e.next != nil {
			e.next.prev = e.prev
		} else {
			c.tail = e.prev
		}
		e.prev = nil
		e.next = c.head
		if c.head != nil {
			c.head.prev = e
		}
		c.head = e
	}
	keyCopy := append([]byte(nil), e.key...)
	return e.aead, keyCopy, true
}

func (c *smartAEADCache) put(blockIndex uint64, key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	if e, ok := c.items[blockIndex]; ok {
		// Zero out old key memory before updating
		for i := range e.key {
			e.key[i] = 0
		}
		e.key = append([]byte(nil), key...)
		e.aead = gcm
		return gcm, nil
	}

	// Evict tail if capacity limit reached
	if len(c.items) >= c.capacity && c.tail != nil {
		c.removeEntry(c.tail)
	}

	keyCopy := append([]byte(nil), key...)
	e := &lruEntry{
		blockIndex: blockIndex,
		key:        keyCopy,
		aead:       gcm,
		next:       c.head,
	}

	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}

	c.items[blockIndex] = e
	return gcm, nil
}

func (c *smartAEADCache) purge() {
	curr := c.head
	for curr != nil {
		next := curr.next
		c.zeroEntry(curr)
		curr = next
	}
	c.items = make(map[uint64]*lruEntry)
	c.head = nil
	c.tail = nil
}

// smartEMECache is an LRU cache of per-directory EME ciphers, keyed by the
// directory-IV-derived index from nameKeyIndex. It mirrors smartAEADCache's
// structure and zeroing behavior, just for filename keys instead of content
// keys.
type nameLruEntry struct {
	index      uint64
	key        []byte
	eme        *eme.EMECipher
	prev, next *nameLruEntry
}

type smartEMECache struct {
	capacity int
	items    map[uint64]*nameLruEntry
	head     *nameLruEntry
	tail     *nameLruEntry
}

func newSmartEMECache(capacity int) *smartEMECache {
	if capacity <= 0 {
		capacity = 2048
	}
	return &smartEMECache{
		capacity: capacity,
		items:    make(map[uint64]*nameLruEntry),
	}
}

func (c *smartEMECache) zeroEntry(e *nameLruEntry) {
	if e == nil {
		return
	}
	if e.key != nil {
		for i := range e.key {
			e.key[i] = 0
		}
		e.key = nil
	}
	e.eme = nil
}

func (c *smartEMECache) removeEntry(e *nameLruEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	delete(c.items, e.index)
	c.zeroEntry(e)
}

func (c *smartEMECache) get(index uint64) (*eme.EMECipher, bool) {
	e, ok := c.items[index]
	if !ok {
		return nil, false
	}
	if e != c.head {
		if e.prev != nil {
			e.prev.next = e.next
		}
		if e.next != nil {
			e.next.prev = e.prev
		} else {
			c.tail = e.prev
		}
		e.prev = nil
		e.next = c.head
		if c.head != nil {
			c.head.prev = e
		}
		c.head = e
	}
	return e.eme, true
}

func (c *smartEMECache) put(index uint64, key []byte) (*eme.EMECipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	emeCipher := eme.New(block)

	if e, ok := c.items[index]; ok {
		for i := range e.key {
			e.key[i] = 0
		}
		e.key = append([]byte(nil), key...)
		e.eme = emeCipher
		return emeCipher, nil
	}

	if len(c.items) >= c.capacity && c.tail != nil {
		c.removeEntry(c.tail)
	}

	keyCopy := append([]byte(nil), key...)
	e := &nameLruEntry{
		index: index,
		key:   keyCopy,
		eme:   emeCipher,
		next:  c.head,
	}
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
	c.items[index] = e
	return emeCipher, nil
}

func (c *smartEMECache) purge() {
	curr := c.head
	for curr != nil {
		next := curr.next
		c.zeroEntry(curr)
		curr = next
	}
	c.items = make(map[uint64]*nameLruEntry)
	c.head = nil
	c.tail = nil
}

func encryptEnvelope(plaintext []byte, key []byte, aad string) (string, string, error) {
	if len(key) == 0 {
		return "", "", fmt.Errorf("encryption key is empty")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))
	return base64.RawURLEncoding.EncodeToString(nonce), base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decryptEnvelope(nonceStr string, ciphertextStr string, key []byte, aad string) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("decryption key is empty")
	}
	if nonceStr == "" || ciphertextStr == "" {
		return nil, fmt.Errorf("empty nonce or ciphertext")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceStr)
	if err != nil {
		nonce, err = base64.StdEncoding.DecodeString(nonceStr)
		if err != nil {
			return nil, fmt.Errorf("invalid nonce base64: %v", err)
		}
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextStr)
	if err != nil {
		ciphertext, err = base64.StdEncoding.DecodeString(ciphertextStr)
		if err != nil {
			return nil, fmt.Errorf("invalid ciphertext base64: %v", err)
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length %d (expected %d)", len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, []byte(aad))
}

// Client handles interaction with the external Carter Keyserver API.
//
// There is no filesystem-wide master key anywhere in this struct. Both file
// content (via cache/GetBlockAEAD) and filenames (via nameCache/GetNameEME)
// are keyed entirely by per-index material fetched from the external
// provider, so nothing cryptographically meaningful is ever derived from
// local secrets.
type Client struct {
	BaseURL          string
	KeyName          string
	ClientId         string
	ClientKey        []byte
	HTTPClient       *http.Client
	SessionToken     string
	RefreshToken     string
	SessionKey       []byte
	SessionExpiresAt time.Time
	CertFingerprint  string
	// LessSecureBaseURL is the HTTP-only bootstrap listener's base URL
	// (scheme+host+port), used for the three less-secure cases documented on
	// sendClientMessage. Empty means "derive it from BaseURL" (see
	// lessSecureBaseURL) — the historical behavior, kept as the fallback so
	// callers that don't know about this field still work unchanged.
	LessSecureBaseURL string
	MaxBlockCount     int
	cache             *smartAEADCache
	nameCache         *smartEMECache
	mu                sync.RWMutex
	fallbackWarned    bool
	lastServerCert    []byte
	lastCertHashHex   string
	// stopHeartbeat, closed exactly once (via stopOnce) by ExternalAEAD.Wipe,
	// signals the background goroutine started in NewClient (see
	// startHeartbeat in clientmessages.go) to stop sending "still alive"
	// messages.
	stopHeartbeat chan struct{}
	stopOnce      sync.Once
}

// Struct definitions matching OpenAPI schemas

type HealthResponse struct {
	Status        string `json:"status"`
	ServiceName   string `json:"serviceName"`
	HTTPSRequired bool   `json:"httpsRequired"`
}

type EncryptedEnvelope struct {
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type ClientEncryptedEnvelope struct {
	ClientId   string `json:"clientId"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type CreatePairingRequest struct {
	ClientId   string `json:"clientId,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	ClientName string `json:"clientName,omitempty"`
}

type CreatePairingPayload struct {
	ClientName      string `json:"clientName,omitempty"`
	ClientPublicKey string `json:"clientPublicKey,omitempty"`
}

type CreatePairingResponse struct {
	PairingRequestId string `json:"pairingRequestId"`
	ClientId         string `json:"clientId,omitempty"`
	PairingCode      string `json:"pairingCode,omitempty"`
	ExpiresAt        string `json:"expiresAt"`
}

type ApprovePairingRequest struct {
	PairingCode     string `json:"pairingCode"`
	CardChallengeId string `json:"cardChallengeId,omitempty"`
	CardPinResponse string `json:"cardPinResponse"`
}

type PendingPairingRequest struct {
	PairingRequestId string `json:"pairingRequestId"`
	ClientId         string `json:"clientId,omitempty"`
	ClientName       string `json:"clientName"`
	ClientIp         string `json:"clientIp"`
	PairingCode      string `json:"pairingCode"`
	CreatedAt        string `json:"createdAt"`
	ExpiresAt        string `json:"expiresAt"`
}

type SessionPolicy struct {
	MaxBlockCount          int `json:"maxBlockCount"`
	ApprovalTimeoutSeconds int `json:"approvalTimeoutSeconds"`
	ApprovalLeaseSeconds   int `json:"approvalLeaseSeconds"`
}

type RefreshSessionRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type SessionResponse struct {
	ClientId         string        `json:"clientId,omitempty"`
	DeviceId         string        `json:"deviceId,omitempty"`
	ClientName       string        `json:"clientName,omitempty"`
	ClientIp         string        `json:"clientIp,omitempty"`
	SessionToken     string        `json:"sessionToken"`
	RefreshToken     string        `json:"refreshToken"`
	SessionKey       string        `json:"sessionKey,omitempty"`
	SessionExpiresAt string        `json:"sessionExpiresAt,omitempty"`
	RefreshExpiresAt string        `json:"refreshExpiresAt,omitempty"`
	Policy           SessionPolicy `json:"policy"`
}

type BlockPasswordRequest struct {
	ClientNonce      string `json:"clientNonce,omitempty"`
	EncryptedPayload string `json:"encryptedPayload,omitempty"`
	// Unencrypted fallback fields:
	KeyName    string `json:"keyName,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	BlockIndex int64  `json:"blockIndex,omitempty"`
	BlockCount int    `json:"blockCount,omitempty"`
	Purpose    string `json:"purpose,omitempty"`
}

// BlockPasswordPayload's Prefix is required by the API (the card uses it to learn/enforce
// per-key usage patterns, see errCardRechallengeRequired) - see fetchBlockPasswords for what
// 115fs sends.
type BlockPasswordPayload struct {
	KeyName    string `json:"keyName"`
	Prefix     string `json:"prefix"`
	BlockIndex int64  `json:"blockIndex"`
	BlockCount int    `json:"blockCount"`
	Purpose    string `json:"purpose,omitempty"`
}

type BlockPasswordResponse struct {
	KeyName    string `json:"keyName"`
	Prefix     string `json:"prefix,omitempty"`
	KeyId      string `json:"keyId,omitempty"`
	BlockIndex int64  `json:"blockIndex"`
	BlockCount int    `json:"blockCount"`
	// KeyMaterial is the current API's primary field (map from block index string to
	// base64url 32-byte card-derived key material). Passwords is the deprecated
	// compatibility alias the API still accepts for older callers; fetchBlockPasswords
	// prefers KeyMaterial and only falls back to Passwords if it's empty.
	KeyMaterial map[string]string `json:"keyMaterial,omitempty"`
	Passwords   map[string]string `json:"passwords,omitempty"`
	ErrorCode   string            `json:"errorCode,omitempty"`
	Message     string            `json:"message,omitempty"`
}

// NewClient initializes a new external encryption provider client. salt is
// the persisted per-installation salt used to derive ClientKey from
// clientKeyStr when the latter isn't already a raw 32-byte key (see
// deriveClientKey) — pass nil only when clientKeyStr is itself a valid
// 32-byte base64 key, since there is otherwise no way to derive the exact
// same key on every run. lessSecureBaseURL overrides the HTTP-only bootstrap
// listener's base URL; pass "" to keep deriving it from baseURL (see
// Client.LessSecureBaseURL).
func NewClient(baseURL string, keyName string, clientKeyStr string, certHash string, lessSecureBaseURL string, salt []byte) (*Client, error) {
	if baseURL == "" {
		baseURL = DefaultServerURL
	}
	if keyName == "" {
		keyName = DefaultKeyName
	}

	c := &Client{
		BaseURL:           baseURL,
		KeyName:           keyName,
		ClientId:          "115fs-worker",
		MaxBlockCount:     DefaultBlockSize,
		cache:             newSmartAEADCache(4096),
		nameCache:         newSmartEMECache(2048),
		SessionExpiresAt:  time.Now().Add(24 * time.Hour), // Enforce max 24h session token lifetime
		CertFingerprint:   certHash,
		LessSecureBaseURL: lessSecureBaseURL,
	}

	if clientKeyStr != "" {
		parts := strings.SplitN(clientKeyStr, ":", 2)
		if len(parts) == 2 {
			c.ClientId = parts[0]
			clientKeyStr = parts[1]
		}
		if err := c.deriveClientKey(clientKeyStr, salt); err != nil {
			return nil, err
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Inspected manually via VerifyPeerCertificate
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) > 0 {
					c.lastServerCert = rawCerts[0]
					c.lastCertHashHex = pinning.Fingerprint(rawCerts[0])
				}
				if c.CertFingerprint != "" && !pinning.Matches(c.CertFingerprint, c.lastCertHashHex) {
					return fmt.Errorf("TLS certificate fingerprint mismatch")
				}
				return nil
			},
		},
	}
	c.HTTPClient = &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}

	// "I've started, what's up" — sent once, here, before pairing/TLS trust
	// is established. initSession (below) can be re-invoked later on session
	// expiry/re-pairing; that's not a fresh client start, so it deliberately
	// does not repeat this message.
	c.reportStarted()

	// Mandatory session initialization and pairing
	err := c.initSession()
	if err != nil {
		return nil, fmt.Errorf("externalenc: pairing and session initialization failed: %w", err)
	}

	c.stopHeartbeat = make(chan struct{})
	go c.startHeartbeat(c.stopHeartbeat)

	return c, nil
}

// scryptN, scryptR, scryptP mirror configfile.ScryptDefaultLogN's parameters
// (N=2^16, r=8, p=1) — gocryptfs's own master-key KDF settings — since these
// are the vetted values already used elsewhere in this codebase for turning a
// human-memorable secret into a 32-byte key.
const (
	scryptN = 1 << 16
	scryptR = 8
	scryptP = 1
)

// deriveClientKey sets c.ClientKey from clientKeyStr. If clientKeyStr decodes
// as a raw 32-byte key (base64, raw or standard padding), it's used directly
// — it already has full key entropy, so no KDF is needed. Otherwise it's
// treated as a human-chosen passphrase and run through scrypt with the
// supplied salt. Unlike a plain hash, this makes brute-forcing a low-entropy
// passphrase from intercepted pairing/session-key ciphertext computationally
// expensive, and — being salted — means the same passphrase never derives to
// the same key across two different installations.
//
// salt must be non-empty for the passphrase path; the caller (NewClient) is
// responsible for sourcing a persisted salt (see 115fs's config-based
// symmetric-key-id lookup) so the same key is derived on every run.
func (c *Client) deriveClientKey(clientKeyStr string, salt []byte) error {
	if rawKey, err := base64.RawURLEncoding.DecodeString(clientKeyStr); err == nil && len(rawKey) == 32 {
		c.ClientKey = rawKey
		return nil
	}
	if rawKey, err := base64.StdEncoding.DecodeString(clientKeyStr); err == nil && len(rawKey) == 32 {
		c.ClientKey = rawKey
		return nil
	}
	if len(salt) == 0 {
		return fmt.Errorf("externalenc: no salt available to derive a key from the configured passphrase — pass a raw 32-byte base64 key instead, or configure this client through 115fs (see -symmetric-key-from-config)")
	}
	key, err := scrypt.Key([]byte(clientKeyStr), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return fmt.Errorf("externalenc: deriving key from passphrase: %w", err)
	}
	c.ClientKey = key
	return nil
}

func (c *Client) probeAndVerifyTLSCertificate() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid BaseURL: %w", err)
	}
	if u.Scheme == "http" {
		return nil
	}

	cert, err := pinning.ProbeCertificate(pinning.DialHostPort(c.BaseURL), 5*time.Second)
	if err != nil {
		return err
	}
	c.lastServerCert = cert
	c.lastCertHashHex = pinning.Fingerprint(cert)

	return c.verifyTLSCertificate()
}

func (c *Client) verifyTLSCertificate() error {
	if len(c.lastServerCert) == 0 {
		return nil
	}

	certHashHex := pinning.Fingerprint(c.lastServerCert)
	alreadyPinned := pinning.Matches(c.CertFingerprint, certHashHex)

	if c.CertFingerprint != "" && !alreadyPinned {
		tlog.Warn.Printf("externalenc: TLS certificate fingerprint mismatch!")
		// The one case where, by definition, this client cannot yet trust the
		// server enough to report the problem over the secure HTTPS channel —
		// send it over the less-secure bootstrap listener instead.
		c.reportTLSTrustIssue(fmt.Sprintf("Certificate fingerprint mismatch for %s: expected %s, got %s", c.BaseURL, c.CertFingerprint, certHashHex))
	}

	if !alreadyPinned {
		// Mandatory interactive verification — there is no bypass. A fingerprint supplied
		// up front via -tls-hash (and matching) short-circuits above without ever reaching here.
		fpBytes := pinning.FingerprintBytes(c.lastServerCert)
		visual := pinning.DrunkenBishop(fpBytes[:], "TLS CERT FINGERPRINT")
		fmt.Printf("\n=== EXTERNAL SERVER TLS CERTIFICATE VERIFICATION ===\n")
		fmt.Printf("Server Endpoint: %s\n\n", c.BaseURL)
		fmt.Print(visual)

		input := pinning.PromptFingerprint()
		if input != "" && pinning.Matches(input, certHashHex) {
			c.CertFingerprint = certHashHex
			fmt.Printf("✓ Server TLS certificate fingerprint pinned successfully.\n\n")
		} else {
			return fmt.Errorf("TLS certificate fingerprint verification failed")
		}
	}

	return nil
}

func (c *Client) initSession() error {
	// 1. Probe and verify TLS certificate BEFORE making any HTTP requests (including /health)
	if err := c.probeAndVerifyTLSCertificate(); err != nil {
		return fmt.Errorf("TLS certificate verification failed: %w", err)
	}

	// 2. Health check (dispatched only AFTER certificate fingerprint has been verified/pinned by user)
	resp, err := c.HTTPClient.Get(c.BaseURL + "/health")
	if err != nil {
		return fmt.Errorf("health check error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	// Every endpoint 115fs actually talks to (pairing request, session-key, refresh,
	// block-passwords) requires the registered clientKey envelope per the API contract —
	// there's no legitimate unencrypted path. Fail fast with a clear message instead of
	// sending a request the server can only reject.
	if len(c.ClientKey) == 0 {
		return fmt.Errorf("no registered clientId/clientKey configured — register a 115fs client through the key server's Web UI first")
	}

	// 3. Create pairing request
	payload := CreatePairingPayload{ClientName: "115fs"}
	payloadBytes, _ := json.Marshal(payload)

	aad := "pairingRequest:" + c.ClientId
	nonce, ciphertext, err := encryptEnvelope(payloadBytes, c.ClientKey, aad)
	if err != nil {
		return fmt.Errorf("encrypting pairing request: %w", err)
	}
	pairReq := CreatePairingRequest{
		ClientId:   c.ClientId,
		Algorithm:  "AES-256-GCM",
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	reqBody, _ := json.Marshal(pairReq)

	resp, err = c.HTTPClient.Post(c.BaseURL+"/api/v1/pairing-requests", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("pairing request error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pairing request returned status %d: %s", resp.StatusCode, string(b))
	}

	respBytes, _ := io.ReadAll(resp.Body)
	var pairResp CreatePairingResponse
	var env EncryptedEnvelope
	if err := json.Unmarshal(respBytes, &env); err == nil && env.Ciphertext != "" {
		aadResp := "pairingResponse:" + c.ClientId
		decrypted, decErr := decryptEnvelope(env.Nonce, env.Ciphertext, c.ClientKey, aadResp)
		if decErr == nil {
			json.Unmarshal(decrypted, &pairResp)
		} else {
			json.Unmarshal(respBytes, &pairResp)
		}
	} else {
		json.Unmarshal(respBytes, &pairResp)
	}

	reqID := pairResp.PairingRequestId
	if reqID == "" {
		return fmt.Errorf("pairing request did not return a pairingRequestId")
	}

	tlog.Info.Printf("externalenc: created pairing request %s (code: %s) — waiting for approval on the Key Server / Web UI...", reqID, pairResp.PairingCode)

	// The card challenge that approval is bound to ("/approve will fail unless this
	// exact challenge is answered") is created by whoever answers it — the trusted
	// Web UI/browser (or an auto-approve service acting in its place) when it picks up
	// the pending pairing request, not by 115fs. Confirmed against the real Key
	// Server: 115fs has no browser session to create one with (POST /card-challenge
	// always 403s "browserNotRegistered" for a headless caller) and pairing still
	// completes fine without it, so there's nothing for the client to do here but
	// poll for the resulting session.
	return c.waitForApprovedSession(reqID)
}

// errPairingRequestGone means the server no longer has any record of the pairing
// request (HTTP 404 / errorCode "pairingRequestNotFound") — per the API, that happens
// when it expired or was explicitly denied (POST .../deny "[r]emoves a pending pairing
// request"). Either way the request is gone for good: polling the same reqID again can
// never turn it back into an approval, so this is treated as terminal rather than
// something to keep retrying like the normal 202 "still pending" response.
var errPairingRequestGone = errors.New("pairing request no longer exists on the Key Server (expired or denied)")

// errKeyAccessUnsupported means the server responded to a block-passwords request with
// HTTP 501 — by definition (unlike a transient 5xx) the server itself doesn't implement
// the capability at all (e.g. no Carter card APDU extension present), so no amount of
// retrying the same request will ever turn it into a 200. The current API no longer
// documents 501 for this endpoint (the card APDU extension is implemented server-side
// now), but the check is kept as a defensive fallback for older/other deployments.
var errKeyAccessUnsupported = errors.New("key server does not implement block-password derivation")

// errSessionInvalid means the server responded to a block-passwords request with HTTP
// 401 — the one block-passwords failure that's about the *session*, not the request
// itself, so it's the one case waitForKeys re-authenticates and retries instead of
// failing straight away.
var errSessionInvalid = errors.New("key server rejected the session")

// errCardRechallengeRequired means the server responded with HTTP 423 /
// cardUsageRechallengeRequired: the card's own usage policy has decided the observed
// pattern for this key/prefix needs fresh user presence before it will derive more key
// material. Per the API, "115fs must wait for the user/keyserver rechallenge flow before
// requesting more key material" — but that rechallenge happens on the Web UI/browser side
// (like pairing approval), not through any request 115fs can make or poll for. Blocking a
// FUSE call here for an unbounded, externally-driven event would recreate exactly the
// un-Ctrl-C-able wait this package's fail-fast design exists to avoid, so this fails the
// current operation immediately instead; the next access to this key naturally retries
// once the operator completes the rechallenge.
var errCardRechallengeRequired = errors.New("card requires a user rechallenge before more key material can be issued")

// errCardUnavailable means the server responded with HTTP 424: the keyserver itself is
// fine, but its dependency (the physical Carter card/reader) is not, so the request could
// not be relayed at all. Not something retrying the identical request fixes on its own.
var errCardUnavailable = errors.New("key server could not reach the Carter card")

// waitForApprovedSession polls the encrypted /session-key endpoint until the Web UI
// operator approves the pairing request (or the wait times out). This is deliberately
// the *only* way 115fs collects session material: /approve is documented as a
// trusted-browser-only endpoint requiring a cardPinResponse that a headless worker has
// no way to produce, so 115fs must never call it directly. A non-200 response here
// (e.g. the spec's 202 "still pending") just means approval hasn't happened yet.
func (c *Client) waitForApprovedSession(reqID string) error {
	const pollInterval = 2 * time.Second
	const maxAttempts = 900 // ~30 minutes — approving a pairing request is a human/Web UI action
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := c.tryCollectSessionKey(reqID)
		if err == nil && c.SessionToken != "" {
			return nil
		}
		lastErr = err
		if errors.Is(err, errPairingRequestGone) {
			// Stop immediately instead of burning the full ~30 minute timeout polling
			// a request that the server has already discarded and will never approve.
			return fmt.Errorf("pairing request %s expired or was denied before it was approved: %w", reqID, err)
		}
		var msg string
		if attempt == 0 {
			msg = fmt.Sprintf("pairing request %s pending approval on the Key Server / Web UI...", reqID)
		} else if attempt%15 == 0 {
			msg = fmt.Sprintf("still waiting for approval of pairing request %s (attempt %d): %v", reqID, attempt+1, lastErr)
		}
		if msg != "" {
			tlog.Info.Printf("externalenc: %s", msg)
			// Mirrored to the Key Server itself (secure channel — TLS is already
			// verified and ClientKey is set by this point in initSession, see
			// probeAndVerifyTLSCertificate above) so an operator watching the Web
			// UI's client log dashboard sees the same wait-status updates a human
			// running 115fs locally sees on their own console.
			c.LogSecure("info", "Pairing approval pending", msg, map[string]interface{}{"pairingRequestId": reqID, "attempt": attempt + 1})
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("timed out waiting for pairing approval: %v", lastErr)
}

func (c *Client) tryCollectSessionKey(reqID string) error {
	sessionKeyURL := fmt.Sprintf("%s/api/v1/pairing-requests/%s/session-key", c.BaseURL, reqID)
	aadReq := fmt.Sprintf("pairingSessionRequest:%s:%s", c.ClientId, reqID)
	nonce, ciphertext, err := encryptEnvelope([]byte("{}"), c.ClientKey, aadReq)
	if err != nil {
		return err
	}

	envReq := ClientEncryptedEnvelope{
		ClientId:   c.ClientId,
		Algorithm:  "AES-256-GCM",
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	bodyBytes, _ := json.Marshal(envReq)

	resp, err := c.HTTPClient.Post(sessionKeyURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w (session-key status %d: %s)", errPairingRequestGone, resp.StatusCode, string(b))
		}
		return fmt.Errorf("session-key status %d: %s", resp.StatusCode, string(b))
	}

	respBytes, _ := io.ReadAll(resp.Body)

	var sessResp SessionResponse
	var env EncryptedEnvelope
	if err := json.Unmarshal(respBytes, &env); err == nil && env.Ciphertext != "" && env.Nonce != "" {
		aadResp := fmt.Sprintf("pairingSessionResponse:%s:%s", c.ClientId, reqID)
		decrypted, decErr := decryptEnvelope(env.Nonce, env.Ciphertext, c.ClientKey, aadResp)
		if decErr == nil {
			json.Unmarshal(decrypted, &sessResp)
		} else {
			json.Unmarshal(respBytes, &sessResp)
		}
	} else {
		json.Unmarshal(respBytes, &sessResp)
	}

	c.SessionToken = sessResp.SessionToken
	c.RefreshToken = sessResp.RefreshToken
	if sessResp.SessionKey != "" {
		if sk, err := base64.RawURLEncoding.DecodeString(sessResp.SessionKey); err == nil {
			c.SessionKey = sk
		} else if sk, err := base64.StdEncoding.DecodeString(sessResp.SessionKey); err == nil {
			c.SessionKey = sk
		}
	}
	if sessResp.Policy.MaxBlockCount > 0 {
		c.MaxBlockCount = sessResp.Policy.MaxBlockCount
	}
	c.SessionExpiresAt = time.Now().Add(24 * time.Hour)
	tlog.Info.Printf("externalenc: acquired session via session-key endpoint (expires: %v)", c.SessionExpiresAt)
	return nil
}

func (c *Client) refreshSession() error {
	if c.RefreshToken == "" {
		return fmt.Errorf("no refresh token")
	}
	refReq := RefreshSessionRequest{RefreshToken: c.RefreshToken}
	bodyBytes, _ := json.Marshal(refReq)

	var reqBody []byte
	if len(c.ClientKey) > 0 {
		aad := "sessionRefreshRequest:" + c.ClientId
		nonce, ciphertext, err := encryptEnvelope(bodyBytes, c.ClientKey, aad)
		if err == nil {
			env := ClientEncryptedEnvelope{
				ClientId:   c.ClientId,
				Algorithm:  "AES-256-GCM",
				Nonce:      nonce,
				Ciphertext: ciphertext,
			}
			reqBody, _ = json.Marshal(env)
		} else {
			reqBody = bodyBytes
		}
	} else {
		reqBody = bodyBytes
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/sessions/refresh", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.SessionToken = ""
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("refresh returned status %d: %s", resp.StatusCode, string(b))
	}

	respBytes, _ := io.ReadAll(resp.Body)
	var sessResp SessionResponse

	if len(c.ClientKey) > 0 {
		var env EncryptedEnvelope
		if err := json.Unmarshal(respBytes, &env); err == nil && env.Ciphertext != "" {
			aad := "sessionRefreshResponse:" + c.ClientId
			decrypted, decErr := decryptEnvelope(env.Nonce, env.Ciphertext, c.ClientKey, aad)
			if decErr == nil {
				json.Unmarshal(decrypted, &sessResp)
			} else {
				json.Unmarshal(respBytes, &sessResp)
			}
		} else {
			json.Unmarshal(respBytes, &sessResp)
		}
	} else {
		json.Unmarshal(respBytes, &sessResp)
	}

	c.SessionToken = sessResp.SessionToken
	c.RefreshToken = sessResp.RefreshToken
	if sessResp.SessionKey != "" {
		if sk, err := base64.RawURLEncoding.DecodeString(sessResp.SessionKey); err == nil {
			c.SessionKey = sk
		} else if sk, err := base64.StdEncoding.DecodeString(sessResp.SessionKey); err == nil {
			c.SessionKey = sk
		}
	}
	if sessResp.Policy.MaxBlockCount > 0 {
		c.MaxBlockCount = sessResp.Policy.MaxBlockCount
	}

	parsedExpiry := false
	if sessResp.SessionExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, sessResp.SessionExpiresAt); err == nil {
			c.SessionExpiresAt = t
			parsedExpiry = true
		}
	}
	if !parsedExpiry {
		c.SessionExpiresAt = time.Now().Add(24 * time.Hour)
	}

	tlog.Info.Printf("externalenc: session successfully refreshed with external provider (expires: %v)", c.SessionExpiresAt.Format(time.RFC3339))
	return nil
}

func (c *Client) clearCacheLocked() {
	if c.cache != nil {
		c.cache.purge()
	}
	if c.nameCache != nil {
		c.nameCache.purge()
	}
}

func (c *Client) GetBlockAEAD(blockIndex uint64) (cipher.AEAD, error) {
	c.mu.Lock()

	// 24-hour Session Token Expiration Check
	if c.SessionToken == "" || time.Now().After(c.SessionExpiresAt) {
		tlog.Info.Printf("externalenc: 24h session token expired or missing (expires: %v). Purging key cache & refreshing session...", c.SessionExpiresAt)
		c.clearCacheLocked()
		c.mu.Unlock()

		refErr := c.refreshSession()
		if refErr != nil {
			tlog.Warn.Printf("externalenc: refreshSession failed (%v), re-initializing session...", refErr)
			if initErr := c.initSession(); initErr != nil {
				return nil, fmt.Errorf("externalenc: 24h session expired and renewal failed: %w", initErr)
			}
		}
		c.mu.Lock()
	}

	// Check LRU AEAD cache
	if aead, _, ok := c.cache.get(blockIndex); ok {
		c.mu.Unlock()
		return aead, nil
	}

	c.mu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check LRU cache
	if aead, _, ok := c.cache.get(blockIndex); ok {
		return aead, nil
	}

	keys, err := c.waitForKeys(c.KeyName, "content", blockIndex, c.MaxBlockCount)
	if err != nil {
		return nil, err
	}

	var targetAEAD cipher.AEAD
	for idx, k := range keys {
		aead, putErr := c.cache.put(idx, k)
		// Explicitly overwrite temporary key slice memory after inserting into LRU cache
		for i := range k {
			k[i] = 0
		}
		if idx == blockIndex && putErr == nil {
			targetAEAD = aead
		}
	}
	if targetAEAD != nil {
		return targetAEAD, nil
	}
	if aead, _, ok := c.cache.get(blockIndex); ok {
		return aead, nil
	}
	return nil, fmt.Errorf("externalenc: block %d not present in server response", blockIndex)
}

// waitForKeys blocks, retrying fetchBlockPasswords under keyName/startIndex/count
// while the session is expired/refreshed/re-paired, until keys become available
// or the retry budget is exhausted. This is the single retry loop behind both
// content-block keys (GetBlockAEAD) and per-directory filename keys
// (GetNameEME) — there is deliberately no other path to key material.
//
// Callers must hold c.mu.
// waitForKeys fetches keys for keyName[startIndex..startIndex+count). The one and only
// legitimate reason to wait on anything in here is a pairing approval: that happens
// inside initSession, and only when there is no valid session to use yet. Once a session
// exists, a block-passwords failure is either a one-shot "the session just died
// server-side, re-authenticate and retry once" (HTTP 401) or a terminal-for-this-call
// problem (unknown key, malformed request, card unreachable, card demands a user
// rechallenge, network failure, ...) that retrying the identical request immediately
// cannot fix. There is deliberately no multi-minute polling loop for the latter — even
// errCardRechallengeRequired, whose resolution genuinely depends on a human action, is not
// polled for here: that action happens out-of-band on the Web UI, so blocking a FUSE call
// on it would just reintroduce the un-Ctrl-C-able wait this design removed. A bad key
// name, a real server problem, or a pending rechallenge must show up immediately; the next
// access to the same key naturally retries once the underlying condition clears.
func (c *Client) waitForKeys(keyName string, kind string, startIndex uint64, count int) (map[uint64][]byte, error) {
	if c.SessionToken == "" || time.Now().After(c.SessionExpiresAt) {
		tlog.Info.Printf("externalenc: no valid session for %s[%d] (%s key) - (re-)establishing session...", keyName, startIndex, kind)
		c.LogSecure("warn", "Session required", fmt.Sprintf("(Re-)establishing session before fetching %s key %s[%d]", kind, keyName, startIndex), nil)
		if c.RefreshToken == "" || c.refreshSession() != nil {
			// Only falls back to a fresh pairing request — which needs a new
			// physical smartcard/Web UI approval, the one legitimate wait in this
			// whole flow — when refreshing an existing session isn't possible.
			if err := c.initSession(); err != nil {
				return nil, fmt.Errorf("externalenc: could not establish a session for %s[%d]: %w", keyName, startIndex, err)
			}
		}
	}

	keys, err := c.fetchBlockPasswords(keyName, kind, startIndex, count)
	if err != nil && errors.Is(err, errSessionInvalid) {
		// The session we thought was valid just got rejected server-side (revoked,
		// expired early, etc). Re-authenticate exactly once and retry exactly once —
		// still "waiting for approval" in spirit if a fresh pairing is needed, not a
		// key problem, so it's exempt from the fail-fast rule above.
		tlog.Info.Printf("externalenc: session rejected fetching %s[%d] (%s key): %v. Re-authenticating once...", keyName, startIndex, kind, err)
		c.LogSecure("warn", "Session rejected by server", fmt.Sprintf("Re-authenticating once for %s[%d] (%s key): %v", keyName, startIndex, kind, err), nil)
		if c.RefreshToken == "" || c.refreshSession() != nil {
			if initErr := c.initSession(); initErr != nil {
				return nil, fmt.Errorf("externalenc: could not re-establish a session for %s[%d]: %w", keyName, startIndex, initErr)
			}
		}
		keys, err = c.fetchBlockPasswords(keyName, kind, startIndex, count)
	}

	if err != nil {
		tlog.Info.Printf("externalenc: key access failed for %s[%d] (%s key): %v", keyName, startIndex, kind, err)
		c.LogSecure("error", "Key access failed", fmt.Sprintf("%s[%d] (%s key): %v", keyName, startIndex, kind, err), nil)
		return nil, fmt.Errorf("externalenc: key access failed for %s[%d]: %w", keyName, startIndex, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("externalenc: key server returned no keys for %s[%d]", keyName, startIndex)
	}
	return keys, nil
}

// nameKeyIndex derives the block-passwords index for a directory (or the
// fixed xattr IV) from its own IV. Directory IVs are already random,
// per-directory, and unique within the vault (see nametransform.DirIVLen),
// so reusing them directly as the index needs no separate allocation scheme
// and can never collide across directories. This is also what actually
// separates name-key requests from content-key requests on the wire — both
// use the same plain registered keyName (see GetNameEME) — since content
// block indices are small sequential offsets and directory IVs are
// effectively random 63-bit values, collision between the two index spaces
// is not a practical concern.
func nameKeyIndex(dirIV []byte) (uint64, error) {
	if len(dirIV) < 8 {
		return 0, fmt.Errorf("externalenc: directory IV too short (%d bytes)", len(dirIV))
	}
	// BlockPasswordPayload.BlockIndex is a signed int64 (matching the API
	// spec), and round-trips through a string-keyed JSON map on the way
	// back — a value with the top bit set would serialize as a negative
	// decimal string that ParseUint (used for content block indices) then
	// silently rejects. Clear the sign bit so the index is always a valid
	// non-negative int64; 63 bits of the directory IV is still far more
	// than enough to make collisions between directories impossible.
	return binary.BigEndian.Uint64(dirIV[:8]) &^ (uint64(1) << 63), nil
}

// GetNameEME returns the EME cipher used to encrypt/decrypt filenames within
// the directory identified by dirIV. There is no filesystem-wide filename
// key: every directory gets its own key, fetched from the external provider
// exactly like content-block keys, and cached here.
func (c *Client) GetNameEME(dirIV []byte) (*eme.EMECipher, error) {
	idx, err := nameKeyIndex(dirIV)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()

	if e, ok := c.nameCache.get(idx); ok {
		c.mu.Unlock()
		return e, nil
	}

	// 24-hour Session Token Expiration Check (mirrors GetBlockAEAD)
	if c.SessionToken == "" || time.Now().After(c.SessionExpiresAt) {
		tlog.Info.Printf("externalenc: 24h session token expired or missing (expires: %v). Purging key cache & refreshing session...", c.SessionExpiresAt)
		c.clearCacheLocked()
		c.mu.Unlock()

		refErr := c.refreshSession()
		if refErr != nil {
			tlog.Warn.Printf("externalenc: refreshSession failed (%v), re-initializing session...", refErr)
			if initErr := c.initSession(); initErr != nil {
				return nil, fmt.Errorf("externalenc: 24h session expired and renewal failed: %w", initErr)
			}
		}
		c.mu.Lock()
	}

	defer c.mu.Unlock()

	// Double check cache
	if e, ok := c.nameCache.get(idx); ok {
		return e, nil
	}

	// keyName sent to the server is the plain registered key (e.g. "key1"), never a
	// derived/namespaced string — the server has never heard of "key1:names" and would
	// have no reason to treat it as valid. blockIndex (idx, derived from the directory's
	// own IV below) is what actually distinguishes this request from a content-block
	// fetch on the wire; "name" here is purely a local label for logging/stats.
	keys, err := c.waitForKeys(c.KeyName, "name", idx, 1)
	if err != nil {
		return nil, err
	}
	key, ok := keys[idx]
	if !ok {
		return nil, fmt.Errorf("externalenc: server did not return a filename key for index %d", idx)
	}
	emeCipher, putErr := c.nameCache.put(idx, key)
	// Explicitly overwrite temporary key slice memory after inserting into LRU cache
	for i := range key {
		key[i] = 0
	}
	if putErr != nil {
		return nil, putErr
	}
	return emeCipher, nil
}

// GetBlockKey retrieves a 32-byte AES key for a specific block index from the external provider.
func (c *Client) GetBlockKey(blockIndex uint64) ([]byte, error) {
	c.mu.Lock()
	if _, key, ok := c.cache.get(blockIndex); ok {
		c.mu.Unlock()
		return key, nil
	}
	c.mu.Unlock()

	aead, err := c.GetBlockAEAD(blockIndex)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, key, ok := c.cache.get(blockIndex); ok {
		return key, nil
	}
	_ = aead
	return nil, fmt.Errorf("key not found in cache")
}

// Round-trip instrumentation for /api/v1/block-passwords, opt-in via
// EXTERNALENC_STATS_FILE. Off by default (statsLogFile stays nil, statsLog
// is then a no-op) since it's diagnostic-only and every call already pays
// for a network round trip anyway, but it's the only way to see how many
// key-server calls (and how much time in them) a given run actually made —
// tlog output alone doesn't tell you that once gocryptfs has daemonized,
// since redirectStdFds (daemonize.go) sends stdout/stderr to syslog at that
// point, which an unprivileged 115fs user typically can't read back.
var (
	statsLogOnce sync.Once
	statsLogFile *os.File
	statsLogMu   sync.Mutex
)

func statsLogInit() {
	path := os.Getenv("EXTERNALENC_STATS_FILE")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		tlog.Warn.Printf("externalenc: EXTERNALENC_STATS_FILE=%s: %v (stats disabled)", path, err)
		return
	}
	statsLogFile = f
}

func statsLog(keyName string, kind string, startIndex uint64, count int, dur time.Duration, err error) {
	statsLogOnce.Do(statsLogInit)
	if statsLogFile == nil {
		return
	}
	status := "ok"
	if err != nil {
		status = "err"
	}
	line := fmt.Sprintf("ts=%d type=%s keyName=%s startIndex=%d count=%d duration_ms=%.3f status=%s\n",
		time.Now().UnixNano(), kind, keyName, startIndex, count, float64(dur.Microseconds())/1000.0, status)
	statsLogMu.Lock()
	statsLogFile.WriteString(line)
	statsLogMu.Unlock()
}

func (c *Client) fetchBlockPasswords(keyName string, kind string, startIndex uint64, count int) (keys map[uint64][]byte, err error) {
	start := time.Now()
	defer func() {
		statsLog(keyName, kind, startIndex, count, time.Since(start), err)
	}()

	// kind ("content" or "name") doubles as the API's required usage prefix: it's a
	// stable, non-empty, <=64-char label the card can key its per-key usage-pattern
	// tracking on. This package has no finer-grained path/inode context available at
	// this layer (GetBlockAEAD/GetNameEME only ever see a block index or directory IV),
	// so kind is the most meaningful namespace it can honestly report.
	payload := BlockPasswordPayload{
		KeyName:    keyName,
		Prefix:     kind,
		BlockIndex: int64(startIndex),
		BlockCount: count,
		Purpose:    "gocryptfs",
	}
	bodyBytes, _ := json.Marshal(payload)

	var reqBody []byte
	if len(c.SessionKey) > 0 {
		aad := "blockPasswordsRequest:" + c.SessionToken
		nonce, ciphertext, err := encryptEnvelope(bodyBytes, c.SessionKey, aad)
		if err == nil {
			bpReq := BlockPasswordRequest{
				ClientNonce:      nonce,
				EncryptedPayload: ciphertext,
			}
			reqBody, _ = json.Marshal(bpReq)
		} else {
			reqBody = bodyBytes
		}
	} else {
		bpReq := BlockPasswordRequest{
			KeyName:    keyName,
			Prefix:     kind,
			BlockIndex: int64(startIndex),
			BlockCount: count,
			Purpose:    "gocryptfs",
		}
		reqBody, _ = json.Marshal(bpReq)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/block-passwords", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.SessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusNotImplemented {
			return nil, fmt.Errorf("%w (status %d: %s)", errKeyAccessUnsupported, resp.StatusCode, string(b))
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("%w (status %d: %s)", errSessionInvalid, resp.StatusCode, string(b))
		}
		if resp.StatusCode == http.StatusLocked { // 423 cardUsageRechallengeRequired
			return nil, fmt.Errorf("%w (status %d: %s)", errCardRechallengeRequired, resp.StatusCode, string(b))
		}
		if resp.StatusCode == http.StatusFailedDependency { // 424 card unreachable
			return nil, fmt.Errorf("%w (status %d: %s)", errCardUnavailable, resp.StatusCode, string(b))
		}
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var bpResp BlockPasswordResponse
	if len(c.SessionKey) > 0 {
		var env EncryptedEnvelope
		if err := json.Unmarshal(respBytes, &env); err == nil && env.Ciphertext != "" {
			aad := "blockPasswordsResponse:" + c.SessionToken
			decrypted, decErr := decryptEnvelope(env.Nonce, env.Ciphertext, c.SessionKey, aad)
			if decErr == nil {
				json.Unmarshal(decrypted, &bpResp)
			} else {
				json.Unmarshal(respBytes, &bpResp)
			}
		} else {
			json.Unmarshal(respBytes, &bpResp)
		}
	} else {
		json.Unmarshal(respBytes, &bpResp)
	}

	if bpResp.ErrorCode != "" {
		return nil, fmt.Errorf("api error %s: %s", bpResp.ErrorCode, bpResp.Message)
	}

	material := bpResp.KeyMaterial
	if len(material) == 0 {
		material = bpResp.Passwords // deprecated compatibility alias
	}
	if len(material) == 0 {
		return nil, fmt.Errorf("empty key material response")
	}

	res := make(map[uint64][]byte)
	for idxStr, pw := range material {
		idx, err := strconv.ParseUint(idxStr, 10, 64)
		if err != nil {
			continue
		}
		pwBytes := []byte(pw)
		keyHash := sha256.Sum256(pwBytes)
		// Zero out raw password string bytes
		for i := range pwBytes {
			pwBytes[i] = 0
		}
		res[idx] = keyHash[:]
	}

	return res, nil
}

// ExternalAEAD implements cipher.AEAD using per-block keys from Client
type ExternalAEAD struct {
	client *Client
}

func NewExternalAEAD(client *Client) *ExternalAEAD {
	return &ExternalAEAD{client: client}
}

func (e *ExternalAEAD) NonceSize() int {
	return 16
}

func (e *ExternalAEAD) Overhead() int {
	return cryptocore.AuthTagLen
}

func (e *ExternalAEAD) extractBlockIndex(additionalData []byte) uint64 {
	if len(additionalData) >= 8 {
		return binary.BigEndian.Uint64(additionalData[:8])
	}
	return 0
}

func (e *ExternalAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	blockIdx := e.extractBlockIndex(additionalData)
	aead, err := e.client.GetBlockAEAD(blockIdx)
	if err != nil {
		// cipher.AEAD.Seal has no error return, so there is no clean way to signal this
		// failure through the interface — returning nil here previously produced a
		// confusing downstream crash ("unexpected ciphertext length") deep in unrelated
		// content-encryption code. Panicking directly, like the stdlib GCM implementation
		// does for its own unrecoverable Seal errors, at least makes the real cause (a
		// key-server failure) the first thing in the crash log instead of the last.
		tlog.Fatal.Printf("externalenc: cannot seal block %d, key retrieval from external provider failed: %v", blockIdx, err)
		panic(fmt.Sprintf("externalenc: Seal key retrieval failed for block %d: %v", blockIdx, err))
	}
	return aead.Seal(dst, nonce, plaintext, additionalData)
}

func (e *ExternalAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	blockIdx := e.extractBlockIndex(additionalData)
	aead, err := e.client.GetBlockAEAD(blockIdx)
	if err != nil {
		return nil, err
	}
	return aead.Open(dst, nonce, ciphertext, additionalData)
}

func (e *ExternalAEAD) Wipe() {
	if e.client != nil {
		if e.client.stopHeartbeat != nil {
			e.client.stopOnce.Do(func() { close(e.client.stopHeartbeat) })
		}
		e.client.mu.Lock()
		defer e.client.mu.Unlock()
		e.client.clearCacheLocked()
		if e.client.ClientKey != nil {
			for i := range e.client.ClientKey {
				e.client.ClientKey[i] = 0
			}
		}
		if e.client.SessionKey != nil {
			for i := range e.client.SessionKey {
				e.client.SessionKey[i] = 0
			}
		}
		e.client.SessionToken = ""
		e.client.RefreshToken = ""
	}
}

// ExternalEME implements nametransform.EMEProvider using per-directory keys
// from Client.GetNameEME. There is no filesystem-wide filename key, mirroring
// ExternalAEAD's per-block content keys — Wipe() on ExternalAEAD already
// purges the shared client's nameCache too, so filename key material doesn't
// need its own Wipe path.
type ExternalEME struct {
	client *Client
}

func NewExternalEME(client *Client) *ExternalEME {
	return &ExternalEME{client: client}
}

func (e *ExternalEME) Get(dirIV []byte) (*eme.EMECipher, error) {
	return e.client.GetNameEME(dirIV)
}
