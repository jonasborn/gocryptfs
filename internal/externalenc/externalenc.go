package externalenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/carter/blobmeta"
	"github.com/rfjakob/gocryptfs/v2/carter/cardclient"
	"github.com/rfjakob/gocryptfs/v2/carter/ksclient"
	"github.com/rfjakob/gocryptfs/v2/carter/proto"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"github.com/rfjakob/gocryptfs/v2/pinning"
)

const (
	DefaultServerURL = "https://192.168.2.223:9443"
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

// Client is a first-class card client (CON-3): it holds one FS transport
// identity (authenticates it to the KS) and one FS card identity
// (authenticates it to 115cos through the KS's opaque relay), and derives
// content/filename block keys directly from the card. The KS never sees a
// derived key.
type Client struct {
	BaseURL string
	// LessSecureBaseURL is the untrusted HTTP bootstrap listener's base URL,
	// used only for the pre-trust diagnostics documented on sendLog (TLS
	// trust issue reports, startup and heartbeat pings) — never for
	// anything that unlocks or fetches key material. Empty means "derive it
	// from BaseURL" (see untrustedBaseURL).
	LessSecureBaseURL string
	CertFingerprint   string

	// KeyID is the one-byte card key id DERIVE_BLOCK_KEY(S) targets for this
	// mount. UsagePrefix is sent with every derive request so the card can
	// learn/enforce per-key usage patterns (a path, namespace, or similar
	// stable label — see CON-2's BlockPasswordPayload.Prefix, which this
	// mirrors on the new CE-tunnel wire format).
	KeyID       byte
	UsagePrefix []byte

	MaxBlockCount int

	ks   *ksclient.Client
	card *cardclient.Client

	session *proto.CardSession

	cache     *smartAEADCache
	nameCache *smartEMECache
	mu        sync.RWMutex

	// indexKey caches K_index (CON-3.1) for the life of the card session:
	// the key behind BlobID and MetaKeyIndex. Cleared by clearCacheLocked
	// whenever the session is torn down.
	indexKey []byte

	lastServerCert  []byte
	lastCertHashHex string

	// stopHeartbeat, closed exactly once (via stopOnce) by ExternalAEAD.Wipe,
	// signals the background goroutine started in NewClient (see
	// startHeartbeat in clientmessages.go) to stop sending "still alive"
	// messages.
	stopHeartbeat chan struct{}
	stopOnce      sync.Once
}

// Options configures NewClient. TransportClientKey and CardClientSecret are
// each exactly 32 bytes and are never logged; the caller (115fs's own
// -fs-identity-from-config resolution, see symkey_config.go) is responsible
// for never putting either on this process's command line.
type Options struct {
	BaseURL           string
	LessSecureBaseURL string
	CertFingerprint   string
	KeyID             byte
	UsagePrefix       []byte
	MaxBlockCount     int

	TransportClientID  string
	TransportClientKey []byte

	CardInstanceID   string
	CardClientID     string
	CardClientSecret []byte
}

// NewClient initializes a new Client: verifies (and, if needed,
// interactively pins — see AGENTS.md's hard rule against any TLS bypass) the
// KS's TLS certificate, opens a transport session, and establishes a Card
// Envelope session with 115cos through the KS's opaque relay — a real
// end-to-end handshake with the live card, not a fabricated/cached one.
func NewClient(opts Options) (*Client, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultServerURL
	}
	if opts.MaxBlockCount <= 0 {
		opts.MaxBlockCount = DefaultBlockSize
	}
	if len(opts.TransportClientKey) != 32 {
		return nil, fmt.Errorf("externalenc: transport client key must be 32 bytes, got %d", len(opts.TransportClientKey))
	}
	if len(opts.CardClientSecret) != 32 {
		return nil, fmt.Errorf("externalenc: card client secret must be 32 bytes, got %d", len(opts.CardClientSecret))
	}

	c := &Client{
		BaseURL:           opts.BaseURL,
		LessSecureBaseURL: opts.LessSecureBaseURL,
		CertFingerprint:   opts.CertFingerprint,
		KeyID:             opts.KeyID,
		UsagePrefix:       opts.UsagePrefix,
		MaxBlockCount:     opts.MaxBlockCount,
		cache:             newSmartAEADCache(4096),
		nameCache:         newSmartEMECache(2048),
	}

	// "I've started, what's up" — sent once, here, before TLS trust is
	// established. establishSession (below) can be re-invoked later on
	// session breakage; that's not a fresh client start, so it deliberately
	// does not repeat this message.
	c.reportStarted()

	// Mandatory TLS certificate verification BEFORE any trusted-channel
	// HTTP request (including /api/v1/fs/health).
	if err := c.probeAndVerifyTLSCertificate(); err != nil {
		return nil, fmt.Errorf("externalenc: TLS certificate verification failed: %w", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Inspected manually via VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no server certificate presented")
			}
			fingerprint := pinning.Fingerprint(rawCerts[0])
			if c.CertFingerprint != "" && !pinning.Matches(c.CertFingerprint, fingerprint) {
				return fmt.Errorf("TLS certificate fingerprint mismatch")
			}
			return nil
		},
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	c.ks = ksclient.New(opts.BaseURL, httpClient)
	c.card = cardclient.New(c.ks, opts.TransportClientID, opts.TransportClientKey,
		opts.CardInstanceID, opts.CardClientID, opts.CardClientSecret)

	if err := c.establishSession(); err != nil {
		return nil, fmt.Errorf("externalenc: establishing FS card session: %w", err)
	}

	c.stopHeartbeat = make(chan struct{})
	go c.startHeartbeat(c.stopHeartbeat)

	return c, nil
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
		// server enough to report the problem over the trusted HTTPS channel —
		// send it over the untrusted bootstrap listener instead.
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

// establishSession opens a transport session and a Card Envelope session
// with 115cos through the KS's opaque relay. Unlike the old pairing/session
// flow this replaces, there is no waiting for out-of-band human approval
// here — the transport and card identities are provisioned in advance
// (ADMIN-side, see AGENTS.md/CON-3), so this either succeeds immediately or
// fails outright (wrong/unprovisioned identity, card or KS unreachable).
func (c *Client) establishSession() error {
	session, err := c.card.EstablishSession()
	if err != nil {
		return err
	}
	c.session = session
	return nil
}

// errSessionInvalid means the card/transport session broke (the KS rejected
// the transport envelope, or the card session no longer validates) — the
// caller should re-establish once and retry, exactly once, before giving up.
var errSessionInvalid = errors.New("FS card session invalid")

func (c *Client) clearCacheLocked() {
	if c.cache != nil {
		c.cache.purge()
	}
	if c.nameCache != nil {
		c.nameCache.purge()
	}
	for i := range c.indexKey {
		c.indexKey[i] = 0
	}
	c.indexKey = nil
}

func (c *Client) GetBlockAEAD(blockIndex uint64) (cipher.AEAD, error) {
	c.mu.Lock()

	if c.session == nil {
		tlog.Info.Printf("externalenc: no FS card session. Purging key cache & establishing session...")
		c.clearCacheLocked()
		c.mu.Unlock()
		if err := c.establishSession(); err != nil {
			return nil, fmt.Errorf("externalenc: establishing FS card session: %w", err)
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

	keys, err := c.waitForKeys(blockIndex, c.MaxBlockCount)
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
	return nil, fmt.Errorf("externalenc: block %d not present in card response", blockIndex)
}

// waitForKeys fetches content-block keys for startIndex..startIndex+count),
// retrying exactly once (re-establishing the card session) if the session
// turned out to be broken. There is no multi-minute polling loop — the card
// has no rechallenge/approval state to wait on in the CE-tunnel model (see
// CarterApplet's DERIVE_BLOCK_KEY(S): pure deterministic KDF, no usage
// policy gate today); a bad key id, a real server/card problem, or a network
// failure must show up immediately.
//
// Callers must hold c.mu.
func (c *Client) waitForKeys(startIndex uint64, count int) (map[uint64][]byte, error) {
	if c.session == nil {
		tlog.Info.Printf("externalenc: no FS card session for block %d - establishing session...", startIndex)
		c.LogSecure("warn", "Session required", fmt.Sprintf("Establishing FS card session before fetching block %d", startIndex), nil)
		if err := c.establishSession(); err != nil {
			return nil, fmt.Errorf("externalenc: could not establish a session for block %d: %w", startIndex, err)
		}
	}

	keys, err := c.fetchBlockKeys(startIndex, count)
	if err != nil && errors.Is(err, errSessionInvalid) {
		tlog.Info.Printf("externalenc: session invalid fetching block %d: %v. Re-establishing once...", startIndex, err)
		c.LogSecure("warn", "FS card session invalid", fmt.Sprintf("Re-establishing once for block %d: %v", startIndex, err), nil)
		if reestErr := c.establishSession(); reestErr != nil {
			return nil, fmt.Errorf("externalenc: could not re-establish a session for block %d: %w", startIndex, reestErr)
		}
		keys, err = c.fetchBlockKeys(startIndex, count)
	}

	if err != nil {
		tlog.Info.Printf("externalenc: key access failed for block %d: %v", startIndex, err)
		c.LogSecure("error", "Key access failed", fmt.Sprintf("block %d: %v", startIndex, err), nil)
		return nil, fmt.Errorf("externalenc: key access failed for block %d: %w", startIndex, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("externalenc: card returned no keys for block %d", startIndex)
	}
	return keys, nil
}

// nameKeyIndex derives the block-key index for a directory (or the fixed
// xattr IV) from its own IV. Directory IVs are already random, per-directory,
// and unique within the vault (see nametransform.DirIVLen), so reusing them
// directly as the index needs no separate allocation scheme and can never
// collide across directories. Content block indices are small sequential
// offsets and directory IVs are effectively random 63-bit values, so
// collision between the two index spaces is not a practical concern.
func nameKeyIndex(dirIV []byte) (uint64, error) {
	if len(dirIV) < 8 {
		return 0, fmt.Errorf("externalenc: directory IV too short (%d bytes)", len(dirIV))
	}
	// Clear the sign bit so the index round-trips cleanly through anything
	// that might treat it as signed — 63 bits of the directory IV is still
	// far more than enough to make collisions between directories impossible.
	return binary.BigEndian.Uint64(dirIV[:8]) &^ (uint64(1) << 63), nil
}

// GetNameEME returns the EME cipher used to encrypt/decrypt filenames within
// the directory identified by dirIV. There is no filesystem-wide filename
// key: every directory gets its own key, derived from the card exactly like
// content-block keys, and cached here.
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

	if c.session == nil {
		tlog.Info.Printf("externalenc: no FS card session. Purging key cache & establishing session...")
		c.clearCacheLocked()
		c.mu.Unlock()
		if err := c.establishSession(); err != nil {
			return nil, fmt.Errorf("externalenc: establishing FS card session: %w", err)
		}
		c.mu.Lock()
	}

	defer c.mu.Unlock()

	// Double check cache
	if e, ok := c.nameCache.get(idx); ok {
		return e, nil
	}

	keys, err := c.waitForKeys(idx, 1)
	if err != nil {
		return nil, err
	}
	key, ok := keys[idx]
	if !ok {
		return nil, fmt.Errorf("externalenc: card did not return a filename key for index %d", idx)
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

// GetBlockKey retrieves a 32-byte AES key for a specific block index from the card.
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

// deriveKeyCached fetches a single 32-byte key for an arbitrary card block
// index (used for the CON-3.1 reserved / per-file metadata indices, which
// live far above the content-block range). It reuses the content-key LRU
// cache so repeat lookups for the same index are free, and never prefetches
// a batch.
func (c *Client) deriveKeyCached(index uint64) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, key, ok := c.cache.get(index); ok {
		return key, nil
	}
	if c.session == nil {
		if err := c.establishSession(); err != nil {
			return nil, fmt.Errorf("externalenc: establishing FS card session: %w", err)
		}
	}
	keys, err := c.waitForKeys(index, 1)
	if err != nil {
		return nil, err
	}
	k, ok := keys[index]
	if !ok {
		return nil, fmt.Errorf("externalenc: card returned no key for index %#016x", index)
	}
	out := append([]byte(nil), k...)
	if _, putErr := c.cache.put(index, k); putErr != nil {
		// AES key that will not build a cipher — surface it rather than
		// silently returning an unusable key.
		return nil, putErr
	}
	for i := range k {
		k[i] = 0
	}
	return out, nil
}

// IndexKey returns K_index (CON-3.1): the card-derived key behind the blob
// id (HMAC) and the per-file metadata key index. Stable for the life of the
// card session; cached on the client.
func (c *Client) IndexKey() ([]byte, error) {
	c.mu.RLock()
	if c.indexKey != nil {
		k := append([]byte(nil), c.indexKey...)
		c.mu.RUnlock()
		return k, nil
	}
	c.mu.RUnlock()

	k, err := c.deriveKeyCached(blobmeta.IdxBlobIDKey)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.indexKey == nil {
		c.indexKey = append([]byte(nil), k...)
	}
	c.mu.Unlock()
	return k, nil
}

// MetaKey returns K_meta for a file UUID: the AEAD key that seals that
// file's info-chunk (CON-3.1).
func (c *Client) MetaKey(uuid [16]byte) ([]byte, error) {
	ik, err := c.IndexKey()
	if err != nil {
		return nil, err
	}
	return c.deriveKeyCached(blobmeta.MetaKeyIndex(ik, uuid))
}

// IndexCacheKey returns K_idx: the card-derived key that seals
// cipher_dir/idx/tree (CON-3.1).
func (c *Client) IndexCacheKey() ([]byte, error) {
	return c.deriveKeyCached(blobmeta.IdxIndexCacheKey)
}

// Round-trip instrumentation for DERIVE_BLOCK_KEY(S), opt-in via
// EXTERNALENC_STATS_FILE. Off by default (statsLogFile stays nil, statsLog is
// then a no-op) since it's diagnostic-only and every call already pays for a
// card-relay round trip anyway, but it's the only way to see how many
// card-relay calls (and how much time in them) a given run actually made —
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

func statsLog(startIndex uint64, count int, dur time.Duration, err error) {
	statsLogOnce.Do(statsLogInit)
	if statsLogFile == nil {
		return
	}
	status := "ok"
	if err != nil {
		status = "err"
	}
	line := fmt.Sprintf("ts=%d startIndex=%d count=%d duration_ms=%.3f status=%s\n",
		time.Now().UnixNano(), startIndex, count, float64(dur.Microseconds())/1000.0, status)
	statsLogMu.Lock()
	statsLogFile.WriteString(line)
	statsLogMu.Unlock()
}

// fetchBlockKeys derives count consecutive block keys starting at startIndex
// through the FS card client, batching DERIVE_BLOCK_KEYS calls of up to
// proto.MaxBlockKeyBatch (a hard card-side limit) to fill the caller's
// requested count — GetBlockAEAD asks for c.MaxBlockCount (default 64) keys
// at once, well above the per-request card limit, so this issues however
// many relay round trips are needed to cover the whole range.
// keyBatch is one DERIVE_BLOCK_KEYS relay round trip's worth of work.
type keyBatch struct {
	start uint64
	count int
}

// planKeyBatches splits [startIndex, startIndex+count) into consecutive
// batches of at most proto.MaxBlockKeyBatch — the card's hard per-request
// limit — so a single GetBlockAEAD prefetch (typically c.MaxBlockCount keys,
// default 64) turns into however many DERIVE_BLOCK_KEYS relay round trips are
// actually needed to cover the whole range. Pure and side-effect-free so the
// batching arithmetic can be tested without a live card/KS.
func planKeyBatches(startIndex uint64, count int) []keyBatch {
	if count <= 0 {
		return nil
	}
	batches := make([]keyBatch, 0, (count+proto.MaxBlockKeyBatch-1)/proto.MaxBlockKeyBatch)
	remaining := count
	idx := startIndex
	for remaining > 0 {
		batch := remaining
		if batch > proto.MaxBlockKeyBatch {
			batch = proto.MaxBlockKeyBatch
		}
		batches = append(batches, keyBatch{start: idx, count: batch})
		idx += uint64(batch)
		remaining -= batch
	}
	return batches
}

func (c *Client) fetchBlockKeys(startIndex uint64, count int) (keys map[uint64][]byte, err error) {
	start := time.Now()
	defer func() {
		statsLog(startIndex, count, time.Since(start), err)
	}()

	if c.session == nil {
		return nil, errSessionInvalid
	}

	keys = make(map[uint64][]byte, count)
	for _, b := range planKeyBatches(startIndex, count) {
		derived, derr := c.card.DeriveBlockKeys(c.session, c.KeyID, b.start, b.count, c.UsagePrefix)
		if derr != nil {
			return nil, fmt.Errorf("%w: %v", errSessionInvalid, derr)
		}
		for i, k := range derived {
			keys[b.start+uint64(i)] = k
		}
	}
	return keys, nil
}

// keyIDHex renders a one-byte card key id as two uppercase hex digits, for
// diagnostics/logging only.
func keyIDHex(id byte) string {
	return hex.EncodeToString([]byte{id})
}

// ExternalAEAD implements cipher.AEAD backed by per-block keys fetched from
// Client. NonceSize/Overhead match gocryptfs's own external-mode content
// format (16-byte nonce, cryptocore.AuthTagLen tag) regardless of which block
// key is in use.
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
		// card/key-server failure) the first thing in the crash log instead of the last.
		tlog.Fatal.Printf("externalenc: cannot seal block %d, key derivation from card failed: %v", blockIdx, err)
		panic(fmt.Sprintf("externalenc: Seal key derivation failed for block %d: %v", blockIdx, err))
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
		if e.client.card != nil {
			e.client.card.Close() // best-effort; a failed/unreachable KS at unmount time isn't fatal
		}
		e.client.mu.Lock()
		defer e.client.mu.Unlock()
		e.client.clearCacheLocked()
		if s := e.client.session; s != nil {
			zero := func(b []byte) {
				for i := range b {
					b[i] = 0
				}
			}
			zero(s.RequestEncKey)
			zero(s.RequestMacKey)
			zero(s.ResponseEncKey)
			zero(s.ResponseMacKey)
			e.client.session = nil
		}
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
