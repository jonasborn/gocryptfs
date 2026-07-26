package externalenc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// newMockKeyserverHandler builds a handler that speaks the real encrypted
// pairing-request -> session-key -> block-passwords flow (the only flow 115fs is
// allowed to use per the API spec — /card-challenge and /approve are trusted-browser
// endpoints and deliberately return 404 here, matching an unregistered-browser server).
func newMockKeyserverHandler(clientId string, clientKey, sessionKey []byte, reqID, sessionToken string) http.HandlerFunc {
	sessionKeyB64 := base64.RawURLEncoding.EncodeToString(sessionKey)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok", ServiceName: "mockCarter", HTTPSRequired: false})
		case r.URL.Path == "/api/v1/pairing-requests":
			pairResp := CreatePairingResponse{
				PairingRequestId: reqID,
				ClientId:         clientId,
				PairingCode:      "111 222",
				ExpiresAt:        "2030-01-01T00:00:00Z",
			}
			body, _ := json.Marshal(pairResp)
			nonce, ciphertext, err := encryptEnvelope(body, clientKey, "pairingResponse:"+clientId)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/pairing-requests/"+reqID+"/session-key":
			sessResp := SessionResponse{
				SessionToken: sessionToken,
				RefreshToken: "mock-refresh-token",
				SessionKey:   sessionKeyB64,
				Policy:       SessionPolicy{MaxBlockCount: 32},
			}
			body, _ := json.Marshal(sessResp)
			aad := fmt.Sprintf("pairingSessionResponse:%s:%s", clientId, reqID)
			nonce, ciphertext, err := encryptEnvelope(body, clientKey, aad)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/block-passwords":
			if r.Header.Get("Authorization") != "Bearer "+sessionToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var req BlockPasswordRequest
			json.NewDecoder(r.Body).Decode(&req)
			decrypted, err := decryptEnvelope(req.ClientNonce, req.EncryptedPayload, sessionKey, "blockPasswordsRequest:"+sessionToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var payload BlockPasswordPayload
			json.Unmarshal(decrypted, &payload)
			if payload.Prefix == "" {
				http.Error(w, "missing required prefix", http.StatusBadRequest)
				return
			}

			pws := make(map[string]string)
			for i := int64(0); i < int64(payload.BlockCount); i++ {
				idx := payload.BlockIndex + i
				pws[strconv.FormatInt(idx, 10)] = "secret-pass-" + strconv.FormatInt(idx, 10)
			}
			respBytes, _ := json.Marshal(BlockPasswordResponse{
				KeyName:     payload.KeyName,
				Prefix:      payload.Prefix,
				BlockIndex:  payload.BlockIndex,
				BlockCount:  payload.BlockCount,
				KeyMaterial: pws,
			})
			nonce, ciphertext, err := encryptEnvelope(respBytes, sessionKey, "blockPasswordsResponse:"+sessionToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		default:
			// Includes /card-challenge and /approve: this mock simulates a server with
			// no trusted browser registered, same as what 115fs must tolerate in practice.
			http.NotFound(w, r)
		}
	})
}

func TestExternalenc_MockServer(t *testing.T) {
	clientId := "mock-worker"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	ts := httptest.NewServer(newMockKeyserverHandler(clientId, clientKey, sessionKey, "req-123", "mock-session-token"))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient mock server failed: %v", err)
	}

	if client.SessionToken != "mock-session-token" {
		t.Fatalf("expected sessionToken mock-session-token, got %s", client.SessionToken)
	}

	key0, err := client.GetBlockKey(0)
	if err != nil || len(key0) != 32 {
		t.Fatalf("GetBlockKey(0) failed: %v, len=%d", err, len(key0))
	}

	key1, err := client.GetBlockKey(1)
	if err != nil || len(key1) != 32 {
		t.Fatalf("GetBlockKey(1) failed: %v, len=%d", err, len(key1))
	}

	if bytes.Equal(key0, key1) {
		t.Fatalf("key0 and key1 should be different for different block indices")
	}

	// Test AEAD Seal and Open using mock keyserver
	aead := NewExternalAEAD(client)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("Hello, strict external provider encryption!")
	ad := []byte{0, 0, 0, 0, 0, 0, 0, 42, 1, 2, 3, 4}

	ciphertext := aead.Seal(nil, nonce, plaintext, ad)
	decrypted, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		t.Fatalf("AEAD Open failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("AEAD Open decrypted mismatch")
	}
}

// TestExternalenc_TLSFingerprintPinnedOnce proves that a fingerprint supplied up front
// (the -tls-hash flag's plumbing) is verified against the live connection and, on match,
// never reaches the interactive prompt. If the pinning were ignored, this test would hang
// reading from os.Stdin instead of completing.
func TestExternalenc_TLSFingerprintPinnedOnce(t *testing.T) {
	clientId := "mock-worker-tls"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	ts := httptest.NewTLSServer(newMockKeyserverHandler(clientId, clientKey, sessionKey, "req-tls", "tls-session-token"))
	defer ts.Close()

	fp := sha256.Sum256(ts.Certificate().Raw)
	certHash := hex.EncodeToString(fp[:])

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, certHash, "", nil)
	if err != nil {
		t.Fatalf("NewClient with pre-verified TLS fingerprint failed: %v", err)
	}
	if client.SessionToken != "tls-session-token" {
		t.Fatalf("expected tls-session-token, got %s", client.SessionToken)
	}
	if client.CertFingerprint != certHash {
		t.Fatalf("expected pinned fingerprint %s, got %s", certHash, client.CertFingerprint)
	}
}

// TestExternalenc_PairingRequestGoneFailsFast proves that once the server reports a
// pairing request as gone (HTTP 404 / errorCode "pairingRequestNotFound" — what it
// returns once a request has expired or been denied), 115fs stops polling immediately
// instead of retrying for up to ~30 minutes (waitForApprovedSession's normal timeout).
// Before the fix, a 404 was treated exactly like the routine 202 "still pending"
// response, so a pairing request that will never be approved could hang the caller for
// the full timeout instead of failing fast with a clear reason.
func TestExternalenc_PairingRequestGoneFailsFast(t *testing.T) {
	clientId := "mock-worker-gone"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	reqID := "req-gone"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok", ServiceName: "mockCarter", HTTPSRequired: false})
		case r.URL.Path == "/api/v1/pairing-requests":
			pairResp := CreatePairingResponse{
				PairingRequestId: reqID,
				ClientId:         clientId,
				PairingCode:      "111 222",
				ExpiresAt:        "2030-01-01T00:00:00Z",
			}
			body, _ := json.Marshal(pairResp)
			nonce, ciphertext, err := encryptEnvelope(body, clientKey, "pairingResponse:"+clientId)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/pairing-requests/"+reqID+"/session-key":
			// Simulates the request having expired or been denied server-side: the
			// server no longer has any record of it, and never will again.
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"errorCode": "pairingRequestNotFound",
				"message":   "Pairing request was not found.",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)

	start := time.Now()
	_, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("NewClient should have failed for a pairing request the server reports as gone")
	}
	if !errors.Is(err, errPairingRequestGone) {
		t.Fatalf("expected error wrapping errPairingRequestGone, got: %v", err)
	}
	// waitForApprovedSession's normal timeout is ~900 attempts * 2s (~30 minutes); failing
	// fast should take a small fraction of one poll interval, not multiple seconds.
	if elapsed > 2*time.Second {
		t.Fatalf("expected fast failure on a gone pairing request, took %v", elapsed)
	}
}

// TestExternalenc_KeyAccessUnsupportedFailsFast proves that once the server reports
// HTTP 501 on /block-passwords (what the real Key Server returns when it has no Carter
// card APDU extension to derive secrets with — see test_big_real.sh), 115fs stops
// retrying immediately instead of polling every 2s for up to 4 minutes
// (waitForKeys's normal retry budget). Before the fix, a 501 was retried exactly like a
// transient failure (expired session, network hiccup), so a server that will never be
// able to answer could hang a read/write for the full retry budget instead of failing
// fast with a clear reason.
func TestExternalenc_KeyAccessUnsupportedFailsFast(t *testing.T) {
	clientId := "mock-worker-501"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	reqID := "req-501"
	sessionToken := "mock-session-token-501"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok", ServiceName: "mockCarter", HTTPSRequired: false})
		case r.URL.Path == "/api/v1/pairing-requests":
			pairResp := CreatePairingResponse{
				PairingRequestId: reqID,
				ClientId:         clientId,
				PairingCode:      "111 222",
				ExpiresAt:        "2030-01-01T00:00:00Z",
			}
			body, _ := json.Marshal(pairResp)
			nonce, ciphertext, err := encryptEnvelope(body, clientKey, "pairingResponse:"+clientId)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/pairing-requests/"+reqID+"/session-key":
			sessResp := SessionResponse{
				SessionToken: sessionToken,
				RefreshToken: "mock-refresh-token-501",
				SessionKey:   base64.RawURLEncoding.EncodeToString(sessionKey),
				Policy:       SessionPolicy{MaxBlockCount: 32},
			}
			body, _ := json.Marshal(sessResp)
			aad := fmt.Sprintf("pairingSessionResponse:%s:%s", clientId, reqID)
			nonce, ciphertext, err := encryptEnvelope(body, clientKey, aad)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/block-passwords":
			// Simulates a real Key Server with no Carter card APDU extension: it will
			// never be able to derive block passwords, no matter how many times asked.
			w.WriteHeader(http.StatusNotImplemented)
			json.NewEncoder(w).Encode(map[string]string{
				"errorCode": "notImplemented",
				"message":   "Block password derivation needs the card APDU extension before this endpoint can return secrets.",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient (mock pairing/session) failed: %v", err)
	}

	start := time.Now()
	_, err = client.GetBlockKey(0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("GetBlockKey should have failed against a server with no block-password support")
	}
	if !errors.Is(err, errKeyAccessUnsupported) {
		t.Fatalf("expected error wrapping errKeyAccessUnsupported, got: %v", err)
	}
	// waitForKeys's normal retry budget is 120 attempts * 2s (~4 minutes); failing fast
	// on a 501 should take a small fraction of one retry interval, not multiple seconds.
	if elapsed > 2*time.Second {
		t.Fatalf("expected fast failure on an unsupported key server, took %v", elapsed)
	}
}

// TestExternalenc_CardRechallengeRequiredFailsFast proves that HTTP 423 /
// cardUsageRechallengeRequired (the card demanding fresh user presence before deriving
// more key material - a real, documented response from the now-implemented card APDU
// extension) fails the current call immediately rather than blocking the FUSE call on an
// external, browser-driven rechallenge it has no way to poll for or complete itself.
func TestExternalenc_CardRechallengeRequiredFailsFast(t *testing.T) {
	clientId := "mock-worker-423"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	reqID := "req-423"
	sessionToken := "mock-session-token-423"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok", ServiceName: "mockCarter", HTTPSRequired: false})
		case r.URL.Path == "/api/v1/pairing-requests":
			pairResp := CreatePairingResponse{PairingRequestId: reqID, ClientId: clientId, PairingCode: "111 222", ExpiresAt: "2030-01-01T00:00:00Z"}
			body, _ := json.Marshal(pairResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, "pairingResponse:"+clientId)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/pairing-requests/"+reqID+"/session-key":
			sessResp := SessionResponse{SessionToken: sessionToken, RefreshToken: "rt-423", SessionKey: base64.RawURLEncoding.EncodeToString(sessionKey), Policy: SessionPolicy{MaxBlockCount: 32}}
			body, _ := json.Marshal(sessResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, fmt.Sprintf("pairingSessionResponse:%s:%s", clientId, reqID))
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/block-passwords":
			// Simulates the card's own usage policy blocking further derivation until a
			// human completes a rechallenge on the Web UI - not something 115fs can do or
			// wait out itself.
			w.WriteHeader(http.StatusLocked)
			json.NewEncoder(w).Encode(map[string]string{
				"errorCode": "cardUsageRechallengeRequired",
				"message":   "Card usage policy requires a user rechallenge before more block keys can be returned.",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient (mock pairing/session) failed: %v", err)
	}

	start := time.Now()
	_, err = client.GetBlockKey(0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("GetBlockKey should have failed when the card demands a rechallenge")
	}
	if !errors.Is(err, errCardRechallengeRequired) {
		t.Fatalf("expected error wrapping errCardRechallengeRequired, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected fast failure on a card rechallenge requirement, took %v", elapsed)
	}
}

// TestExternalenc_CardUnavailableFailsFast proves that HTTP 424 (the keyserver's
// dependency - the physical card/reader - being unreachable) also fails fast rather than
// retrying, since retrying the identical request cannot fix a hardware problem.
func TestExternalenc_CardUnavailableFailsFast(t *testing.T) {
	clientId := "mock-worker-424"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	reqID := "req-424"
	sessionToken := "mock-session-token-424"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok", ServiceName: "mockCarter", HTTPSRequired: false})
		case r.URL.Path == "/api/v1/pairing-requests":
			pairResp := CreatePairingResponse{PairingRequestId: reqID, ClientId: clientId, PairingCode: "111 222", ExpiresAt: "2030-01-01T00:00:00Z"}
			body, _ := json.Marshal(pairResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, "pairingResponse:"+clientId)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/pairing-requests/"+reqID+"/session-key":
			sessResp := SessionResponse{SessionToken: sessionToken, RefreshToken: "rt-424", SessionKey: base64.RawURLEncoding.EncodeToString(sessionKey), Policy: SessionPolicy{MaxBlockCount: 32}}
			body, _ := json.Marshal(sessResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, fmt.Sprintf("pairingSessionResponse:%s:%s", clientId, reqID))
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/block-passwords":
			w.WriteHeader(http.StatusFailedDependency)
			json.NewEncoder(w).Encode(map[string]string{
				"errorCode": "cardUnavailable",
				"message":   "Carter card reader not responding.",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient (mock pairing/session) failed: %v", err)
	}

	start := time.Now()
	_, err = client.GetBlockKey(0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("GetBlockKey should have failed when the card is unreachable")
	}
	if !errors.Is(err, errCardUnavailable) {
		t.Fatalf("expected error wrapping errCardUnavailable, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected fast failure when the card is unreachable, took %v", elapsed)
	}
}

// TestExternalenc_KeyNameSentPlainOnWire proves that both content-key and name-key
// requests send the server the plain registered key name (e.g. "photos") and nothing
// else - never a derived/namespaced string like "photos:names". The server only knows
// about whatever key name it was actually registered under; sending anything else is a
// request for a key that, from the server's point of view, does not exist. blockIndex
// (a small sequential offset for content, a directory's own ~63-bit IV for names) is
// what actually distinguishes the two kinds of request on the wire.
func TestExternalenc_KeyNameSentPlainOnWire(t *testing.T) {
	clientId := "mock-worker-plain-keyname"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	reqID := "req-plain-keyname"
	sessionToken := "mock-session-token-plain-keyname"

	var mu sync.Mutex
	var seenKeyNames []string
	var seenPrefixes []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok", ServiceName: "mockCarter", HTTPSRequired: false})
		case r.URL.Path == "/api/v1/pairing-requests":
			pairResp := CreatePairingResponse{PairingRequestId: reqID, ClientId: clientId, PairingCode: "111 222", ExpiresAt: "2030-01-01T00:00:00Z"}
			body, _ := json.Marshal(pairResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, "pairingResponse:"+clientId)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/pairing-requests/"+reqID+"/session-key":
			sessResp := SessionResponse{SessionToken: sessionToken, RefreshToken: "rt", SessionKey: base64.RawURLEncoding.EncodeToString(sessionKey), Policy: SessionPolicy{MaxBlockCount: 32}}
			body, _ := json.Marshal(sessResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, fmt.Sprintf("pairingSessionResponse:%s:%s", clientId, reqID))
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/block-passwords":
			var req BlockPasswordRequest
			json.NewDecoder(r.Body).Decode(&req)
			decrypted, err := decryptEnvelope(req.ClientNonce, req.EncryptedPayload, sessionKey, "blockPasswordsRequest:"+sessionToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var payload BlockPasswordPayload
			json.Unmarshal(decrypted, &payload)

			mu.Lock()
			seenKeyNames = append(seenKeyNames, payload.KeyName)
			mu.Unlock()

			if strings.Contains(payload.KeyName, ":") {
				// A real server only knows the plain registered name - simulate it
				// rejecting anything else as an unknown key, exactly like it would
				// reject "photos:names" when only "photos" was ever registered.
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"errorCode": "keyNotFound", "message": "no such key: " + payload.KeyName})
				return
			}

			if payload.Prefix == "" {
				http.Error(w, "missing required prefix", http.StatusBadRequest)
				return
			}

			mu.Lock()
			seenPrefixes = append(seenPrefixes, payload.Prefix)
			mu.Unlock()

			pws := make(map[string]string)
			for i := int64(0); i < int64(payload.BlockCount); i++ {
				idx := payload.BlockIndex + i
				pws[strconv.FormatInt(idx, 10)] = "secret-pass-" + strconv.FormatInt(idx, 10)
			}
			respBytes, _ := json.Marshal(BlockPasswordResponse{KeyName: payload.KeyName, Prefix: payload.Prefix, BlockIndex: payload.BlockIndex, BlockCount: payload.BlockCount, KeyMaterial: pws})
			nonce, ciphertext, _ := encryptEnvelope(respBytes, sessionKey, "blockPasswordsResponse:"+sessionToken)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if _, err := client.GetBlockKey(0); err != nil {
		t.Fatalf("GetBlockKey(0) failed: %v", err)
	}
	dirIV := make([]byte, 16)
	rand.Read(dirIV)
	if _, err := client.GetNameEME(dirIV); err != nil {
		t.Fatalf("GetNameEME failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenKeyNames) != 2 {
		t.Fatalf("expected 2 block-passwords requests, server saw %d: %v", len(seenKeyNames), seenKeyNames)
	}
	for _, kn := range seenKeyNames {
		if kn != "photos" {
			t.Fatalf("expected every request to use the plain registered key name %q, server saw %q", "photos", kn)
		}
	}
	if len(seenPrefixes) != 2 || seenPrefixes[0] == "" || seenPrefixes[1] == "" {
		t.Fatalf("expected every request to carry a non-empty required prefix, server saw %v", seenPrefixes)
	}
}

// TestExternalenc_UnknownKeyFailsFast proves that a block-passwords failure unrelated to
// the session (e.g. the requested key name isn't registered on the server at all) fails
// immediately, the same way the 501 case does — there is no reason to retry a request for
// a key that will never exist, and no multi-minute wait should happen for it.
func TestExternalenc_UnknownKeyFailsFast(t *testing.T) {
	clientId := "mock-worker-unknown-key"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	reqID := "req-unknown-key"
	sessionToken := "mock-session-token-unknown-key"

	ts := httptest.NewServer(newMockKeyserverHandler(clientId, clientKey, sessionKey, reqID, sessionToken))
	defer ts.Close()
	// Override /block-passwords on top of the base mock to always report the key as
	// unknown, regardless of what was requested.
	base := ts.Config.Handler
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/block-passwords" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"errorCode": "keyNotFound", "message": "no such key"})
			return
		}
		base.ServeHTTP(w, r)
	})

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	start := time.Now()
	_, err = client.GetBlockKey(0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("GetBlockKey should have failed for an unregistered key name")
	}
	if !strings.Contains(err.Error(), "keyNotFound") {
		t.Fatalf("expected the server's keyNotFound error to surface, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected fast failure on an unknown key, took %v", elapsed)
	}
}

// TestExternalenc_SessionRejectedRetriesOnce proves the one exception to the fail-fast
// rule: a block-passwords request rejected with HTTP 401 (the session itself, not the
// request, being the problem) causes exactly one re-authenticate-and-retry, not a
// generic failure and not an open-ended loop.
func TestExternalenc_SessionRejectedRetriesOnce(t *testing.T) {
	clientId := "mock-worker-401-retry"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	reqID := "req-401-retry"

	var mu sync.Mutex
	tokenGeneration := 0
	rejectedOnce := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok", ServiceName: "mockCarter", HTTPSRequired: false})
		case r.URL.Path == "/api/v1/pairing-requests":
			pairResp := CreatePairingResponse{PairingRequestId: reqID, ClientId: clientId, PairingCode: "111 222", ExpiresAt: "2030-01-01T00:00:00Z"}
			body, _ := json.Marshal(pairResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, "pairingResponse:"+clientId)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/pairing-requests/"+reqID+"/session-key":
			mu.Lock()
			tokenGeneration++
			tok := fmt.Sprintf("session-token-gen-%d", tokenGeneration)
			mu.Unlock()
			sessResp := SessionResponse{SessionToken: tok, RefreshToken: "rt-" + tok, SessionKey: base64.RawURLEncoding.EncodeToString(sessionKey), Policy: SessionPolicy{MaxBlockCount: 32}}
			body, _ := json.Marshal(sessResp)
			nonce, ciphertext, _ := encryptEnvelope(body, clientKey, fmt.Sprintf("pairingSessionResponse:%s:%s", clientId, reqID))
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		case r.URL.Path == "/api/v1/sessions/refresh":
			// No refresh support in this mock - forces waitForKeys down the
			// full-re-pairing path, which still must only happen once.
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/api/v1/block-passwords":
			auth := r.Header.Get("Authorization")
			mu.Lock()
			firstGenToken := "Bearer session-token-gen-1"
			already := rejectedOnce
			if auth == firstGenToken && !already {
				rejectedOnce = true
			}
			mu.Unlock()
			if auth == firstGenToken {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"errorCode": "sessionInvalid", "message": "session no longer valid"})
				return
			}
			var req BlockPasswordRequest
			json.NewDecoder(r.Body).Decode(&req)
			tok := strings.TrimPrefix(auth, "Bearer ")
			decrypted, err := decryptEnvelope(req.ClientNonce, req.EncryptedPayload, sessionKey, "blockPasswordsRequest:"+tok)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var payload BlockPasswordPayload
			json.Unmarshal(decrypted, &payload)
			if payload.Prefix == "" {
				http.Error(w, "missing required prefix", http.StatusBadRequest)
				return
			}
			pws := map[string]string{strconv.FormatInt(payload.BlockIndex, 10): "secret-pass"}
			respBytes, _ := json.Marshal(BlockPasswordResponse{KeyName: payload.KeyName, Prefix: payload.Prefix, BlockIndex: payload.BlockIndex, BlockCount: payload.BlockCount, KeyMaterial: pws})
			nonce, ciphertext, _ := encryptEnvelope(respBytes, sessionKey, "blockPasswordsResponse:"+tok)
			json.NewEncoder(w).Encode(EncryptedEnvelope{Algorithm: "AES-256-GCM", Nonce: nonce, Ciphertext: ciphertext})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	start := time.Now()
	key, err := client.GetBlockKey(0)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GetBlockKey should have succeeded after one re-authentication, got: %v", err)
	}
	if len(key) == 0 {
		t.Fatalf("expected a non-empty key after recovering from a 401")
	}
	// Re-pairing here is instant (mock auto-approves on the first session-key poll),
	// so this should complete in well under the fail-fast tests' 2s budget too.
	if elapsed > 2*time.Second {
		t.Fatalf("expected quick recovery from a single 401, took %v", elapsed)
	}
}

func TestExternalenc_UnpairedFails(t *testing.T) {
	_, err := NewClient("https://invalid.local:9443", "testkey", "", "", "", nil)
	if err == nil {
		t.Fatalf("NewClient should have failed when server is unreachable/unpaired")
	}
}

// TestExternalenc_PassphraseKeyDerivation proves that a non-raw-key
// "clientKeyStr" (i.e. a human-chosen passphrase, not a 32-byte base64 key)
// is deterministically derived via salted scrypt: the same passphrase+salt
// always yields the same key (required so the client can decrypt its own
// past session data across restarts), a different salt yields a different
// key (proving it's actually salted, not a bare hash), and no salt at all is
// a hard error rather than silently falling back to something unsalted.
func TestExternalenc_PassphraseKeyDerivation(t *testing.T) {
	c := &Client{}
	salt1 := []byte("0123456789abcdef0123456789abcdef")
	salt2 := []byte("fedcba9876543210fedcba9876543210")

	if err := c.deriveClientKey("correct horse battery staple", salt1); err != nil {
		t.Fatalf("deriveClientKey failed: %v", err)
	}
	key1 := append([]byte(nil), c.ClientKey...)
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte derived key, got %d bytes", len(key1))
	}

	c2 := &Client{}
	if err := c2.deriveClientKey("correct horse battery staple", salt1); err != nil {
		t.Fatalf("deriveClientKey (again) failed: %v", err)
	}
	if !bytes.Equal(key1, c2.ClientKey) {
		t.Fatalf("same passphrase+salt produced different keys — derivation is not deterministic")
	}

	c3 := &Client{}
	if err := c3.deriveClientKey("correct horse battery staple", salt2); err != nil {
		t.Fatalf("deriveClientKey (different salt) failed: %v", err)
	}
	if bytes.Equal(key1, c3.ClientKey) {
		t.Fatalf("different salts produced the same key — derivation is not actually salted")
	}

	c4 := &Client{}
	if err := c4.deriveClientKey("correct horse battery staple", nil); err == nil {
		t.Fatalf("deriveClientKey with no salt should have failed, not silently derived a key")
	}
}

// TestExternalenc_NameKeysPerDirectory proves that filename encryption has no
// filesystem-wide key: different directory IVs must yield different EME
// ciphers (fetched from the same mock server, under the ":names" KeyName
// namespace), and the same IV must yield the identical cached cipher again.
func TestExternalenc_NameKeysPerDirectory(t *testing.T) {
	clientId := "mock-worker-names"
	clientKey := make([]byte, 32)
	rand.Read(clientKey)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	ts := httptest.NewServer(newMockKeyserverHandler(clientId, clientKey, sessionKey, "req-names", "names-session-token"))
	defer ts.Close()

	clientKeyStr := clientId + ":" + base64.RawURLEncoding.EncodeToString(clientKey)
	client, err := NewClient(ts.URL, "photos", clientKeyStr, "", "", nil)
	if err != nil {
		t.Fatalf("NewClient mock server failed: %v", err)
	}

	dirIVa := make([]byte, 16)
	dirIVb := make([]byte, 16)
	rand.Read(dirIVa)
	rand.Read(dirIVb)

	emeA, err := client.GetNameEME(dirIVa)
	if err != nil {
		t.Fatalf("GetNameEME(dirIVa) failed: %v", err)
	}
	emeB, err := client.GetNameEME(dirIVb)
	if err != nil {
		t.Fatalf("GetNameEME(dirIVb) failed: %v", err)
	}

	plaintext := make([]byte, 16)
	cA := emeA.Encrypt(dirIVa, plaintext)
	cB := emeB.Encrypt(dirIVb, plaintext)
	if bytes.Equal(cA, cB) {
		t.Fatalf("different directories produced identical ciphertext — filename key is not per-directory")
	}

	emeAAgain, err := client.GetNameEME(dirIVa)
	if err != nil {
		t.Fatalf("GetNameEME(dirIVa) second call failed: %v", err)
	}
	if !bytes.Equal(emeAAgain.Encrypt(dirIVa, plaintext), cA) {
		t.Fatalf("re-fetching the same directory IV produced a different key")
	}
}
