package externalenc

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExternalenc_LessSecureBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://192.168.2.223:9443": "http://192.168.2.223:9080",
		"https://127.0.0.1:9443":     "http://127.0.0.1:9080",
		"https://keyserver.local":    "http://keyserver.local:9080",
	}
	for in, want := range cases {
		got := lessSecureBaseURL(in)
		if got != want {
			t.Errorf("lessSecureBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// captureEnvelope decrypts and returns the ClientMessagePayload carried by a
// clientLogEnvelope request body, and fails the test if the outer body ever
// contains a clientKey field (it never should — the server authenticates via
// successful AES-GCM decryption alone).
func captureEnvelope(t *testing.T, body []byte, clientKey []byte, aad string) ClientMessagePayload {
	t.Helper()
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("invalid envelope JSON: %v", err)
	}
	if _, ok := raw["clientKey"]; ok {
		t.Fatalf("request envelope contains a clientKey field — the secret must never be sent: %s", body)
	}
	var env clientLogEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	if env.ClientId == "" || env.Nonce == "" || env.Ciphertext == "" {
		t.Fatalf("incomplete envelope: %+v", env)
	}
	plaintext, err := decryptEnvelope(env.Nonce, env.Ciphertext, clientKey, aad)
	if err != nil {
		t.Fatalf("decrypting payload with AAD %q: %v", aad, err)
	}
	var payload ClientMessagePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	return payload
}

func TestExternalenc_LogSecureSendsOverHTTPS(t *testing.T) {
	clientKey := make([]byte, 32)
	rand.Read(clientKey)

	received := make(chan ClientMessagePayload, 1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/client-messages" {
			http.NotFound(w, r)
			return
		}
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		payload := captureEnvelope(t, body, clientKey, "clientMessage:test-client")
		received <- payload
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"accepted":true,"messageId":1,"category":"log"}`))
	}))
	defer ts.Close()

	c := &Client{
		BaseURL:   ts.URL,
		ClientId:  "test-client",
		ClientKey: clientKey,
		HTTPClient: &http.Client{
			Transport: ts.Client().Transport,
			Timeout:   5 * time.Second,
		},
	}

	c.LogSecure("warn", "Key access blocked", "waiting for key re-entry", nil)

	select {
	case payload := <-received:
		if payload.Category != "log" || payload.Level != "warn" || payload.Title != "Key access blocked" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server never received the client message")
	}
}

func TestExternalenc_LessSecureChannelUsesPlainHTTPAndNoClientKey(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:9080")
	if err != nil {
		t.Skipf("port 9080 unavailable in this environment, skipping: %v", err)
	}

	clientKey := make([]byte, 32)
	rand.Read(clientKey)

	received := make(chan ClientMessagePayload, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/less-secure/client-messages", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		payload := captureEnvelope(t, body, clientKey, "lessSecureClientMessage:test-client")
		received <- payload
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"accepted":true,"messageId":1,"category":"userMessage"}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	c := &Client{
		BaseURL:   "https://127.0.0.1:9443", // secure base — lessSecureBaseURL must derive :9080 from this
		ClientId:  "test-client",
		ClientKey: clientKey,
	}

	c.reportTLSTrustIssue("certificate fingerprint mismatch")

	select {
	case payload := <-received:
		if payload.Category != "userMessage" || payload.Level != "error" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("less-secure listener never received the client message")
	}
}

func TestExternalenc_SendClientMessageNoopsWithoutClientKey(t *testing.T) {
	// A Client with no ClientKey/ClientId (e.g. before pairing has any
	// identity configured) must not panic or attempt a network call — just
	// silently do nothing.
	c := &Client{BaseURL: "https://192.0.2.1:9443"}
	c.LogSecure("info", "no-op", "should not send", nil)
	c.reportStarted()
}
