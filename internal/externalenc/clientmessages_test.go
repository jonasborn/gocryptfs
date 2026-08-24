package externalenc

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/carter/ksclient"
)

func TestExternalenc_UntrustedBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://192.168.2.223:9443": "http://192.168.2.223:9080",
		"https://127.0.0.1:9443":     "http://127.0.0.1:9080",
		"https://keyserver.local":    "http://keyserver.local:9080",
	}
	for in, want := range cases {
		got := untrustedBaseURL(in)
		if got != want {
			t.Errorf("untrustedBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

type logSubmission struct {
	Level   string `json:"level"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Source  string `json:"source"`
}

func TestExternalenc_LogSecureSendsOverHTTPS(t *testing.T) {
	received := make(chan logSubmission, 1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fs/logs" {
			http.NotFound(w, r)
			return
		}
		var sub logSubmission
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			t.Errorf("decoding log submission: %v", err)
		}
		received <- sub
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"accepted":true,"id":1,"level":"warn"}`))
	}))
	defer ts.Close()

	c := &Client{
		BaseURL: ts.URL,
		ks:      ksclient.New(ts.URL, &http.Client{Transport: ts.Client().Transport, Timeout: 5 * time.Second}),
	}

	c.LogSecure("warn", "Key access blocked", "waiting for key re-entry", nil)

	select {
	case sub := <-received:
		if sub.Level != "warn" || sub.Title != "Key access blocked" {
			t.Fatalf("unexpected submission: %+v", sub)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server never received the log submission")
	}
}

func TestExternalenc_UntrustedChannelUsesPlainHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:9080")
	if err != nil {
		t.Skipf("port 9080 unavailable in this environment, skipping: %v", err)
	}

	received := make(chan logSubmission, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/untrusted/logs", func(w http.ResponseWriter, r *http.Request) {
		var sub logSubmission
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			t.Errorf("decoding log submission: %v", err)
		}
		received <- sub
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"accepted":true,"id":1,"level":"error"}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	c := &Client{
		BaseURL: "https://127.0.0.1:9443", // trusted base — untrustedBaseURL must derive :9080 from this
	}

	c.reportTLSTrustIssue("certificate fingerprint mismatch")

	select {
	case sub := <-received:
		if sub.Level != "error" {
			t.Fatalf("unexpected submission: %+v", sub)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("untrusted listener never received the log submission")
	}
}

func TestExternalenc_LogSecureNoopsWithoutKSClient(t *testing.T) {
	// A Client with no ks set (e.g. before NewClient has finished wiring it
	// up) must not panic or attempt a network call — just silently do
	// nothing.
	c := &Client{BaseURL: "https://192.0.2.1:9443"}
	c.LogSecure("info", "no-op", "should not send", nil)
}
