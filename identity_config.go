package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// decodeKey decodes a base64-encoded key/secret, accepting both standard and
// raw (unpadded) encodings since 115fs writes standard-padded base64 but
// hand-edited config files might not have padding.
func decodeKey(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// fsIdentityConfigFile mirrors the small subset of 115fs's own config.json
// (see main.go's Config struct in the 115fs module) that gocryptfs needs to
// resolve its FS transport and card identity. It intentionally only declares
// the fields it reads — json.Unmarshal ignores the rest (profiles, etc.), so
// this never needs to track 115fs's full config schema.
type fsIdentityConfigFile struct {
	TransportClientID  string `json:"transport_client_id"`
	TransportClientKey string `json:"transport_client_key"`
	CardClientID       string `json:"card_client_id"`
	CardClientSecret   string `json:"card_client_secret"`
	CardInstanceID     string `json:"card_instance_id"`
}

// fsIdentityConfigPath returns the same path 115fs's own getConfigPath()
// computes, so both processes agree on one file without needing to pass a
// path explicitly. gocryptfs is always launched with the same HOME/APPDATA
// environment as the 115fs process that spawned it (os/exec inherits the
// parent's environment by default), so this resolves to the identical file.
func fsIdentityConfigPath() (string, error) {
	if runtime.GOOS == "windows" {
		configDir := os.Getenv("APPDATA")
		if configDir == "" {
			configDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
		return filepath.Join(configDir, "115fs", "config.json"), nil
	}
	home := os.Getenv("HOME")
	if home == "" {
		return "", fmt.Errorf("HOME is not set")
	}
	return filepath.Join(home, ".config", "115fs", "config.json"), nil
}

// fsIdentity is the resolved, decoded form of resolveFsIdentityFromConfig's
// result — ready to hand straight to cardclient.New.
type fsIdentity struct {
	TransportClientID  string
	TransportClientKey []byte
	CardClientID       string
	CardClientSecret   []byte
	CardInstanceID     string
}

// resolveFsIdentityFromConfig looks up the FS transport identity
// (transportClientId/Key) and card identity (cardClientId/Secret,
// cardInstanceId) from 115fs's config file, so neither secret ever has to be
// passed on this process's command line (visible to any local user via
// `ps auxww` or /proc/<pid>/cmdline). 115fs's cmdMount passes only
// -fs-identity-from-config — never a secret itself — and this is the other
// half of that split.
//
// There is one FS identity per config file (see main.go's Config), so there
// is nothing to select between here — this always resolves to that single
// configured identity.
func resolveFsIdentityFromConfig() (*fsIdentity, error) {
	path, err := fsIdentityConfigPath()
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading 115fs config %s: %w", path, err)
	}
	// Defense in depth: this file holds the transport and card secrets used
	// to authenticate with the keyserver and the card. Refuse to use it at
	// all if its permissions would let another local user read it — 115fs's
	// own interactive permission check (run on every terminal invocation) is
	// the primary defense, this is a fail-closed backstop for the process
	// that actually needs the secrets.
	if fi.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("115fs config %s has overly permissive permissions (%04o); refusing to read FS identity secrets from it. Fix with: chmod 600 %s", path, fi.Mode().Perm(), path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading 115fs config %s: %w", path, err)
	}
	var cfg fsIdentityConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing 115fs config %s: %w", path, err)
	}

	if cfg.TransportClientID == "" || cfg.TransportClientKey == "" {
		return nil, fmt.Errorf("115fs config %s has no transport identity configured", path)
	}
	if cfg.CardClientID == "" || cfg.CardClientSecret == "" || cfg.CardInstanceID == "" {
		return nil, fmt.Errorf("115fs config %s has no card identity configured", path)
	}

	transportKey, err := decodeKey(cfg.TransportClientKey)
	if err != nil {
		return nil, fmt.Errorf("115fs config %s has an invalid transport_client_key: %w", path, err)
	}
	if len(transportKey) != 32 {
		return nil, fmt.Errorf("115fs config %s: transport_client_key must decode to 32 bytes, got %d", path, len(transportKey))
	}
	cardSecret, err := decodeKey(cfg.CardClientSecret)
	if err != nil {
		return nil, fmt.Errorf("115fs config %s has an invalid card_client_secret: %w", path, err)
	}
	if len(cardSecret) != 32 {
		return nil, fmt.Errorf("115fs config %s: card_client_secret must decode to 32 bytes, got %d", path, len(cardSecret))
	}

	return &fsIdentity{
		TransportClientID:  cfg.TransportClientID,
		TransportClientKey: transportKey,
		CardClientID:       cfg.CardClientID,
		CardClientSecret:   cardSecret,
		CardInstanceID:     cfg.CardInstanceID,
	}, nil
}
