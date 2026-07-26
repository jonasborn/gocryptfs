package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// decodeSalt decodes a base64-encoded salt, accepting both standard and
// raw (unpadded) encodings since 115fs writes standard-padded base64 but
// hand-edited config files might not have padding.
func decodeSalt(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// symkeyConfigFile mirrors the small subset of 115fs's own config.json (see
// main.go's Config struct in the 115fs module) that gocryptfs needs to
// resolve a symmetric key by client ID. It intentionally only declares the
// fields it reads — json.Unmarshal ignores the rest (profiles, cert hashes,
// etc.), so this never needs to track 115fs's full config schema.
type symkeyConfigFile struct {
	ClientId         string `json:"client_id"`
	SymmetricKey     string `json:"symmetric_key"`
	SymmetricKeySalt string `json:"symmetric_key_salt"`
}

// symkeyConfigPath returns the same path 115fs's own getConfigPath()
// computes, so both processes agree on one file without needing to pass a
// path explicitly. gocryptfs is always launched with the same HOME/APPDATA
// environment as the 115fs process that spawned it (os/exec inherits the
// parent's environment by default), so this resolves to the identical file.
func symkeyConfigPath() (string, error) {
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

// resolveSymmetricKeyFromConfig looks up the symmetric key and its
// derivation salt from 115fs's config file, so the actual secret never has
// to be passed on this process's command line (visible to any local user via
// `ps auxww` or /proc/<pid>/cmdline). 115fs's cmdMount passes only
// -symmetric-key-from-config — never the secret itself — and this is the
// other half of that split.
//
// There is one client identity per config file (see main.go's Config), so
// there is nothing to select between here — this always resolves to that
// single configured secret.
//
// It returns a "clientId:symmetricKey" string in the same format NewClient
// already accepts from a direct -symmetric-key argument, plus the persisted
// salt (see deriveClientKey) needed to turn a non-raw-key passphrase into a
// deterministic 32-byte key.
func resolveSymmetricKeyFromConfig() (clientKeyStr string, salt []byte, err error) {
	path, err := symkeyConfigPath()
	if err != nil {
		return "", nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		return "", nil, fmt.Errorf("reading 115fs config %s: %w", path, err)
	}
	// Defense in depth: this file holds the shared secret used to
	// authenticate with the key server. Refuse to use it at all if its
	// permissions would let another local user read it — 115fs's own
	// interactive permission check (run on every terminal invocation) is the
	// primary defense, this is a fail-closed backstop for the process that
	// actually needs the secret.
	if fi.Mode().Perm()&0077 != 0 {
		return "", nil, fmt.Errorf("115fs config %s has overly permissive permissions (%04o); refusing to read the symmetric key from it. Fix with: chmod 600 %s", path, fi.Mode().Perm(), path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("reading 115fs config %s: %w", path, err)
	}
	var cfg symkeyConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", nil, fmt.Errorf("parsing 115fs config %s: %w", path, err)
	}

	if cfg.SymmetricKey == "" {
		return "", nil, fmt.Errorf("115fs config %s has no symmetric_key configured", path)
	}

	if cfg.SymmetricKeySalt != "" {
		saltBytes, decErr := decodeSalt(cfg.SymmetricKeySalt)
		if decErr != nil {
			return "", nil, fmt.Errorf("115fs config %s has an invalid symmetric_key_salt: %w", path, decErr)
		}
		salt = saltBytes
	}

	return cfg.ClientId + ":" + cfg.SymmetricKey, salt, nil
}
