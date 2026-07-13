package crypto

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"time"
)

const sessionTTL = 15 * time.Minute

type SessionCache struct {
	path string
}

func NewSessionCache() *SessionCache {
	home, _ := os.UserHomeDir()
	return &SessionCache{path: filepath.Join(home, ".aegis", ".session")}
}

// Store garde la clé dérivée (jamais le mot de passe lui-même) avec un horodatage d'expiration.
func (s *SessionCache) Store(key []byte) error {
	expiry := time.Now().Add(sessionTTL).Unix()
	content := make([]byte, 0)
	content = append(content, []byte(base64.StdEncoding.EncodeToString(key))...)
	content = append(content, '\n')
	content = append(content, []byte(time.Unix(expiry, 0).Format(time.RFC3339))...)
	return os.WriteFile(s.path, content, 0600)
}

// Load retourne la clé en cache si elle n'a pas expiré, sinon nil.
func (s *SessionCache) Load() []byte {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}

	lines := splitLines(data)
	if len(lines) < 2 {
		return nil
	}

	expiry, err := time.Parse(time.RFC3339, lines[1])
	if err != nil || time.Now().After(expiry) {
		os.Remove(s.path)
		return nil
	}

	key, err := base64.StdEncoding.DecodeString(lines[0])
	if err != nil {
		return nil
	}
	return key
}

func (s *SessionCache) Clear() {
	os.Remove(s.path)
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}
