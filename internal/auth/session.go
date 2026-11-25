package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session limits (SPEC §8).
const (
	// SessionIdleTimeout ends a session that was not used for this long.
	SessionIdleTimeout = 12 * time.Hour
	// MaxSessions caps concurrent sessions; creating one more drops the
	// oldest.
	MaxSessions = 100
	// tokenBytes is the token entropy: 256 bits.
	tokenBytes = 32
)

type tokenHash [sha256.Size]byte

type session struct {
	username  string
	createdAt time.Time
	lastSeen  time.Time
}

// sessionStore keeps sessions in memory, keyed by the SHA-256 of their
// token, so a memory dump does not reveal usable tokens.
type sessionStore struct {
	mu          sync.Mutex
	idleTimeout time.Duration
	maxSessions int
	sessions    map[tokenHash]session
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		idleTimeout: SessionIdleTimeout,
		maxSessions: MaxSessions,
		sessions:    make(map[tokenHash]session),
	}
}

// create starts a session for username and returns its token. It first
// removes expired sessions, then the oldest ones while the cap is reached.
// Both sweeps are bounded by maxSessions.
func (s *sessionStore) create(username string, now time.Time) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpired(now)
	for len(s.sessions) >= s.maxSessions {
		s.removeOldest()
	}
	s.sessions[hashToken(token)] = session{username: username, createdAt: now, lastSeen: now}
	return token, nil
}

// authenticate returns the username of the session behind token and
// refreshes its idle timer. An expired session is removed.
func (s *sessionStore) authenticate(token string, now time.Time) (string, bool) {
	if token == "" {
		return "", false
	}
	key := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[key]
	if !ok {
		return "", false
	}
	if s.expired(current, now) {
		delete(s.sessions, key)
		return "", false
	}
	current.lastSeen = now
	s.sessions[key] = current
	return current.username, true
}

// revoke ends the session behind token, if any.
func (s *sessionStore) revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hashToken(token))
}

// revokeAll ends every session.
func (s *sessionStore) revokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.sessions)
}

func (s *sessionStore) expired(current session, now time.Time) bool {
	return now.Sub(current.lastSeen) >= s.idleTimeout
}

// removeExpired deletes expired sessions. The caller holds s.mu.
func (s *sessionStore) removeExpired(now time.Time) {
	for key, current := range s.sessions {
		if s.expired(current, now) {
			delete(s.sessions, key)
		}
	}
}

// removeOldest deletes the session created first. The caller holds s.mu.
func (s *sessionStore) removeOldest() {
	var oldestKey tokenHash
	var oldest time.Time
	first := true
	for key, current := range s.sessions {
		if first || current.createdAt.Before(oldest) {
			oldestKey, oldest, first = key, current.createdAt, false
		}
	}
	delete(s.sessions, oldestKey)
}

func newToken() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(token string) tokenHash {
	return sha256.Sum256([]byte(token))
}
