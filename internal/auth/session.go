package auth

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"tunneldeck/internal/domain"
)

// Session limits (SPEC §8).
const (
	// SessionIdleTimeout ends a session that was not used for this long.
	SessionIdleTimeout = 12 * time.Hour
	// RememberedIdleTimeout ends a "stay signed in" session that was not
	// used for this long.
	RememberedIdleTimeout = 30 * 24 * time.Hour
	// RememberedLifetime ends a "stay signed in" session this long after
	// the login, however often it is used. Its cookie lives as long.
	RememberedLifetime = 90 * 24 * time.Hour
	// MaxSessions caps concurrent sessions; creating one more drops the
	// oldest.
	MaxSessions = 100
	// MaxRememberedSessions caps "stay signed in" sessions; remembering one
	// more drops the oldest remembered one.
	MaxRememberedSessions = 10
	// lastUsedWriteInterval throttles writing the last-used time of a
	// remembered session to the store.
	lastUsedWriteInterval = time.Hour
	// tokenBytes is the token entropy: 256 bits.
	tokenBytes = 32
)

// RememberedSessionStore persists "stay signed in" sessions across restarts.
// *store.Store satisfies it.
type RememberedSessionStore interface {
	RememberedSessions() []domain.RememberedSession
	SetRememberedSessions(sessions []domain.RememberedSession) error
}

type tokenHash [sha256.Size]byte

type session struct {
	username   string
	clientIP   string
	remembered bool
	createdAt  time.Time
	lastSeen   time.Time
	// lastPersisted is the last-used time the store holds; remembered
	// sessions only.
	lastPersisted time.Time
}

// sessionStore keeps sessions in memory, keyed by the SHA-256 of their
// token, so a memory dump does not reveal usable tokens. Remembered
// sessions are also written to persisted, as token hashes only.
type sessionStore struct {
	mu        sync.Mutex
	persisted RememberedSessionStore
	sessions  map[tokenHash]session
}

func newSessionStore(persisted RememberedSessionStore) *sessionStore {
	return &sessionStore{persisted: persisted, sessions: make(map[tokenHash]session)}
}

// load restores the remembered sessions of the store. Malformed and
// expired entries are skipped; beyond the cap the oldest are dropped. The
// store is not written.
func (s *sessionStore) load(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.persisted.RememberedSessions() {
		key, ok := parseTokenHash(record.TokenHash)
		if !ok {
			continue
		}
		restored := session{
			username: record.Username, clientIP: record.ClientIP, remembered: true,
			createdAt: record.CreatedAt, lastSeen: record.LastUsedAt, lastPersisted: record.LastUsedAt,
		}
		if !expired(restored, now) {
			s.sessions[key] = restored
		}
	}
	for s.countRemembered() > MaxRememberedSessions {
		s.removeOldest(isRemembered)
	}
}

// create starts a session for username and returns its token. It first
// removes expired sessions, then the oldest ones while a cap is reached.
// Both sweeps are bounded by MaxSessions. A remembered session is only
// created once the store holds it.
func (s *sessionStore) create(username, clientIP string, remembered bool, now time.Time) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	droppedRemembered := s.makeRoom(remembered, now)
	key := hashToken(token)
	s.sessions[key] = session{
		username: username, clientIP: clientIP, remembered: remembered,
		createdAt: now, lastSeen: now, lastPersisted: now,
	}
	if !remembered {
		if droppedRemembered {
			s.persistOrWarn()
		}
		return token, nil
	}
	if err := s.persist(); err != nil {
		delete(s.sessions, key)
		return "", err
	}
	return token, nil
}

// makeRoom removes expired sessions and the oldest ones over the caps. It
// reports whether a remembered session was removed. The caller holds s.mu.
func (s *sessionStore) makeRoom(remembered bool, now time.Time) bool {
	dropped := s.removeExpired(now)
	for len(s.sessions) >= MaxSessions {
		dropped = s.removeOldest(anySession).remembered || dropped
	}
	for remembered && s.countRemembered() >= MaxRememberedSessions {
		s.removeOldest(isRemembered)
		dropped = true
	}
	return dropped
}

// authenticate returns the username of the session behind token and
// refreshes its idle timer. An expired session is removed. The last-used
// time of a remembered session reaches the store at most once per
// lastUsedWriteInterval.
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
	if expired(current, now) {
		delete(s.sessions, key)
		if current.remembered {
			s.persistOrWarn()
		}
		return "", false
	}
	current.lastSeen = now
	s.sessions[key] = current
	if current.remembered && now.Sub(current.lastPersisted) >= lastUsedWriteInterval {
		s.persistOrWarn()
	}
	return current.username, true
}

// revoke ends the session behind token, if any. A remembered session is
// also removed from the store.
func (s *sessionStore) revoke(token string) error {
	key := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[key]
	if !ok {
		return nil
	}
	delete(s.sessions, key)
	if !current.remembered {
		return nil
	}
	return s.persist()
}

// revokeAll ends every session and empties the store's list.
func (s *sessionStore) revokeAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.sessions)
	return s.persist()
}

// dropAll ends every session in memory only; the caller clears the store.
func (s *sessionStore) dropAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.sessions)
}

// persist writes every remembered session, oldest first, with its current
// last-used time. The caller holds s.mu.
func (s *sessionStore) persist() error {
	records := make([]domain.RememberedSession, 0, MaxRememberedSessions)
	for key, current := range s.sessions {
		if !current.remembered {
			continue
		}
		records = append(records, domain.RememberedSession{
			TokenHash: hex.EncodeToString(key[:]), Username: current.username,
			CreatedAt: current.createdAt.UTC(), LastUsedAt: current.lastSeen.UTC(), ClientIP: current.clientIP,
		})
	}
	slices.SortFunc(records, func(a, b domain.RememberedSession) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.TokenHash, b.TokenHash))
	})
	if err := s.persisted.SetRememberedSessions(records); err != nil {
		return fmt.Errorf("persist remembered sessions: %w", err)
	}
	for key, current := range s.sessions {
		if current.remembered {
			current.lastPersisted = current.lastSeen
			s.sessions[key] = current
		}
	}
	return nil
}

// persistOrWarn persists where the caller cannot report an error; the
// sessions in memory stay authoritative until the next write. The caller
// holds s.mu.
func (s *sessionStore) persistOrWarn() {
	if err := s.persist(); err != nil {
		slog.Warn("auth: keep remembered sessions", "error", err)
	}
}

func (s *sessionStore) countRemembered() int {
	count := 0
	for _, current := range s.sessions {
		if current.remembered {
			count++
		}
	}
	return count
}

// removeExpired deletes expired sessions and reports whether one of them
// was remembered. The caller holds s.mu.
func (s *sessionStore) removeExpired(now time.Time) bool {
	dropped := false
	for key, current := range s.sessions {
		if expired(current, now) {
			delete(s.sessions, key)
			dropped = dropped || current.remembered
		}
	}
	return dropped
}

// removeOldest deletes the session created first among those matching
// and returns it. The caller holds s.mu.
func (s *sessionStore) removeOldest(matches func(session) bool) session {
	var oldestKey tokenHash
	var oldest session
	found := false
	for key, current := range s.sessions {
		if matches(current) && (!found || current.createdAt.Before(oldest.createdAt)) {
			oldestKey, oldest, found = key, current, true
		}
	}
	delete(s.sessions, oldestKey)
	return oldest
}

func anySession(session) bool { return true }

func isRemembered(current session) bool { return current.remembered }

// expired applies the idle timeout and, for remembered sessions, the
// absolute lifetime.
func expired(current session, now time.Time) bool {
	if !current.remembered {
		return now.Sub(current.lastSeen) >= SessionIdleTimeout
	}
	return now.Sub(current.lastSeen) >= RememberedIdleTimeout || now.Sub(current.createdAt) >= RememberedLifetime
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

func parseTokenHash(encoded string) (tokenHash, bool) {
	var key tokenHash
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != len(key) {
		return key, false
	}
	copy(key[:], raw)
	return key, true
}
