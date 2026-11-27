package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"tunneldeck/internal/domain"
)

// Credential rules for the admin account.
const (
	UsernameMinLength = 3
	UsernameMaxLength = 32
	PasswordMinLength = 12
	PasswordMaxLength = 256
)

// ErrInvalidCredentials reports a failed login. It does not tell whether the
// username or the password was wrong.
var ErrInvalidCredentials = errors.New("invalid username or password")

// CredentialsError reports a failed login and the cooldown it started; it
// matches ErrInvalidCredentials.
type CredentialsError struct {
	// RetryAfter is how long the client must wait before its next attempt.
	RetryAfter time.Duration
}

func (e *CredentialsError) Error() string {
	return fmt.Sprintf("%s, retry after %s", ErrInvalidCredentials, e.RetryAfter)
}

// Is makes errors.Is(err, ErrInvalidCredentials) true.
func (e *CredentialsError) Is(target error) bool {
	return target == ErrInvalidCredentials
}

// ErrRateLimited is matched by every *RateLimitError.
var ErrRateLimited = errors.New("too many failed logins")

// RateLimitError reports a login refused by the rate limit, without
// checking the credentials.
type RateLimitError struct {
	// RetryAfter is the remaining wait.
	RetryAfter time.Duration
	// Remote is true when the remote listener rejects every client
	// (SPEC §8.1), not just this one.
	Remote bool
}

func (e *RateLimitError) Error() string {
	if e.Remote {
		return fmt.Sprintf("%s on the remote listener, retry after %s", ErrRateLimited, e.RetryAfter)
	}
	return fmt.Sprintf("%s, retry after %s", ErrRateLimited, e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool {
	return target == ErrRateLimited
}

// AccountStore persists the single admin account and the remembered
// sessions. *store.Store satisfies it.
type AccountStore interface {
	RememberedSessionStore
	AdminAccount() (domain.AdminAccount, bool)
	// CreateAdminAccount fails with domain.ErrSetupAlreadyDone when an
	// account exists. It also drops every remembered session.
	CreateAdminAccount(account domain.AdminAccount) error
	// RemoveAdminAccount also drops every remembered session.
	RemoveAdminAccount() error
}

// Service handles the admin account, sessions and the login rate limit.
// It is safe for concurrent use.
type Service struct {
	store    AccountStore
	now      func() time.Time
	hasher   *passwordHasher
	sessions *sessionStore
	limiter  *loginLimiter
}

// Option configures a Service.
type Option func(*Service)

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// WithHashParams sets the argon2id parameters for new hashes. Existing
// hashes are always checked with the parameters they carry.
func WithHashParams(params HashParams) Option {
	return func(s *Service) { s.hasher.params = params }
}

// NewService returns a Service backed by store and restores the remembered
// sessions it holds.
func NewService(store AccountStore, opts ...Option) *Service {
	s := &Service{
		store:    store,
		now:      time.Now,
		hasher:   newPasswordHasher(),
		sessions: newSessionStore(store),
		limiter:  newLoginLimiter(),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.sessions.load(s.now())
	return s
}

// SetupRequired reports whether no admin account exists yet.
func (s *Service) SetupRequired() bool {
	_, exists := s.store.AdminAccount()
	return !exists
}

// Setup creates the admin account. It fails with domain.ErrSetupAlreadyDone
// when an account exists and with a *domain.ValidationError (fields
// "username", "password") for invalid credentials.
func (s *Service) Setup(username, password string) error {
	if !s.SetupRequired() {
		return fmt.Errorf("auth: setup: %w", domain.ErrSetupAlreadyDone)
	}
	if err := validateCredentials(username, password); err != nil {
		return err
	}
	encoded, err := s.hasher.hash(password)
	if err != nil {
		return fmt.Errorf("auth: setup: %w", err)
	}
	if err := s.store.CreateAdminAccount(domain.AdminAccount{Username: username, PasswordHash: encoded}); err != nil {
		return fmt.Errorf("auth: setup: %w", err)
	}
	s.sessions.dropAll()
	return nil
}

// Login checks the credentials and returns a new session token. listener
// selects the rate limits that apply; remember starts a "stay signed in"
// session (longer timeouts, kept across restarts). It fails with
// *RateLimitError, without checking the credentials, while clientIP or the
// remote listener is cooling down, and with *CredentialsError (matching
// ErrInvalidCredentials) for a wrong username or password; a wrong username
// and a wrong password cost the same password hash computation. Every
// failure, an internal error included, starts a cooldown for clientIP.
func (s *Service) Login(username, password, clientIP string, listener Listener, remember bool) (string, error) {
	if err := s.limiter.begin(clientIP, listener, s.now()); err != nil {
		return "", err
	}
	valid, err := s.checkCredentials(username, password)
	var retryAfter time.Duration
	if err != nil || !valid {
		retryAfter = s.limiter.failed(clientIP, listener, s.now())
	}
	if err != nil {
		return "", fmt.Errorf("auth: login: %w", err)
	}
	if !valid {
		return "", &CredentialsError{RetryAfter: retryAfter}
	}
	s.limiter.succeeded(clientIP, listener)
	token, err := s.sessions.create(username, clientIP, remember, s.now())
	if err != nil {
		return "", fmt.Errorf("auth: login: %w", err)
	}
	return token, nil
}

// Authenticate returns the username behind token and refreshes the
// session's idle timer. Sessions of a removed or replaced admin account are
// ended.
func (s *Service) Authenticate(token string) (string, bool) {
	username, ok := s.sessions.authenticate(token, s.now())
	if !ok {
		return "", false
	}
	account, exists := s.store.AdminAccount()
	if !exists || account.Username != username {
		if err := s.sessions.revoke(token); err != nil {
			slog.Warn("auth: end session of a replaced account", "error", err)
		}
		return "", false
	}
	return username, true
}

// Logout ends the session behind token, also in the store. Unknown tokens
// are ignored. On an error the session has ended in memory but may come
// back after a restart.
func (s *Service) Logout(token string) error {
	if err := s.sessions.revoke(token); err != nil {
		return fmt.Errorf("auth: logout: %w", err)
	}
	return nil
}

// LogoutEverywhere ends every session, remembered ones included.
func (s *Service) LogoutEverywhere() error {
	if err := s.sessions.revokeAll(); err != nil {
		return fmt.Errorf("auth: logout everywhere: %w", err)
	}
	return nil
}

// ResetAdmin ends all sessions and removes the admin account together with
// the remembered sessions, so the UI offers setup again. Profiles and
// settings are kept.
func (s *Service) ResetAdmin() error {
	s.sessions.dropAll()
	if err := s.store.RemoveAdminAccount(); err != nil {
		return fmt.Errorf("auth: reset admin: %w", err)
	}
	return nil
}

// checkCredentials always computes one password hash, also when no account
// exists or the username is wrong, so timing does not reveal usernames.
func (s *Service) checkCredentials(username, password string) (bool, error) {
	account, exists := s.store.AdminAccount()
	if !exists {
		s.hasher.matches(s.hasher.dummyHash(), password)
		return false, nil
	}
	stored, err := parsePasswordHash(account.PasswordHash)
	if err != nil {
		return false, err
	}
	usernameMatches := subtle.ConstantTimeCompare([]byte(username), []byte(account.Username)) == 1
	passwordMatches := s.hasher.matches(stored, password)
	return usernameMatches && passwordMatches, nil
}

// validateCredentials checks the setup rules. Messages never echo values.
func validateCredentials(username, password string) error {
	v := &domain.ValidationError{}
	if !validUsername(username) {
		v.AddIssue("username", domain.Issue("username_invalid", "min", strconv.Itoa(UsernameMinLength), "max", strconv.Itoa(UsernameMaxLength)), fmt.Sprintf("must be %d to %d characters: letters, digits, dot, underscore or hyphen",
			UsernameMinLength, UsernameMaxLength))
	}
	if length := utf8.RuneCountInString(password); length < PasswordMinLength || length > PasswordMaxLength {
		v.AddIssue("password", domain.Issue("length_between", "min", strconv.Itoa(PasswordMinLength), "max", strconv.Itoa(PasswordMaxLength)), fmt.Sprintf("must be between %d and %d characters", PasswordMinLength, PasswordMaxLength))
	}
	return v.OrNil()
}

func validUsername(username string) bool {
	if len(username) < UsernameMinLength || len(username) > UsernameMaxLength {
		return false
	}
	return !strings.ContainsFunc(username, func(r rune) bool { return !isUsernameRune(r) })
}

func isUsernameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	default:
		return r == '.' || r == '_' || r == '-'
	}
}
