package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
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

// ErrRateLimited is matched by every *RateLimitError.
var ErrRateLimited = errors.New("too many failed logins")

// RateLimitError reports a login refused because the client is locked out.
type RateLimitError struct {
	// RetryAfter is the remaining lockout.
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s, retry after %s", ErrRateLimited, e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool {
	return target == ErrRateLimited
}

// AccountStore persists the single admin account. *store.Store satisfies it.
type AccountStore interface {
	AdminAccount() (domain.AdminAccount, bool)
	// CreateAdminAccount fails with domain.ErrSetupAlreadyDone when an
	// account exists.
	CreateAdminAccount(account domain.AdminAccount) error
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

// NewService returns a Service backed by store.
func NewService(store AccountStore, opts ...Option) *Service {
	s := &Service{
		store:    store,
		now:      time.Now,
		hasher:   newPasswordHasher(),
		sessions: newSessionStore(),
		limiter:  newLoginLimiter(),
	}
	for _, opt := range opts {
		opt(s)
	}
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
	return nil
}

// Login checks the credentials and returns a new session token. It fails
// with *RateLimitError while clientIP is locked out and with
// ErrInvalidCredentials for a wrong username or password; both cases cost
// the same password hash computation.
func (s *Service) Login(username, password, clientIP string) (string, error) {
	if retryAfter, allowed := s.limiter.begin(clientIP, s.now()); !allowed {
		return "", &RateLimitError{RetryAfter: retryAfter}
	}
	valid, err := s.checkCredentials(username, password)
	if err != nil {
		return "", fmt.Errorf("auth: login: %w", err)
	}
	if !valid {
		return "", ErrInvalidCredentials
	}
	s.limiter.succeeded(clientIP)
	token, err := s.sessions.create(username, s.now())
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
		s.sessions.revoke(token)
		return "", false
	}
	return username, true
}

// Logout ends the session behind token. Unknown tokens are ignored.
func (s *Service) Logout(token string) {
	s.sessions.revoke(token)
}

// ResetAdmin ends all sessions and removes the admin account, so the UI
// offers setup again. Profiles and settings are kept.
func (s *Service) ResetAdmin() error {
	s.sessions.revokeAll()
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
		v.Add("username", fmt.Sprintf("must be %d to %d characters: letters, digits, dot, underscore or hyphen",
			UsernameMinLength, UsernameMaxLength))
	}
	if length := utf8.RuneCountInString(password); length < PasswordMinLength || length > PasswordMaxLength {
		v.Add("password", fmt.Sprintf("must be between %d and %d characters", PasswordMinLength, PasswordMaxLength))
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
