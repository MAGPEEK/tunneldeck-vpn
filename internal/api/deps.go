package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/remoteaccess"
	"tunneldeck/internal/vpn"
)

// ErrInvalidCredentials is returned by Auth.Login for a wrong username or
// password.
var ErrInvalidCredentials = errors.New("invalid username or password")

// RateLimitError is returned by Auth.Login while the client is locked out.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("too many failed logins, retry after %s", e.RetryAfter)
}

// LoginClient describes who attempts a login.
type LoginClient struct {
	IP string
	// Remote is true for a client outside the private, loopback and
	// link-local ranges on the HTTPS listener; it gets the stricter login
	// limit (SPEC §8.1).
	Remote bool
}

// Auth manages the admin account and sessions.
type Auth interface {
	SetupRequired() bool
	// Setup fails with domain.ErrSetupAlreadyDone or a
	// *domain.ValidationError.
	Setup(username, password string) error
	// Login returns a session token. It fails with ErrInvalidCredentials or
	// *RateLimitError.
	Login(username, password string, client LoginClient) (token string, err error)
	Authenticate(token string) (username string, ok bool)
	Logout(token string)
}

// SessionCookies carries the session token between client and server.
// secure is true on the HTTPS listener.
type SessionCookies interface {
	Set(w http.ResponseWriter, token string, secure bool)
	Clear(w http.ResponseWriter, secure bool)
	Token(r *http.Request) string
}

// Profiles persists profiles. Errors wrap domain.ErrNotFound,
// domain.ErrConflict or are a *domain.ValidationError.
type Profiles interface {
	ListProfiles() []domain.PublicProfile
	GetProfile(id string) (domain.PublicProfile, error)
	ProfileWithSecrets(id string) (domain.Profile, error)
	CreateProfile(p domain.Profile) (domain.PublicProfile, error)
	UpdateProfile(p domain.Profile, clearSecrets []string) (domain.PublicProfile, error)
	DeleteProfile(id string) error
}

// Drivers lists the VPN drivers; *vpn.Registry implements it.
type Drivers interface {
	Protocols() []domain.Protocol
	Lookup(protocol domain.Protocol) (vpn.Factory, error)
}

// ImportWarning reports a line of an imported file that was dropped,
// rejected or mapped.
type ImportWarning struct {
	Code      string `json:"code"`
	Severity  string `json:"severity"`
	Directive string `json:"directive,omitempty"`
	Line      int    `json:"line,omitempty"`
	Message   string `json:"message"`
}

// ImportDraft is a profile parsed from a configuration file. It is not
// saved; Secrets go back to the same client only.
type ImportDraft struct {
	Settings domain.Settings
	Secrets  map[string]string
	Warnings []ImportWarning
}

// Importer parses configuration files of a protocol. An unknown protocol
// yields an error wrapping domain.ErrNotFound; unparseable text a
// *domain.ValidationError.
type Importer interface {
	Import(protocol domain.Protocol, text string) (ImportDraft, error)
}

// Connection controls the single tunnel; *vpn.ConnectionManager
// implements it.
type Connection interface {
	Connect(ctx context.Context, profileID string) error
	Disconnect(ctx context.Context) error
	Reconnect(ctx context.Context) error
	ProfileChanged(id string)
	Status() vpn.Status
	Logs(tail int) []domain.LogEvent
	Subscribe() (<-chan domain.Event, func())
}

// FirewallStore persists the firewall settings and rules; *store.Store
// implements it. SetFirewall fails with a *domain.ValidationError.
type FirewallStore interface {
	Firewall() domain.Firewall
	SetFirewall(firewall domain.Firewall) (domain.Firewall, error)
}

// Firewall applies the firewall; *netguard.Guard implements it.
type Firewall interface {
	InstallFirewall(ctx context.Context, firewall domain.Firewall, uiPort int) error
}

// RemoteAccessSettings persists the remote-access setting and its
// certificates; *store.Store implements it. Nothing here returns a key.
type RemoteAccessSettings interface {
	RemoteAccess() domain.RemoteAccess
	SetRemoteAccess(settings domain.RemoteAccess) error
	// RemoteAccessCertificate returns the PEM chain stored for source.
	RemoteAccessCertificate(source domain.CertificateSource) (certificatePEM string, ok bool)
	SetRemoteAccessKeyPair(source domain.CertificateSource, pair domain.KeyPair) error
}

// RemoteAccessListener runs the HTTPS listener; *remoteaccess.Manager
// implements it.
type RemoteAccessListener interface {
	// Apply starts, stops or moves the listener and opens its port in the
	// firewall.
	Apply(ctx context.Context, settings domain.RemoteAccess) error
	Status() remoteaccess.Status
}

// CheckResult is one line of the startup self-check.
type CheckResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

// System describes the running server.
type System struct {
	Version       string
	ListenAddress string
	// UIPort is the port of the web UI, which a host-access rule never
	// opens.
	UIPort int
	// TimeZone names the server's time zone, for example "Europe/Berlin".
	TimeZone string
	// Checks returns the self-check results.
	Checks func() []CheckResult
}
