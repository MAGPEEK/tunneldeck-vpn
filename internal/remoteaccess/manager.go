package remoteaccess

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tunneldeck/internal/domain"
)

const (
	// network and listenHost: the HTTPS listener serves IPv4 on every
	// interface, so it is reachable on the VPN address (SPEC §8.1).
	network    = "tcp4"
	listenHost = "0.0.0.0"
	// renewalInterval is how often the self-signed certificate is checked.
	renewalInterval = 24 * time.Hour
	// retireTimeout bounds how long a replaced or stopped server may finish
	// its open requests.
	retireTimeout = 5 * time.Second

	defaultReadHeaderTimeout = 10 * time.Second
	defaultIdleTimeout       = 2 * time.Minute
)

// Errors returned by the Manager.
var (
	// ErrNoCertificate reports that the uploaded source was chosen before a
	// certificate was uploaded.
	ErrNoCertificate = errors.New("no certificate has been uploaded")
	// ErrClosed reports a call after Shutdown.
	ErrClosed = errors.New("remote access is shut down")
)

// KeyPairs stores the certificates; *store.Store implements it.
type KeyPairs interface {
	RemoteAccessKeyPair(source domain.CertificateSource) (domain.KeyPair, bool, error)
	SetRemoteAccessKeyPair(source domain.CertificateSource, pair domain.KeyPair) error
}

// Firewall lets tunnel traffic reach the HTTPS port (0 closes it);
// *netguard.Guard implements it.
type Firewall interface {
	SetRemoteAccessPort(ctx context.Context, port int) error
}

// SocketListener opens listening sockets; *net.ListenConfig implements it.
type SocketListener interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
}

// Clock is the time source of the renewal check; tests inject a fake one.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f once d has elapsed; stop cancels a pending call.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

// Config wires a Manager. Handler, KeyPairs and Firewall are required.
type Config struct {
	// Handler serves every request of the HTTPS listener.
	Handler  http.Handler
	KeyPairs KeyPairs
	Firewall Firewall
	// Listener defaults to a net.ListenConfig.
	Listener SocketListener
	// Clock defaults to the system clock.
	Clock Clock
	// ReadHeaderTimeout and IdleTimeout default to 10 s and 2 min.
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
}

// Status is the state of the HTTPS listener.
type Status struct {
	Listening bool
	// LastError describes the last failed apply or renewal, "" after a
	// successful apply.
	LastError string
}

// Manager owns the HTTPS listener: Apply starts, stops or moves it, the
// certificate is swapped without a restart, and a self-signed certificate
// is renewed 30 days before expiry (checked on Apply and daily). It is safe
// for concurrent use.
type Manager struct {
	cfg         Config
	certificate atomic.Pointer[tls.Certificate]
	wg          sync.WaitGroup // serve and retire goroutines

	mu          sync.Mutex
	active      *activeServer            // nil while not listening
	source      domain.CertificateSource // source of the served certificate
	lastError   string
	stopRenewal func() bool
	closed      bool
}

type activeServer struct {
	server   *http.Server
	listener net.Listener
	port     int
}

// New returns a Manager that does not listen until Apply enables it.
func New(cfg Config) *Manager {
	if cfg.Listener == nil {
		cfg.Listener = &net.ListenConfig{}
	}
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	return &Manager{cfg: cfg}
}

// Apply makes the listener match settings: it starts, stops or moves the
// listener, opens or closes the port in the firewall and loads the
// certificate of the chosen source, generating or renewing a self-signed
// one. On failure the listener keeps serving as before where possible; a
// failed disable still stops the listener.
func (m *Manager) Apply(ctx context.Context, settings domain.RemoteAccess) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	err := m.apply(ctx, settings)
	m.lastError = errorText(err)
	m.scheduleRenewal()
	return err
}

// Status reports whether the listener runs and the last error.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{Listening: m.active != nil, LastError: m.lastError}
}

// Shutdown stops the listener, waiting for open requests until ctx ends.
// The firewall is left to its owner. Apply fails afterwards.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	m.scheduleRenewal()
	active := m.active
	m.active = nil
	m.mu.Unlock()
	var err error
	if active != nil {
		_ = active.listener.Close()
		if shutdownErr := active.server.Shutdown(ctx); shutdownErr != nil {
			_ = active.server.Close()
			err = fmt.Errorf("shut down the https listener: %w", shutdownErr)
		}
	}
	m.wg.Wait()
	return err
}

func (m *Manager) apply(ctx context.Context, settings domain.RemoteAccess) error {
	if !settings.Enabled {
		return m.disable(ctx)
	}
	certificate, err := m.loadCertificate(settings.CertificateSource)
	if err != nil {
		return fmt.Errorf("load the %s certificate: %w", settings.CertificateSource, err)
	}
	if m.active != nil && m.active.port == settings.Port {
		if err := m.openFirewall(ctx, settings.Port); err != nil {
			return err
		}
		m.certificate.Store(certificate)
		m.source = settings.CertificateSource
		return nil
	}
	return m.listen(ctx, settings, certificate)
}

// listen binds the new port, opens it in the firewall and only then
// replaces the running server, so a failure leaves the old one serving.
func (m *Manager) listen(ctx context.Context, settings domain.RemoteAccess, certificate *tls.Certificate) error {
	address := net.JoinHostPort(listenHost, strconv.Itoa(settings.Port))
	listener, err := m.cfg.Listener.Listen(ctx, network, address)
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", settings.Port, err)
	}
	if err := m.openFirewall(ctx, settings.Port); err != nil {
		_ = listener.Close()
		m.restoreFirewall(ctx)
		return err
	}
	m.certificate.Store(certificate)
	m.source = settings.CertificateSource
	previous := m.active
	m.active = m.serve(listener, settings.Port)
	if previous != nil {
		m.retire(previous)
	}
	slog.Info("remote access listening", "address", listener.Addr().String())
	return nil
}

// disable closes the port in the firewall and stops the listener, also when
// the firewall fails, so nothing keeps serving that should not.
func (m *Manager) disable(ctx context.Context) error {
	err := m.cfg.Firewall.SetRemoteAccessPort(ctx, 0)
	if m.active != nil {
		m.retire(m.active)
		m.active = nil
		slog.Info("remote access stopped")
	}
	if err != nil {
		return fmt.Errorf("close the remote-access port in the firewall: %w", err)
	}
	return nil
}

func (m *Manager) openFirewall(ctx context.Context, port int) error {
	if err := m.cfg.Firewall.SetRemoteAccessPort(ctx, port); err != nil {
		return fmt.Errorf("open port %d in the firewall: %w", port, err)
	}
	return nil
}

// restoreFirewall points the firewall back at the port still served, after
// a failed move.
func (m *Manager) restoreFirewall(ctx context.Context) {
	port := 0
	if m.active != nil {
		port = m.active.port
	}
	if err := m.cfg.Firewall.SetRemoteAccessPort(ctx, port); err != nil {
		slog.Error("restore the remote-access port in the firewall", "error", err)
	}
}

func (m *Manager) serve(listener net.Listener, port int) *activeServer {
	active := &activeServer{
		server: &http.Server{
			Handler: m.cfg.Handler,
			TLSConfig: &tls.Config{
				MinVersion:     tls.VersionTLS12,
				GetCertificate: m.getCertificate,
			},
			ReadHeaderTimeout: m.cfg.ReadHeaderTimeout,
			IdleTimeout:       m.cfg.IdleTimeout,
			ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
		},
		listener: &closeOnceListener{Listener: listener},
		port:     port,
	}
	m.wg.Go(func() {
		m.served(active, active.server.ServeTLS(active.listener, "", ""))
	})
	return active
}

// served handles the end of ServeTLS: an unexpected end marks the listener
// as stopped.
func (m *Manager) served(active *activeServer, err error) {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return
	}
	slog.Error("remote access listener stopped", "error", err)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == active {
		m.active = nil
		m.lastError = fmt.Sprintf("the HTTPS listener stopped: %v", err)
	}
}

// retire closes the listener at once, freeing the port, and lets open
// requests finish in the background. The caller holds m.mu.
func (m *Manager) retire(active *activeServer) {
	_ = active.listener.Close()
	m.wg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), retireTimeout)
		defer cancel()
		if err := active.server.Shutdown(ctx); err != nil {
			_ = active.server.Close()
		}
	})
}

func (m *Manager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.certificate.Load(), nil
}

// loadCertificate reads the certificate of source from the store. A
// missing, unreadable or expiring self-signed certificate is replaced by a
// new one first.
func (m *Manager) loadCertificate(source domain.CertificateSource) (*tls.Certificate, error) {
	pair, ok, err := m.cfg.KeyPairs.RemoteAccessKeyPair(source)
	if err != nil {
		return nil, err
	}
	switch {
	case source == domain.CertificateSelfSigned && (!ok || m.selfSignedDue(pair)):
		if pair, err = m.renewSelfSigned(); err != nil {
			return nil, err
		}
	case !ok:
		return nil, ErrNoCertificate
	}
	certificate, err := tls.X509KeyPair([]byte(pair.CertificatePEM), []byte(pair.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}
	return &certificate, nil
}

func (m *Manager) selfSignedDue(pair domain.KeyPair) bool {
	info, err := Describe(pair.CertificatePEM)
	return err != nil || info.NeedsRenewal(m.cfg.Clock.Now())
}

func (m *Manager) renewSelfSigned() (domain.KeyPair, error) {
	pair, err := GenerateSelfSigned(m.cfg.Clock.Now())
	if err != nil {
		return domain.KeyPair{}, fmt.Errorf("generate a self-signed certificate: %w", err)
	}
	if err := m.cfg.KeyPairs.SetRemoteAccessKeyPair(domain.CertificateSelfSigned, pair); err != nil {
		return domain.KeyPair{}, fmt.Errorf("store the self-signed certificate: %w", err)
	}
	if info, err := Describe(pair.CertificatePEM); err == nil {
		slog.Info("generated a self-signed certificate", "notAfter", info.NotAfter, "fingerprintSha256", info.FingerprintSHA256)
	}
	return pair, nil
}

// scheduleRenewal replaces the pending renewal check by one in a day while
// the listener runs. The caller holds m.mu.
func (m *Manager) scheduleRenewal() {
	if m.stopRenewal != nil {
		m.stopRenewal()
		m.stopRenewal = nil
	}
	if m.active != nil && !m.closed {
		m.stopRenewal = m.cfg.Clock.AfterFunc(renewalInterval, m.checkRenewal)
	}
}

// checkRenewal renews a due self-signed certificate of the running
// listener and swaps it in without a restart.
func (m *Manager) checkRenewal() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.active == nil {
		return
	}
	if m.source == domain.CertificateSelfSigned {
		certificate, err := m.loadCertificate(m.source)
		if err != nil {
			slog.Error("renew the self-signed certificate", "error", err)
			m.lastError = fmt.Sprintf("renew the self-signed certificate: %v", err)
		} else {
			m.certificate.Store(certificate)
		}
	}
	m.scheduleRenewal()
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// closeOnceListener lets the Manager free the port before http.Server
// closes the listener again during Shutdown.
type closeOnceListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *closeOnceListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}

// systemClock is the Clock of the running application.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}
