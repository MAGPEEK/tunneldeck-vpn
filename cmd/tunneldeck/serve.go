package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"tunneldeck/internal/api"
	"tunneldeck/internal/auth"
	"tunneldeck/internal/config"
	"tunneldeck/internal/control"
	"tunneldeck/internal/devices"
	"tunneldeck/internal/domain"
	"tunneldeck/internal/netguard"
	"tunneldeck/internal/publicip"
	"tunneldeck/internal/remoteaccess"
	"tunneldeck/internal/secret"
	"tunneldeck/internal/store"
	"tunneldeck/internal/vpn"
	"tunneldeck/internal/vpn/ipsec"
	"tunneldeck/internal/vpn/openvpn"
	"tunneldeck/internal/vpn/wireguard"
	"tunneldeck/internal/web"
)

const (
	shutdownTimeout   = 10 * time.Second
	startTimeout      = 30 * time.Second
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 2 * time.Minute
)

// runtimeDir holds the control socket, next to the OpenVPN runtime files.
func runtimeDir() string {
	if runtime.GOOS == "linux" {
		return openvpn.DefaultRuntimeDir
	}
	return filepath.Join(os.TempDir(), "tunneldeck")
}

func controlSocketPath() string { return filepath.Join(runtimeDir(), control.SocketName) }

// host is what the server needs from the machine; tests replace it.
type host struct {
	runner      netguard.CommandRunner
	network     network
	controlPath string
	// sockets opens the HTTPS listener of remote access.
	sockets remoteaccess.SocketListener
	// now is the clock; nil means time.Now.
	now func() time.Time
}

// app is the wired server. Fields are set in startup order.
type app struct {
	cfg       config.Config
	host      host
	startedAt time.Time
	listen    string
	uiPort    int
	store     *store.Store
	auth      *auth.Service
	guard     *netguard.Guard
	checks    []api.CheckResult
	manager   *vpn.ConnectionManager
	remote    *remoteaccess.Manager
	api       *api.Server
	router    http.Handler
	control   *control.Server
	listener  net.Listener
	server    *http.Server
}

// serveCommand runs the server until ctx ends.
func serveCommand(ctx context.Context, cfg config.Config) error {
	a, err := startApp(ctx, cfg, host{
		runner: netguard.ExecRunner{}, network: systemNetwork{}, controlPath: controlSocketPath(), sockets: &net.ListenConfig{},
		now: time.Now,
	})
	if err != nil {
		return err
	}
	return a.run(ctx)
}

// startApp wires and starts everything up to the bound HTTP listener, in
// this order: listen address, key and store, admin reset, auth, host
// protection, drivers and connection manager, control socket, HTTP, and
// the HTTPS listener of remote access.
func startApp(ctx context.Context, cfg config.Config, h host) (*app, error) {
	if h.now == nil {
		h.now = time.Now
	}
	a := &app{cfg: cfg, host: h, startedAt: h.now().UTC()}
	steps := []func(context.Context) error{
		a.resolveListen, a.openStore, a.resetAdminFromEnv, a.protectHost, a.startManager, a.listenControl, a.listenHTTP,
		a.startRemoteAccess,
	}
	for _, step := range steps {
		if err := step(ctx); err != nil {
			return nil, errors.Join(err, a.shutdown())
		}
	}
	return a, nil
}

func (a *app) resolveListen(context.Context) error {
	listen, err := resolveListenAddress(a.cfg.Listen, runtime.GOOS, a.host.network)
	if err != nil {
		return err
	}
	if a.uiPort, err = config.ListenPort(listen); err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	a.listen = listen
	return nil
}

func (a *app) openStore(context.Context) error {
	st, err := openStore(a.cfg)
	if err != nil {
		return err
	}
	a.store = st
	a.auth = auth.NewService(st)
	return nil
}

func openStore(cfg config.Config) (*store.Store, error) {
	key, err := secret.LoadOrCreateKey(cfg.DataDir, cfg.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("load secret key: %w", err)
	}
	cipher, err := secret.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	return store.Open(cfg.DataDir, cipher)
}

func (a *app) resetAdminFromEnv(context.Context) error {
	if !a.cfg.ResetAdmin {
		return nil
	}
	slog.Warn(config.EnvResetAdmin + " is set: the admin account is removed at every start until the variable is removed")
	if err := a.auth.ResetAdmin(); err != nil {
		return fmt.Errorf("reset admin: %w", err)
	}
	return nil
}

// protectHost runs the self-check and installs the firewall. Failures are
// logged and shown on the System page; the server keeps running, and the
// connection manager refuses to connect without the firewall.
func (a *app) protectHost(ctx context.Context) error {
	a.guard = netguard.New(a.host.runner, netguard.WithBackend(netguard.BackendPreference(a.cfg.Iptables)))
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	results := a.guard.SelfCheck(ctx)
	for _, r := range results {
		if !r.OK {
			slog.Warn("self-check failed", "check", r.ID, "detail", r.Detail, "hint", r.Hint)
		}
	}
	a.checks = toCheckResults(results)
	logBackend(a.guard)
	if err := a.guard.InstallFirewall(ctx, a.store.Firewall(), a.uiPort); err != nil {
		slog.Error("install firewall; connecting is refused until it works", "error", err)
	}
	return nil
}

// logBackend logs the detected iptables backend and why it was chosen; a
// host whose firewall uses both backends gets a warning.
func logBackend(guard *netguard.Guard) {
	backend, ok := guard.Backend()
	if !ok {
		return
	}
	if backend.Mixed {
		slog.Warn("iptables backend: the host has rules in both backends", "binary", backend.Binary, "reason", backend.Reason)
		return
	}
	slog.Info("iptables backend", "binary", backend.Binary, "reason", backend.Reason)
}

func (a *app) startManager(ctx context.Context) error {
	registry, err := a.drivers()
	if err != nil {
		return err
	}
	a.manager = vpn.NewConnectionManager(vpn.ManagerConfig{
		Registry: registry, Profiles: a.store, Desired: a.store, Firewall: a.store, Guard: a.guard, UIPort: a.uiPort,
		PublicIP: publicip.NewFinder(a.store),
	})
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	if err := a.manager.Start(ctx); err != nil {
		slog.Error("restore the desired connection", "error", err)
	}
	// The HTTPS listener serves the router built below; it starts serving
	// only in startRemoteAccess, after a.router is set.
	a.remote = remoteaccess.New(remoteaccess.Config{
		Handler:  api.SecureListener(http.HandlerFunc(a.serveRouter)),
		KeyPairs: a.store, Firewall: a.guard, Listener: a.host.sockets,
		ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: idleTimeout,
	})
	a.api = api.New(a.apiDeps(registry), api.Options{})
	a.router = newRouter(a.api, web.Handler())
	return nil
}

// drivers registers the VPN drivers; each creates the tunnel device
// netguard guards.
func (a *app) drivers() (*vpn.Registry, error) {
	registry := vpn.NewRegistry()
	factories := map[domain.Protocol]vpn.Factory{
		domain.ProtocolOpenVPN: openvpn.Factory(openvpn.Options{DeviceName: netguard.DeviceName, LANSubnets: a.guard.LANSubnets}),
		domain.ProtocolWireGuard: wireguard.Factory(wireguard.Options{
			DeviceName: netguard.DeviceName, Runner: a.host.runner, LANSubnets: a.guard.LANSubnets,
		}),
		domain.ProtocolIPsec: ipsec.Factory(ipsec.Options{
			DeviceName: netguard.DeviceName, Runner: a.host.runner, LANSubnets: a.guard.LANSubnets,
		}),
	}
	for protocol, factory := range factories {
		if err := registry.Register(protocol, factory); err != nil {
			return nil, fmt.Errorf("register drivers: %w", err)
		}
	}
	return registry, nil
}

// apiDeps wires the API; one api.Server serves both listeners.
func (a *app) apiDeps(registry *vpn.Registry) api.Deps {
	return api.Deps{
		Auth: authAdapter{a.auth}, Cookies: sessionCookies{}, Profiles: a.store, Drivers: registry,
		Importer: profileImporter{}, Connection: a.manager, FirewallStore: a.store, Firewall: a.guard,
		Devices: devices.New(a.guard, net.DefaultResolver, time.Now),
		System: api.System{
			Version: version, ListenAddress: a.listen, UIPort: a.uiPort, TimeZone: a.cfg.TimeZone,
			Checks:    func() []api.CheckResult { return a.checks },
			StartedAt: a.startedAt,
		},
		RemoteAccess: a.store, RemoteAccessListener: a.remote,
		PublicIPLookup: a.store,
	}
}

func (a *app) serveRouter(w http.ResponseWriter, r *http.Request) { a.router.ServeHTTP(w, r) }

// listenControl opens the control socket for "tunneldeck reset-admin". A
// failure is logged; the server works without it.
func (a *app) listenControl(context.Context) error {
	server, err := control.Listen(a.host.controlPath, map[string]control.Handler{
		control.CommandResetAdmin: a.auth.ResetAdmin,
	})
	if err != nil {
		slog.Error("open control socket; reset-admin then edits the store directly", "error", err)
		return nil
	}
	a.control = server
	return nil
}

func (a *app) listenHTTP(context.Context) error {
	listener, err := net.Listen("tcp4", a.listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", a.listen, err)
	}
	a.listener = listener
	a.server = &http.Server{
		Handler:           a.router,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	a.server.RegisterOnShutdown(a.api.CloseStreams)
	return nil
}

// startRemoteAccess starts the HTTPS listener when remote access is on; it
// runs after the firewall install. A failure is logged and reported on the
// remote-access page; the server keeps running.
func (a *app) startRemoteAccess(ctx context.Context) error {
	settings := a.store.RemoteAccess()
	if !settings.Enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	if err := a.remote.Apply(ctx, settings); err != nil {
		slog.Error("start remote access", "error", err)
	}
	return nil
}

func newRouter(apiHandler, spa http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/", spa)
	return mux
}

// run serves HTTP until ctx ends or serving fails, then shuts down.
func (a *app) run(ctx context.Context) error {
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("listening", "address", a.listener.Addr().String(), "version", version)
		serveErr <- a.server.Serve(a.listener)
	}()
	var err error
	select {
	case err = <-serveErr:
		err = fmt.Errorf("serve http: %w", err)
	case <-ctx.Done():
	}
	return errors.Join(err, a.shutdown())
}

// shutdown stops HTTPS, HTTP, the tunnel, the firewall and the control
// socket, in that order. Event streams are ended first so neither listener
// waits for them. Parts that were never started are skipped.
func (a *app) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var errs []error
	if a.api != nil {
		a.api.CloseStreams()
	}
	if a.remote != nil {
		if err := a.remote.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shut down remote access: %w", err))
		}
	}
	if a.server != nil {
		if err := a.server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shut down http server: %w", err))
		}
	} else if a.listener != nil {
		_ = a.listener.Close()
	}
	if a.manager != nil {
		if err := a.manager.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shut down connection manager: %w", err))
		}
	}
	if a.guard != nil {
		if err := a.guard.RemoveFirewall(ctx); err != nil {
			slog.Warn("remove firewall", "error", err)
		}
	}
	if a.control != nil {
		if err := a.control.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close control socket: %w", err))
		}
	}
	return errors.Join(errs...)
}
