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
	"tunneldeck/internal/domain"
	"tunneldeck/internal/netguard"
	"tunneldeck/internal/secret"
	"tunneldeck/internal/store"
	"tunneldeck/internal/vpn"
	"tunneldeck/internal/vpn/openvpn"
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
}

// app is the wired server. Fields are set in startup order.
type app struct {
	cfg      config.Config
	host     host
	listen   string
	uiPort   int
	store    *store.Store
	auth     *auth.Service
	guard    *netguard.Guard
	checks   []api.CheckResult
	manager  *vpn.ConnectionManager
	control  *control.Server
	api      *api.Server
	listener net.Listener
	server   *http.Server
}

// serveCommand runs the server until ctx ends.
func serveCommand(ctx context.Context, cfg config.Config) error {
	a, err := startApp(ctx, cfg, host{runner: netguard.ExecRunner{}, network: systemNetwork{}, controlPath: controlSocketPath()})
	if err != nil {
		return err
	}
	return a.run(ctx)
}

// startApp wires and starts everything up to the bound HTTP listener, in
// this order: listen address, key and store, admin reset, auth, host
// protection, drivers and connection manager, control socket, HTTP.
func startApp(ctx context.Context, cfg config.Config, h host) (*app, error) {
	a := &app{cfg: cfg, host: h}
	steps := []func(context.Context) error{
		a.resolveListen, a.openStore, a.resetAdminFromEnv, a.protectHost, a.startManager, a.listenControl, a.listenHTTP,
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
	a.guard = netguard.New(a.host.runner)
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	results := a.guard.SelfCheck(ctx)
	for _, r := range results {
		if !r.OK {
			slog.Warn("self-check failed", "check", r.ID, "detail", r.Detail, "hint", r.Hint)
		}
	}
	a.checks = toCheckResults(results)
	if err := a.guard.InstallFirewall(ctx, a.store.HostAccessRules(), a.uiPort); err != nil {
		slog.Error("install firewall; connecting is refused until it works", "error", err)
	}
	return nil
}

func (a *app) startManager(ctx context.Context) error {
	registry := vpn.NewRegistry()
	factory := openvpn.Factory(openvpn.Options{DeviceName: netguard.DeviceName})
	if err := registry.Register(domain.ProtocolOpenVPN, factory); err != nil {
		return fmt.Errorf("register drivers: %w", err)
	}
	a.manager = vpn.NewConnectionManager(vpn.ManagerConfig{
		Registry: registry, Profiles: a.store, Desired: a.store, HostAccess: a.store, Guard: a.guard, UIPort: a.uiPort,
	})
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	if err := a.manager.Start(ctx); err != nil {
		slog.Error("restore the desired connection", "error", err)
	}
	a.api = api.New(a.apiDeps(registry, sessionCookies{secure: false}), api.Options{})
	return nil
}

// apiDeps wires the API for one listener; a second (HTTPS) listener gets
// its own api.Server with secure cookies.
func (a *app) apiDeps(registry *vpn.Registry, cookies api.SessionCookies) api.Deps {
	return api.Deps{
		Auth: authAdapter{a.auth}, Cookies: cookies, Profiles: a.store, Drivers: registry,
		Importer: profileImporter{}, Connection: a.manager, HostAccess: a.store, Firewall: a.guard,
		System: api.System{
			Version: version, ListenAddress: a.listen, UIPort: a.uiPort, TimeZone: a.cfg.TimeZone,
			Checks: func() []api.CheckResult { return a.checks },
		},
	}
}

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
		Handler:           newRouter(a.api, web.Handler()),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	a.server.RegisterOnShutdown(a.api.CloseStreams)
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

// shutdown stops HTTP, the tunnel, the firewall and the control socket, in
// that order. Parts that were never started are skipped.
func (a *app) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var errs []error
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
