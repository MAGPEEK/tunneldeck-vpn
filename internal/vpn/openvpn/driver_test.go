package openvpn

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// The lab password of docs/openvpn-notes.md and the line it must become.
const (
	trickyPassword     = `p a"s\s'w#rd;$x`
	trickyPasswordLine = `password "Auth" "p a\"s\\s'w#rd;$x"`
	usernameLine       = `username "Auth" "tduser"`
)

func TestDriverHappyPath(t *testing.T) {
	h := newDriverHarness(t, true)
	h.start(newProfile(t, mdexSettings(), nil), vpn.Secrets{SecretPassword: trickyPassword})

	name, args, config := h.starter.commandLine()
	if name != DefaultBinary || !slices.Equal(args, []string{"--config", testConfigPath}) {
		t.Errorf("command line = %s %v, want openvpn --config %s", name, args, testConfigPath)
	}
	if config.mode != 0o600 || !strings.Contains(config.data, "management /run/tunneldeck/mgmt.sock unix") ||
		!strings.Contains(config.data, "dev tdvpn0") {
		t.Errorf("config at spawn: mode %v, content\n%s", config.mode, config.data)
	}
	if strings.Contains(config.data, "w#rd") {
		t.Error("the password was written into the config file")
	}
	if mode := h.fs.dirs[testRuntimeDir]; mode != 0o700 {
		t.Errorf("runtime directory mode = %v, want 0700", mode)
	}
	h.events.waitLog(t, domain.LogLevelWarn, `extra option "redirect-gateway" dropped`)

	h.process.print(t, "2026-11-25 18:52:23 WARNING: cipher 'none' specified for --data-ciphers.")
	h.events.waitLog(t, domain.LogLevelWarn, "WARNING: cipher 'none' specified for --data-ciphers.")
	h.events.waitLog(t, domain.LogLevelInfo, "come from the profile setting Cipher = none")

	server := acceptManagement(t, h.dialer)
	if got := h.dialer.dialedPath(); got != testSocketPath {
		t.Errorf("dialed %q, want %q", got, testSocketPath)
	}
	server.handshake()
	server.login(usernameLine, trickyPasswordLine)
	server.send(
		">LOG:1795632744,W,WARNING: this configuration may cache passwords in memory",
		">LOG:1795632744,,Control Channel: TLSv1.3, cipher TLSv1.3 TLS_CHACHA20_POLY1305_SHA256, peer certificate: 384 bits ECsecp384r1, signature: ecdsa-with-SHA384",
		">LOG:1795632744,W,******* WARNING *******: '--cipher none' was specified.",
		">LOG:1795632744,,Data Channel: cipher '[null-cipher]', auth '[null-digest]', peer-id: 0",
		">STATE:1795632744,CONNECTED,SUCCESS,10.66.0.2,172.20.0.2,1194,,",
		">BYTECOUNT:4172,2327",
	)
	h.events.waitLog(t, domain.LogLevelInfo, "may cache passwords in memory")
	h.events.waitFor(t, "control channel", func(e domain.Event) bool {
		return e == domain.ChannelEvent{ControlChannel: "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256"}
	})
	h.events.waitFor(t, "data cipher", func(e domain.Event) bool { return e == domain.ChannelEvent{DataCipher: "none"} })
	connected := h.events.waitState(t, domain.StateConnected)
	if connected.VPNIP != "10.66.0.2" || connected.Remote != "172.20.0.2:1194" {
		t.Errorf("connected event = %+v", connected)
	}
	h.events.waitFor(t, "traffic", func(e domain.Event) bool {
		return e == domain.TrafficEvent{BytesIn: 4172, BytesOut: 2327}
	})
	h.process.print(t, "2026-11-25 18:52:24 Initialization Sequence Completed")

	stopped := h.stopAsync(context.Background())
	server.expect("signal SIGTERM")
	server.send(
		"SUCCESS: signal SIGTERM thrown",
		">LOG:1795632746,I,SIGTERM[soft,exit-with-notification] received, process exiting",
		">STATE:1795632746,EXITING,exit-with-notification,,,,,",
	)
	server.close()
	h.process.exit(nil)
	if err := h.awaitStop(stopped); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	events := h.events.waitClosed(t)
	if last := lastState(t, events); last.State != domain.StateDisconnected || last.Code != "" {
		t.Errorf("last state = %+v, want disconnected", last)
	}
	assertNoEventContains(t, events, "tduser", "w#rd", "Initialization Sequence Completed")
	if notes := countLogs(events, cipherNoneNote); notes != 1 {
		t.Errorf("the cipher note was logged %d times, want once per process", notes)
	}
	h.assertFilesRemoved()
}

func countLogs(events []domain.Event, text string) int {
	n := 0
	for _, e := range events {
		if line, ok := e.(domain.LogEvent); ok && line.Text == text {
			n++
		}
	}
	return n
}

func TestDriverRejections(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantCode    domain.ErrorCode
		wantMessage string
	}{
		{
			name: "wrong credentials", line: ">PASSWORD:Verification Failed: 'Auth'",
			wantCode: domain.ErrorCodeAuthFailed, wantMessage: "rejected the username or password",
		},
		{
			name:     "server rejection with reason",
			line:     ">PASSWORD:Verification Failed: 'Auth' ['Data channel cipher negotiation failed (no shared cipher)']",
			wantCode: domain.ErrorCodeServerRejected, wantMessage: "no shared cipher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newDriverHarness(t, true)
			server := h.startMdex("wrong")
			server.login(usernameLine, `password "Auth" "wrong"`)
			server.send(
				">LOG:1795632744,,AUTH: Received control message: AUTH_FAILED",
				tt.line,
				">STATE:1795632746,EXITING,exit-with-notification,,,,,",
			)
			h.events.waitLog(t, domain.LogLevelError, tt.wantMessage)
			server.close()
			h.process.exit(nil) // exit code 0, as in the lab
			last := lastState(t, h.events.waitClosed(t))
			if last.State != domain.StateError || last.Code != tt.wantCode || !strings.Contains(last.Message, tt.wantMessage) {
				t.Errorf("last state = %+v, want error %s", last, tt.wantCode)
			}
			h.assertFilesRemoved()
		})
	}
}

func TestDriverTemporaryRejectionAndInternalReconnect(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	server.login(usernameLine, `password "Auth" "secret"`)
	server.send(
		">PASSWORD:Verification Failed: 'Auth' ['TEMP[backoff 5]: try again']",
		">STATE:1795632745,RECONNECTING,auth-failure,,,,,",
		">HOLD:Waiting for hold release:2",
	)
	h.events.waitLog(t, domain.LogLevelWarn, "temporary authentication failure")
	if e := h.events.waitState(t, domain.StateReconnecting); e.Message != "auth-failure" {
		t.Errorf("reconnecting message = %q, want auth-failure", e.Message)
	}
	h.clock.WaitForTimers(t, 1)
	if pending := h.clock.Pending(); !slices.Equal(pending, []time.Duration{2 * time.Second}) {
		t.Fatalf("pending timers = %v, want the 2s hold delay", pending)
	}
	h.clock.Advance(2 * time.Second)
	server.expect("hold release")
	server.send("SUCCESS: hold release succeeded")
	server.login(usernameLine, `password "Auth" "secret"`)

	stopped := h.stopAsync(context.Background())
	server.expect("signal SIGTERM")
	server.close()
	h.process.exit(nil)
	if err := h.awaitStop(stopped); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if last := lastState(t, h.events.waitClosed(t)); last.State != domain.StateDisconnected {
		t.Errorf("last state = %+v, want disconnected", last)
	}
}

func TestDriverHoldDelayIsCapped(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	server.send(">STATE:1795632745,RECONNECTING,SIGUSR1,,,,,", ">HOLD:Waiting for hold release:300")
	h.clock.WaitForTimers(t, 1)
	if pending := h.clock.Pending(); !slices.Equal(pending, []time.Duration{maxHoldDelay}) {
		t.Fatalf("pending timers = %v, want %v", pending, maxHoldDelay)
	}
	server.send(">HOLD:Waiting for hold release:0")
	server.expect("hold release")
	if pending := h.clock.Pending(); len(pending) != 0 {
		t.Errorf("the earlier delayed release is still pending: %v", pending)
	}
	server.close()
	h.process.exit(nil)
	h.events.waitClosed(t)
}

func TestDriverPrivateKeyPassphrase(t *testing.T) {
	m := testMaterial()
	settings := map[string]any{
		KeyRemoteHost: "vpn.example.com",
		KeyAuthMode:   AuthModeCertificate,
		KeyCACert:     m.caPEM,
		KeyClientCert: m.clientCertPEM,
	}
	secrets := vpn.Secrets{SecretClientKey: m.clientKeyPEM, SecretKeyPassphrase: `key "phrase"`}
	h := newDriverHarness(t, true)
	h.start(newProfile(t, settings, nil), secrets)
	server := acceptManagement(t, h.dialer)
	server.handshake()
	server.send(">PASSWORD:Need 'Private Key' password")
	server.expect(`password "Private Key" "key \"phrase\""`)
	server.send(">PASSWORD:Verification Failed: 'Private Key'")
	h.events.waitLog(t, domain.LogLevelError, "passphrase was rejected")
	server.close()
	h.process.exit(errors.New("exit status 1"))
	if last := lastState(t, h.events.waitClosed(t)); last.Code != domain.ErrorCodeAuthFailed {
		t.Errorf("last state = %+v, want auth_failed", last)
	}
}

func TestDriverProcessDiesBeforeSocket(t *testing.T) {
	h := newDriverHarness(t, false)
	h.start(newProfile(t, mdexSettings(), nil), mdexSecrets())
	h.process.print(t,
		"2026-11-25 18:52:23 Options error: You must define CA file (--ca) or CA path (--capath)",
		"2026-11-25 18:52:23 Use --help for more information.",
		"2026-11-25 18:52:23 Exiting due to fatal error",
	)
	h.events.waitLog(t, domain.LogLevelError, "Options error: You must define CA file")
	h.process.exit(errors.New("exit status 1"))
	last := lastState(t, h.events.waitClosed(t))
	wantParts := []string{"before its management interface was up (exit status 1)", "Options error", "Exiting due to fatal error"}
	for _, part := range wantParts {
		if !strings.Contains(last.Message, part) {
			t.Errorf("message %q lacks %q", last.Message, part)
		}
	}
	if last.State != domain.StateError || last.Code != domain.ErrorCodeProcessFailed {
		t.Errorf("last state = %+v, want process_failed", last)
	}
	h.assertFilesRemoved()
}

func TestDriverManagementNeverComesUp(t *testing.T) {
	h := newDriverHarness(t, false)
	h.start(newProfile(t, mdexSettings(), nil), mdexSecrets())
	for range int(socketWaitTimeout / socketPollInterval) {
		h.clock.WaitForTimers(t, 1)
		h.clock.Advance(socketPollInterval)
	}
	last := lastState(t, h.events.waitClosed(t))
	if last.Code != domain.ErrorCodeProcessFailed || !strings.Contains(last.Message, "did not come up within 10s") {
		t.Errorf("last state = %+v", last)
	}
	if !h.process.killed.Load() {
		t.Error("the process was not killed")
	}
	h.assertFilesRemoved()
}

func TestDriverCrashMidSession(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	server.login(usernameLine, `password "Auth" "secret"`)
	server.send(">STATE:1795632744,CONNECTED,SUCCESS,10.66.0.2,172.20.0.2,1194,,")
	h.events.waitState(t, domain.StateConnected)
	server.close()
	h.process.exit(errors.New("signal: segmentation fault"))
	last := lastState(t, h.events.waitClosed(t))
	if last.Code != domain.ErrorCodeProcessFailed || last.Message != "openvpn exited unexpectedly: signal: segmentation fault" {
		t.Errorf("last state = %+v", last)
	}
	h.assertFilesRemoved()
}

func TestDriverFatalMessage(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	fatal := "ERROR: Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)"
	server.send(">LOG:1795632744,F,"+fatal, ">FATAL:"+fatal)
	h.events.waitLog(t, domain.LogLevelError, "Cannot open TUN/TAP")
	server.close()
	h.process.exit(errors.New("exit status 1"))
	last := lastState(t, h.events.waitClosed(t))
	if last.Code != domain.ErrorCodeProcessFailed || last.Message != fatal {
		t.Errorf("last state = %+v, want the fatal text", last)
	}
}

func TestDriverUnexpectedCleanExit(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	server.send(">STATE:1795632746,EXITING,exit-with-notification,,,,,")
	server.close()
	h.process.exit(nil)
	last := lastState(t, h.events.waitClosed(t))
	if last.State != domain.StateDisconnected || last.Message != "openvpn exited" {
		t.Errorf("last state = %+v, want an unrequested clean exit", last)
	}
}

func TestDriverStopDuringConnect(t *testing.T) {
	h := newDriverHarness(t, false)
	h.start(newProfile(t, mdexSettings(), nil), mdexSecrets())
	h.clock.WaitForTimers(t, 1) // polling for the socket
	if err := h.awaitStop(h.stopAsync(context.Background())); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !h.process.killed.Load() {
		t.Error("a held process must be killed")
	}
	if last := lastState(t, h.events.waitClosed(t)); last.State != domain.StateDisconnected {
		t.Errorf("last state = %+v, want disconnected", last)
	}
	h.assertFilesRemoved()
}

func TestDriverStopWhileDialing(t *testing.T) {
	h := newDriverHarness(t, true)
	h.dialer.gate = make(chan struct{})
	h.start(newProfile(t, mdexSettings(), nil), mdexSecrets())
	stopped := h.stopAsync(context.Background())
	h.clock.WaitForTimers(t, 1) // Stop's SIGKILL deadline
	close(h.dialer.gate)
	if err := h.awaitStop(stopped); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if last := lastState(t, h.events.waitClosed(t)); last.State != domain.StateDisconnected {
		t.Errorf("last state = %+v, want disconnected", last)
	}
	h.assertFilesRemoved()
}

func TestDriverStopKillsAfterTimeout(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	stopped := h.stopAsync(context.Background())
	server.expect("signal SIGTERM")
	h.clock.WaitForTimers(t, 1)
	h.clock.Advance(terminateTimeout)
	if err := h.awaitStop(stopped); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !h.process.killed.Load() {
		t.Error("the process ignoring SIGTERM was not killed")
	}
	h.assertFilesRemoved()
}

func TestDriverStopWithCancelledContext(t *testing.T) {
	h := newDriverHarness(t, true)
	h.startMdex("secret")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := h.awaitStop(h.stopAsync(ctx))
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop: %v", err)
	}
	if !h.process.killed.Load() {
		t.Error("the process was not killed")
	}
	h.events.waitClosed(t)
	h.assertFilesRemoved()
}

func TestDriverStartFailures(t *testing.T) {
	failure := errors.New("boom")
	tests := []struct {
		name     string
		settings map[string]any
		prepare  func(h *driverHarness)
		ctx      func() context.Context
		wantIs   error
		spawned  bool
	}{
		{
			name:     "invalid profile",
			settings: map[string]any{KeyAuthMode: AuthModePassword},
			wantIs:   domain.ErrValidation,
		},
		{name: "runtime directory", prepare: func(h *driverHarness) { h.fs.mkdirErr = failure }, wantIs: failure},
		{name: "config file", prepare: func(h *driverHarness) { h.fs.writeErr = failure }, wantIs: failure},
		{name: "spawn", prepare: func(h *driverHarness) { h.starter.err = failure }, wantIs: failure, spawned: true},
		{
			name: "cancelled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantIs: context.Canceled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newDriverHarness(t, true)
			if tt.prepare != nil {
				tt.prepare(h)
			}
			settings, ctx := tt.settings, context.Background()
			if settings == nil {
				settings = mdexSettings()
			}
			if tt.ctx != nil {
				ctx = tt.ctx()
			}
			err := h.driver.Start(ctx, newProfile(t, settings, nil), mdexSecrets())
			if !errors.Is(err, tt.wantIs) {
				t.Fatalf("Start error = %v, want %v", err, tt.wantIs)
			}
			if name, _, _ := h.starter.commandLine(); (name != "") != tt.spawned {
				t.Errorf("spawn attempted = %v, want %v", name != "", tt.spawned)
			}
			h.events.waitClosed(t)
			h.assertFilesRemoved()
			if err := h.driver.Stop(context.Background()); err != nil {
				t.Errorf("Stop after a failed start: %v", err)
			}
		})
	}
}

func TestDriverLifecycleMisuse(t *testing.T) {
	t.Run("start twice", func(t *testing.T) {
		h := newDriverHarness(t, true)
		h.startMdex("secret")
		if err := h.driver.Start(context.Background(), newProfile(t, mdexSettings(), nil), mdexSecrets()); err == nil {
			t.Error("second Start succeeded")
		}
	})
	t.Run("stop without start", func(t *testing.T) {
		h := newDriverHarness(t, true)
		if err := h.driver.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		h.events.waitClosed(t)
		if err := h.driver.Start(context.Background(), newProfile(t, mdexSettings(), nil), mdexSecrets()); err == nil {
			t.Error("Start after Stop succeeded")
		}
	})
}

func TestDriverReportsManagementProblems(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	server.send(">PASSWORD:Need 'Auth' username/password")
	server.expect(usernameLine, `password "Auth" "secret"`)
	server.send(
		"SUCCESS: 'Auth' username entered, but not yet verified",
		"ERROR: password command failed",
		">BYTECOUNT:many,1",
		">PASSWORD:Need 'HTTP Proxy' username/password",
		">STATE:1795632744,CONNECTED,ROUTE_ERROR,10.66.0.2,172.20.0.2,1194,,",
		"ERROR: reply without a command",
	)
	h.events.waitLog(t, domain.LogLevelError, `management command "password" failed: password command failed`)
	h.events.waitLog(t, domain.LogLevelDebug, "malformed >BYTECOUNT")
	h.events.waitLog(t, domain.LogLevelWarn, `"HTTP Proxy" credentials`)
	h.events.waitLog(t, domain.LogLevelWarn, "connected with errors: ROUTE_ERROR")
	h.events.waitLog(t, domain.LogLevelError, `management command "" failed`)
	server.close()
	h.process.exit(nil)
	h.events.waitClosed(t)
}

func TestDriverReportsUnremovableConfig(t *testing.T) {
	h := newDriverHarness(t, true)
	server := h.startMdex("secret")
	h.fs.setRemoveErr(errors.New("read-only file system"))
	server.close()
	h.process.exit(nil)
	h.events.waitLog(t, domain.LogLevelError, "could not remove the rendered config")
	h.events.waitClosed(t)
}

func TestDriverMetadata(t *testing.T) {
	d, ok := Factory(Options{DeviceName: "tdvpn0"})().(*Driver)
	if !ok {
		t.Fatal("Factory does not create *Driver")
	}
	if d.Protocol() != domain.ProtocolOpenVPN {
		t.Errorf("Protocol = %s", d.Protocol())
	}
	if len(d.Describe().Sections) == 0 {
		t.Error("Describe returned no sections")
	}
	if err := d.Validate(newProfile(t, mdexSettings(), mdexSecrets())); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if d.opts.RuntimeDir != DefaultRuntimeDir || d.opts.Binary != DefaultBinary {
		t.Errorf("defaults not applied: %+v", d.opts)
	}
}

func TestOSFileSystem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	fsys := osFileSystem{}
	if err := fsys.MkdirAll(dir, runtimeDirMode); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := fsys.Chmod(dir, runtimeDirMode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	file := filepath.Join(dir, configFileName)
	if err := fsys.WriteFile(file, []byte("client\n"), configFileMode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fsys.Remove(file); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file still exists: %v", err)
	}
}

func assertNoEventContains(t *testing.T, events []domain.Event, forbidden ...string) {
	t.Helper()
	for _, e := range events {
		text := eventText(e)
		for _, f := range forbidden {
			if strings.Contains(text, f) {
				t.Errorf("event %+v contains %q", e, f)
			}
		}
	}
}

func eventText(e domain.Event) string {
	switch e := e.(type) {
	case domain.LogEvent:
		return e.Text
	case domain.StateEvent:
		return e.Message
	}
	return ""
}

func TestDriverValidateChecksRemoteNetworksAgainstTheLAN(t *testing.T) {
	settings := mdexSettings()
	settings[KeyRemoteNetworks] = []string{"192.168.2.0/25"}
	p := newProfile(t, settings, mdexSecrets())
	lan := func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")}, nil
	}
	failing := func(context.Context) ([]netip.Prefix, error) { return nil, errors.New("ip: not found") }

	if _, ok := validationFields(t, New(Options{LANSubnets: lan}).Validate(p))[KeyRemoteNetworks]; !ok {
		t.Error("remote network inside the LAN accepted")
	}
	for name, source := range map[string]LANSource{"no LAN source": nil, "failing LAN source": failing} {
		if err := New(Options{LANSubnets: source}).Validate(p); err != nil {
			t.Errorf("%s: Validate = %v, want the check skipped", name, err)
		}
	}
	if got := New(Options{}).RemoteNetworks(p); !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("192.168.2.0/25")}) {
		t.Errorf("RemoteNetworks = %v", got)
	}
	var _ vpn.RemoteNetworker = New(Options{})
}
