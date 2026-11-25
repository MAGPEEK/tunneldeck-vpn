package openvpn

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
	"tunneldeck/internal/vpn/vpntest"
)

// waitLimit bounds real-time waits so a broken test fails instead of
// hanging; nothing sleeps.
const waitLimit = 5 * time.Second

const (
	testRuntimeDir = "/run/tunneldeck"
	testConfigPath = "/run/tunneldeck/openvpn.conf"
	testSocketPath = "/run/tunneldeck/mgmt.sock"
)

// memFS is an in-memory FileSystem with injectable failures.
type memFS struct {
	mu        sync.Mutex
	dirs      map[string]fs.FileMode
	files     map[string]memFile
	mkdirErr  error
	writeErr  error
	removeErr error
}

type memFile struct {
	data string
	mode fs.FileMode
}

func newMemFS() *memFS {
	return &memFS{dirs: map[string]fs.FileMode{}, files: map[string]memFile{}}
}

func (m *memFS) MkdirAll(path string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mkdirErr != nil {
		return m.mkdirErr
	}
	if _, ok := m.dirs[path]; !ok {
		m.dirs[path] = perm
	}
	return nil
}

func (m *memFS) Chmod(path string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirs[path] = perm
	return nil
}

func (m *memFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErr != nil {
		return m.writeErr
	}
	m.files[path] = memFile{data: string(data), mode: perm}
	return nil
}

func (m *memFS) Remove(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removeErr != nil {
		return m.removeErr
	}
	if _, ok := m.files[path]; !ok {
		return &fs.PathError{Op: "remove", Path: path, Err: fs.ErrNotExist}
	}
	delete(m.files, path)
	return nil
}

func (m *memFS) file(path string) (memFile, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	return f, ok
}

func (m *memFS) setRemoveErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeErr = err
}

// fakeProcess is a scripted openvpn process.
type fakeProcess struct {
	outR     *io.PipeReader
	outW     *io.PipeWriter
	exited   chan struct{}
	exitOnce sync.Once
	exitErr  error
	killed   atomic.Bool
}

func newFakeProcess() *fakeProcess {
	r, w := io.Pipe()
	return &fakeProcess{outR: r, outW: w, exited: make(chan struct{})}
}

func (p *fakeProcess) Output() io.ReadCloser { return p.outR }

func (p *fakeProcess) Wait() error {
	<-p.exited
	return p.exitErr
}

func (p *fakeProcess) Kill() error {
	p.killed.Store(true)
	p.exit(errors.New("signal: killed"))
	return nil
}

// exit ends the process with err; later calls do nothing.
func (p *fakeProcess) exit(err error) {
	p.exitOnce.Do(func() {
		p.exitErr = err
		_ = p.outW.Close()
		close(p.exited)
	})
}

// print writes lines to the process output.
func (p *fakeProcess) print(t *testing.T, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if _, err := io.WriteString(p.outW, line+"\n"); err != nil {
			t.Fatalf("write process output: %v", err)
		}
	}
}

// fakeStarter hands out one fakeProcess and records the command line.
type fakeStarter struct {
	process *fakeProcess
	err     error
	fs      *memFS

	mu            sync.Mutex
	name          string
	args          []string
	configAtSpawn memFile
}

func (s *fakeStarter) Start(name string, args ...string) (Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.name, s.args = name, args
	s.configAtSpawn, _ = s.fs.file(testConfigPath)
	if s.err != nil {
		return nil, s.err
	}
	return s.process, nil
}

func (s *fakeStarter) commandLine() (string, []string, memFile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name, s.args, s.configAtSpawn
}

// fakeDialer connects to an in-memory management server once the socket
// is "ready".
type fakeDialer struct {
	accepted chan net.Conn
	gate     chan struct{} // when set, Dial waits for it to close

	mu    sync.Mutex
	ready bool
	path  string
}

func newFakeDialer(ready bool) *fakeDialer {
	return &fakeDialer{accepted: make(chan net.Conn, 1), ready: ready}
}

func (d *fakeDialer) Dial(_ context.Context, socketPath string) (io.ReadWriteCloser, error) {
	if d.gate != nil {
		<-d.gate
	}
	d.mu.Lock()
	ready := d.ready
	d.path = socketPath
	d.mu.Unlock()
	if !ready {
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: errors.New("connect: no such file or directory")}
	}
	client, server := net.Pipe()
	d.accepted <- server
	return client, nil
}

func (d *fakeDialer) dialedPath() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.path
}

// mgmtServer plays OpenVPN's side of the management socket.
type mgmtServer struct {
	t        *testing.T
	conn     net.Conn
	commands chan string
}

func acceptManagement(t *testing.T, d *fakeDialer) *mgmtServer {
	t.Helper()
	select {
	case conn := <-d.accepted:
		s := &mgmtServer{t: t, conn: conn, commands: make(chan string, 32)}
		go s.readCommands()
		t.Cleanup(func() { _ = conn.Close() })
		return s
	case <-time.After(waitLimit):
		t.Fatal("the driver never connected to the management socket")
		return nil
	}
}

func (s *mgmtServer) readCommands() {
	defer close(s.commands)
	scanner := bufio.NewScanner(s.conn)
	for scanner.Scan() {
		s.commands <- scanner.Text()
	}
}

// send writes lines with OpenVPN's CRLF line ending.
func (s *mgmtServer) send(lines ...string) {
	s.t.Helper()
	for _, line := range lines {
		if _, err := io.WriteString(s.conn, line+"\r\n"); err != nil {
			s.t.Fatalf("management write %q: %v", line, err)
		}
	}
}

// expect checks the next commands the driver sent.
func (s *mgmtServer) expect(want ...string) {
	s.t.Helper()
	for _, w := range want {
		select {
		case got, ok := <-s.commands:
			if !ok {
				s.t.Fatalf("connection closed, want command %q", w)
			}
			if got != w {
				s.t.Fatalf("command = %q, want %q", got, w)
			}
		case <-time.After(waitLimit):
			s.t.Fatalf("no command, want %q", w)
		}
	}
}

// handshake runs the start of the dialogue in docs/openvpn-notes.md.
func (s *mgmtServer) handshake() {
	s.t.Helper()
	s.send(
		">INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info",
		">HOLD:Waiting for hold release:0",
	)
	s.expect("state on", "log on", "bytecount 2", "hold release")
	s.send(
		"SUCCESS: real-time state notification set to ON",
		"SUCCESS: real-time log notification set to ON",
		">LOG:1795632744,D,MANAGEMENT: CMD 'bytecount 2'",
		"SUCCESS: bytecount interval changed",
		"SUCCESS: hold release succeeded",
	)
}

// login answers the credential prompt and expects the given commands.
func (s *mgmtServer) login(wantUsername, wantPassword string) {
	s.t.Helper()
	s.send(">PASSWORD:Need 'Auth' username/password")
	s.expect(wantUsername, wantPassword)
	s.send(
		`>LOG:1795632744,D,MANAGEMENT: CMD 'username "Auth" "tduser"'`,
		"SUCCESS: 'Auth' username entered, but not yet verified",
		"SUCCESS: 'Auth' password entered, but not yet verified",
	)
}

func (s *mgmtServer) close() { _ = s.conn.Close() }

// eventLog collects a driver's events until its channel closes.
type eventLog struct {
	mu      sync.Mutex
	events  []domain.Event
	closed  bool
	changed chan struct{}
}

func collectEvents(events <-chan domain.Event) *eventLog {
	l := &eventLog{changed: make(chan struct{})}
	go func() {
		for e := range events {
			l.update(func() { l.events = append(l.events, e) })
		}
		l.update(func() { l.closed = true })
	}()
	return l
}

func (l *eventLog) update(f func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f()
	close(l.changed)
	l.changed = make(chan struct{})
}

// waitFor returns the first event matching match.
func (l *eventLog) waitFor(t *testing.T, what string, match func(domain.Event) bool) domain.Event {
	t.Helper()
	deadline := time.After(waitLimit)
	for {
		l.mu.Lock()
		for _, e := range l.events {
			if match(e) {
				l.mu.Unlock()
				return e
			}
		}
		closed, changed := l.closed, l.changed
		l.mu.Unlock()
		if closed {
			t.Fatalf("events closed without %s; got %v", what, l.snapshot())
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("no %s; got %v", what, l.snapshot())
		}
	}
}

func (l *eventLog) waitState(t *testing.T, state domain.ConnectionState) domain.StateEvent {
	t.Helper()
	e := l.waitFor(t, "state "+string(state), func(e domain.Event) bool {
		s, ok := e.(domain.StateEvent)
		return ok && s.State == state
	})
	return e.(domain.StateEvent)
}

func (l *eventLog) waitLog(t *testing.T, level domain.LogLevel, text string) domain.LogEvent {
	t.Helper()
	e := l.waitFor(t, "log "+text, func(e domain.Event) bool {
		g, ok := e.(domain.LogEvent)
		return ok && g.Level == level && strings.Contains(g.Text, text)
	})
	return e.(domain.LogEvent)
}

// waitClosed waits until the driver closed Events and returns all events.
func (l *eventLog) waitClosed(t *testing.T) []domain.Event {
	t.Helper()
	deadline := time.After(waitLimit)
	for {
		l.mu.Lock()
		closed, changed := l.closed, l.changed
		l.mu.Unlock()
		if closed {
			return l.snapshot()
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("events not closed; got %v", l.snapshot())
		}
	}
}

func (l *eventLog) snapshot() []domain.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]domain.Event(nil), l.events...)
}

// lastState returns the terminal state event of a closed log.
func lastState(t *testing.T, events []domain.Event) domain.StateEvent {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if s, ok := events[i].(domain.StateEvent); ok {
			return s
		}
	}
	t.Fatalf("no state event in %v", events)
	return domain.StateEvent{}
}

// driverHarness wires a Driver to fakes.
type driverHarness struct {
	t       *testing.T
	clock   *vpntest.FakeClock
	fs      *memFS
	process *fakeProcess
	starter *fakeStarter
	dialer  *fakeDialer
	driver  *Driver
	events  *eventLog
}

func newDriverHarness(t *testing.T, socketReady bool) *driverHarness {
	t.Helper()
	h := &driverHarness{
		t:       t,
		clock:   vpntest.NewFakeClock(time.Date(2026, 11, 25, 18, 52, 23, 0, time.UTC)),
		fs:      newMemFS(),
		process: newFakeProcess(),
		dialer:  newFakeDialer(socketReady),
	}
	h.starter = &fakeStarter{process: h.process, fs: h.fs}
	h.driver = New(Options{
		RuntimeDir: testRuntimeDir,
		DeviceName: "tdvpn0",
		Starter:    h.starter,
		Dialer:     h.dialer,
		FileSystem: h.fs,
		Clock:      h.clock,
	})
	h.events = collectEvents(h.driver.Events())
	t.Cleanup(func() { h.process.exit(nil) })
	return h
}

func (h *driverHarness) start(p domain.Profile, s vpn.Secrets) {
	h.t.Helper()
	if err := h.driver.Start(context.Background(), p, s); err != nil {
		h.t.Fatalf("Start: %v", err)
	}
}

// startMdex starts the mdex reference profile and connects management.
func (h *driverHarness) startMdex(password string) *mgmtServer {
	h.t.Helper()
	h.start(newProfile(h.t, mdexSettings(), nil), vpn.Secrets{SecretPassword: password})
	server := acceptManagement(h.t, h.dialer)
	server.handshake()
	return server
}

// stopAsync calls Stop in the background; the result arrives on the
// channel.
func (h *driverHarness) stopAsync(ctx context.Context) <-chan error {
	result := make(chan error, 1)
	go func() { result <- h.driver.Stop(ctx) }()
	return result
}

func (h *driverHarness) awaitStop(result <-chan error) error {
	h.t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(waitLimit):
		h.t.Fatal("Stop did not return")
		return nil
	}
}

// assertFilesRemoved checks that neither the config nor the socket is left.
func (h *driverHarness) assertFilesRemoved() {
	h.t.Helper()
	for _, name := range []string{testConfigPath, testSocketPath} {
		if _, ok := h.fs.file(name); ok {
			h.t.Errorf("%s was not removed", name)
		}
	}
}
