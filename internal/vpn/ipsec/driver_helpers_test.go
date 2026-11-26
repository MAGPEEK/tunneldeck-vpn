package ipsec

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn/vpntest"
)

// waitLimit bounds how long a test waits for asynchronous work.
const waitLimit = 5 * time.Second

var testStart = time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)

// fakeCharon answers VICI requests on one end of a pipe like charon: it
// confirms event registrations, records commands, fails those named in
// fail and streams sas as list-sa events. Events are pushed with send.
type fakeCharon struct {
	t       *testing.T
	writeMu sync.Mutex
	conn    net.Conn

	mu       sync.Mutex
	commands []string
	messages map[string]*message
	fail     map[string]string
	sas      []*message
}

func newFakeCharon(t *testing.T) *fakeCharon {
	return &fakeCharon{t: t, messages: map[string]*message{}, fail: map[string]string{}}
}

func (f *fakeCharon) serve(conn net.Conn) {
	f.conn = conn
	go func() {
		for {
			p, err := readPacket(conn)
			if err != nil {
				return
			}
			f.answer(p)
		}
	}()
}

func (f *fakeCharon) answer(p packet) {
	switch p.kind {
	case packetEventRegister:
		f.write(packet{kind: packetEventConfirm, message: newMessage()})
	case packetCmdRequest:
		f.mu.Lock()
		f.commands = append(f.commands, p.name)
		f.messages[p.name] = p.message
		errmsg, failing := f.fail[p.name]
		sas := slices.Clone(f.sas)
		f.mu.Unlock()
		if p.name == "list-sas" {
			for _, sa := range sas {
				f.write(packet{kind: packetEvent, name: "list-sa", message: sa})
			}
		}
		reply := newMessage().set("success", "yes")
		if failing {
			reply = newMessage().set("success", "no").set("errmsg", errmsg)
		}
		f.write(packet{kind: packetCmdResponse, message: reply})
	}
}

func (f *fakeCharon) write(p packet) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	_ = writePacket(f.conn, p)
}

// send pushes an event to the driver.
func (f *fakeCharon) send(name string, m *message) {
	f.write(packet{kind: packetEvent, name: name, message: m})
}

func (f *fakeCharon) setSAs(sas ...*message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sas = sas
}

func (f *fakeCharon) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.commands)
}

func (f *fakeCharon) lastMessage(command string) *message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.messages[command]
}

// waitCommands waits until charon has received at least n commands.
func (f *fakeCharon) waitCommands(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		if got := f.recorded(); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("charon received %v, want %d commands", f.recorded(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// fakeProcess is a charon whose output the test writes; Terminate and
// Kill end it.
type fakeProcess struct {
	output     *io.PipeReader
	writer     *io.PipeWriter
	exited     chan struct{}
	once       sync.Once
	exitErr    error
	terminated chan struct{}
	ignoreTerm bool
}

func newFakeProcess() *fakeProcess {
	r, w := io.Pipe()
	return &fakeProcess{output: r, writer: w, exited: make(chan struct{}), terminated: make(chan struct{}, 1)}
}

func (p *fakeProcess) Output() io.ReadCloser { return p.output }

func (p *fakeProcess) Wait() error {
	<-p.exited
	return p.exitErr
}

func (p *fakeProcess) Terminate() error {
	select {
	case p.terminated <- struct{}{}:
	default:
	}
	if !p.ignoreTerm {
		p.exit(nil)
	}
	return nil
}

func (p *fakeProcess) Kill() error {
	p.exit(errors.New("signal: killed"))
	return nil
}

func (p *fakeProcess) exit(err error) {
	p.once.Do(func() {
		p.exitErr = err
		_ = p.writer.Close()
		close(p.exited)
	})
}

func (p *fakeProcess) logLine(line string) {
	_, _ = io.WriteString(p.writer, line+"\n")
}

// fakeStarter starts fakeProcess, which reports kernel-libipsec's TUN
// device unless quiet is set.
type fakeStarter struct {
	mu      sync.Mutex
	process *fakeProcess
	env     []string
	err     error
	quiet   bool
}

func (s *fakeStarter) Start(_ string, env []string, _ ...string) (Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	s.env = env
	if !s.quiet {
		go s.process.logLine("00[LIB] created TUN device: ipsec0")
	}
	return s.process, nil
}

// fakeDialer connects to charon, which serves the other end of a pipe.
type fakeDialer struct {
	charon *fakeCharon
	err    error
}

func (d fakeDialer) Dial(context.Context, string) (io.ReadWriteCloser, error) {
	if d.err != nil {
		return nil, d.err
	}
	client, server := net.Pipe()
	d.charon.serve(server)
	return client, nil
}

// fakeFS keeps files in memory.
type fakeFS struct {
	mu    sync.Mutex
	files map[string]string
	modes map[string]fs.FileMode
}

func newFakeFS() *fakeFS { return &fakeFS{files: map[string]string{}, modes: map[string]fs.FileMode{}} }

func (f *fakeFS) MkdirAll(path string, perm fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modes[path] = perm
	return nil
}

func (f *fakeFS) Chmod(path string, perm fs.FileMode) error { return f.MkdirAll(path, perm) }

func (f *fakeFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path], f.modes[path] = string(data), perm
	return nil
}

func (f *fakeFS) Remove(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[path]; !ok {
		return fs.ErrNotExist
	}
	delete(f.files, path)
	return nil
}

func (f *fakeFS) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for name := range f.files {
		out = append(out, name)
	}
	return out
}

// fakeRunner records the commands it runs.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	return "", r.fail[call]
}

func (r *fakeRunner) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// harness runs one driver against the fakes and collects its events.
type harness struct {
	t       *testing.T
	driver  *Driver
	clock   *vpntest.FakeClock
	charon  *fakeCharon
	process *fakeProcess
	starter *fakeStarter
	fs      *fakeFS
	runner  *fakeRunner
	events  chan domain.Event
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t: t, clock: vpntest.NewFakeClock(testStart), charon: newFakeCharon(t), process: newFakeProcess(),
		fs: newFakeFS(), runner: &fakeRunner{fail: map[string]error{}}, events: make(chan domain.Event, 256),
	}
	h.starter = &fakeStarter{process: h.process}
	return h
}

// start creates the driver with opts adjusted by adjust and starts p.
func (h *harness) start(p domain.Profile, adjust ...func(*Options)) error {
	opts := Options{
		DeviceName: "tdvpn0", Runner: h.runner, Starter: h.starter, Dialer: fakeDialer{charon: h.charon},
		FileSystem: h.fs, Clock: h.clock,
	}
	for _, a := range adjust {
		a(&opts)
	}
	h.driver = New(opts)
	go func() {
		for e := range h.driver.Events() {
			h.events <- e
		}
		close(h.events)
	}()
	return h.driver.Start(context.Background(), p, p.Secrets)
}

// waitState returns the next state event, skipping other events, and
// fails unless it is state.
func (h *harness) waitState(state domain.ConnectionState) domain.StateEvent {
	h.t.Helper()
	for {
		e := h.next()
		if s, ok := e.(domain.StateEvent); ok {
			if s.State != state {
				h.t.Fatalf("state %s (%+v), want %s", s.State, s, state)
			}
			return s
		}
	}
}

// waitEvent returns the next event matching match.
func (h *harness) waitEvent(match func(domain.Event) bool) domain.Event {
	h.t.Helper()
	for {
		if e := h.next(); match(e) {
			return e
		}
	}
}

func (h *harness) next() domain.Event {
	h.t.Helper()
	select {
	case e, ok := <-h.events:
		if !ok {
			h.t.Fatal("the events ended")
		}
		return e
	case <-time.After(waitLimit):
		h.t.Fatal("no event")
	}
	return nil
}

// connected brings p up to the point where charon initiated it.
func (h *harness) initiated(p domain.Profile) {
	h.t.Helper()
	if err := h.start(p); err != nil {
		h.t.Fatalf("Start: %v", err)
	}
	h.charon.waitCommands(h.t, len(credentialRequests(mustConfig(h.t, p)))+2)
}

// poll fires the next SA check and waits until charon has answered it.
func (h *harness) poll() {
	h.t.Helper()
	before := len(h.charon.recorded())
	h.clock.WaitForTimers(h.t, 1)
	h.clock.Advance(pollInterval)
	h.charon.waitCommands(h.t, before+1)
}

func (h *harness) stop() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
	defer cancel()
	if err := h.driver.Stop(ctx); err != nil {
		h.t.Fatalf("Stop: %v", err)
	}
}

func mustConfig(t *testing.T, p domain.Profile) profileConfig {
	t.Helper()
	c, problems := parseProfile(p, p.Secrets, nil)
	if err := problems.OrNil(); err != nil {
		t.Fatal(err)
	}
	return c
}

// saMessage is an IKE SA of the tunnel as charon lists it, with one
// installed CHILD_SA.
func saMessage(state, vip string, childID string, bytesIn, bytesOut string) *message {
	m := newMessage()
	sa := m.setSection(connName)
	sa.set("state", state).set("remote-host", "198.51.100.7").set("remote-port", "4500").
		set("encr-alg", "AES_GCM_16").set("encr-keysize", "256").set("prf-alg", "PRF_HMAC_SHA2_384").set("dh-group", "CURVE_25519")
	if vip != "" {
		sa.setList("local-vips", vip)
	}
	if childID != "" {
		child := sa.setSection("child-sas").setSection(connName + "-" + childID)
		child.set("uniqueid", childID).set("state", stateInstalled).set("encr-alg", "AES_GCM_16").set("encr-keysize", "256").
			set("bytes-in", bytesIn).set("bytes-out", bytesOut).set("install-time", "3")
	}
	return m
}

// ikeSAMessage is the established IKE SA with the unique ID ikeID, with
// one installed CHILD_SA unless childID is "".
func ikeSAMessage(ikeID, vip, childID string) *message {
	m := saMessage(stateEstablished, vip, childID, "0", "0")
	m.section(connName).set("uniqueid", ikeID)
	return m
}

// updown is a child-updown or ike-updown event for sa.
func updown(up bool, sa *message) *message {
	m := newMessage()
	if up {
		m.set("up", "yes")
	}
	m.entries = append(m.entries, sa.entries...)
	return m
}

// waitFor waits until cond holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited in vain for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
