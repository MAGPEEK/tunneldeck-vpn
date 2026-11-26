package openvpn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

const (
	// outputTailLines is how many stdout lines a start-up failure reports.
	outputTailLines = 5
	// maxLineBytes bounds a line from stdout or the management socket.
	maxLineBytes = 64 * 1024
)

// managementCredentials are the values sent over management, never written
// to disk.
type managementCredentials struct {
	username      string
	password      string
	keyPassphrase string
}

func managementCredentialsOf(p domain.Profile, s vpn.Secrets) managementCredentials {
	username, _ := p.Settings.String(KeyUsername) // absent in certificate mode
	return managementCredentials{username: username, password: s[SecretPassword], keyPassphrase: s[SecretKeyPassphrase]}
}

// failure is a terminal outcome reported as an error state event.
type failure struct {
	code    domain.ErrorCode
	message string
}

func (f failure) event(at time.Time) domain.StateEvent {
	return domain.StateEvent{State: domain.StateError, Code: f.code, Message: f.message, Since: at}
}

// run supervises one openvpn process from spawn to exit.
type run struct {
	driver   *Driver
	process  Process
	creds    managementCredentials
	warnings []Warning

	exited  chan struct{}
	exitErr error // valid once exited is closed

	outputDone chan struct{}
	tail       []string // last stdout lines, valid once outputDone is closed
	// forwardOutput is true until the management log takes over; from then
	// on stdout repeats the >LOG: lines and only feeds the tail.
	forwardOutput atomic.Bool

	// Owned by the supervise goroutine.
	managementUp bool
	failure      *failure
}

func newRun(d *Driver, process Process, creds managementCredentials, warnings []Warning) *run {
	r := &run{
		driver:     d,
		process:    process,
		creds:      creds,
		warnings:   warnings,
		exited:     make(chan struct{}),
		outputDone: make(chan struct{}),
	}
	r.forwardOutput.Store(true)
	return r
}

// supervise connects the management interface, waits for the process to
// exit, removes the files and reports the outcome.
func (r *run) supervise() {
	r.reportWarnings()
	go r.readOutput()
	go r.waitForExit()
	conn := r.connect()
	var s *session
	if conn != nil {
		s = r.startSession(conn)
	}
	<-r.exited
	if conn != nil {
		_ = conn.Close()
		<-s.done
	}
	<-r.outputDone
	r.finish(s)
}

func (r *run) reportWarnings() {
	for _, w := range r.warnings {
		r.log(domain.LogLevelWarn, describeExtraWarning(w))
	}
}

// describeExtraWarning names the extra option of w by its directive, or by
// its line when the warning withholds the text.
func describeExtraWarning(w Warning) string {
	if w.Directive == "" {
		return fmt.Sprintf("extra option on line %d %s", w.Line, w.Message)
	}
	return fmt.Sprintf("extra option %q %s", w.Directive, w.Message)
}

func (r *run) waitForExit() {
	r.exitErr = r.process.Wait()
	close(r.exited)
}

func (r *run) readOutput() {
	defer close(r.outputDone)
	output := r.process.Output()
	defer func() { _ = output.Close() }()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for scanner.Scan() {
		r.outputLine(stripOutputTimestamp(strings.TrimSuffix(scanner.Text(), "\r")))
	}
	// Keep draining after an over-long line so openvpn never blocks on
	// stdout.
	_, _ = io.Copy(io.Discard, output)
}

func (r *run) outputLine(text string) {
	if text == "" || isManagementEcho(text) {
		return
	}
	r.tail = append(r.tail, text)
	if len(r.tail) > outputTailLines {
		r.tail = r.tail[1:]
	}
	if r.forwardOutput.Load() {
		r.log(outputLogLevel(text), text)
	}
}

// connect dials the management socket until it appears. It gives up when
// the process exits, a stop is requested or socketWaitTimeout passes.
func (r *run) connect() io.ReadWriteCloser {
	deadline := r.driver.opts.Clock.Now().Add(socketWaitTimeout)
	for {
		conn, err := r.driver.opts.Dialer.Dial(context.Background(), r.driver.socketPath())
		if err == nil {
			return conn
		}
		if !r.driver.opts.Clock.Now().Before(deadline) {
			r.failure = &failure{
				code:    domain.ErrorCodeProcessFailed,
				message: fmt.Sprintf("the openvpn management interface did not come up within %s: %v", socketWaitTimeout, err),
			}
			_ = r.process.Kill()
			return nil
		}
		if !r.pause(socketPollInterval) {
			return nil
		}
	}
}

// pause waits for d. It returns false early when the process exits or a
// stop is requested; a stop kills the process, which is still held.
func (r *run) pause(d time.Duration) bool {
	elapsed := make(chan struct{})
	stopTimer := r.driver.opts.Clock.AfterFunc(d, func() { close(elapsed) })
	defer stopTimer()
	select {
	case <-elapsed:
		return true
	case <-r.exited:
		return false
	case <-r.driver.stopping:
		_ = r.process.Kill()
		return false
	}
}

func (r *run) startSession(conn io.ReadWriteCloser) *session {
	r.managementUp = true
	commands := &commandWriter{w: conn}
	s := newSession(r, commands)
	go s.read(conn)
	if r.driver.attachCommands(commands) {
		go r.driver.terminate(commands)
	}
	return s
}

func (r *run) finish(s *session) {
	if err := r.driver.removeFiles(); err != nil {
		r.log(domain.LogLevelError, "could not remove the rendered config: "+err.Error())
	}
	r.driver.emit(r.outcome(s))
	r.driver.finish()
}

// outcome tells how the process ended. The exit code cannot tell an
// authentication failure from a clean stop (both are 0), so the messages
// seen on management decide first.
func (r *run) outcome(s *session) domain.StateEvent {
	now := r.now()
	reported := r.failure
	if s != nil && s.failure != nil {
		reported = s.failure
	}
	switch {
	case r.driver.wasStopRequested():
		return domain.StateEvent{State: domain.StateDisconnected, Since: now}
	case reported != nil:
		return reported.event(now)
	case !r.managementUp:
		return failure{code: domain.ErrorCodeProcessFailed, message: r.startupFailure()}.event(now)
	case r.exitErr != nil:
		return failure{code: domain.ErrorCodeProcessFailed, message: "openvpn exited unexpectedly: " + r.exitErr.Error()}.event(now)
	}
	return domain.StateEvent{State: domain.StateDisconnected, Message: "openvpn exited", Since: now}
}

// startupFailure describes a process that died before its management
// interface was up, with its last output lines: option errors such as a
// missing CA only appear there.
func (r *run) startupFailure() string {
	status := "exit status 0"
	if r.exitErr != nil {
		status = r.exitErr.Error()
	}
	message := "openvpn exited before its management interface was up (" + status + ")"
	if len(r.tail) == 0 {
		return message
	}
	return message + ":\n" + strings.Join(r.tail, "\n")
}

func (r *run) log(level domain.LogLevel, text string) {
	r.driver.emit(domain.LogEvent{Time: r.now(), Level: level, Text: text})
}

func (r *run) now() time.Time { return r.driver.opts.Clock.Now().UTC() }
