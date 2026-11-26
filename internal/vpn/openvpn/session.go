package openvpn

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"tunneldeck/internal/domain"
)

// OpenVPN states the driver reacts to (>STATE: field 1).
const (
	stateConnected    = "CONNECTED"
	stateReconnecting = "RECONNECTING"
	detailSuccess     = "SUCCESS"
)

// session runs the management dialogue of one process
// (docs/openvpn-notes.md (c) and implementation items 10 to 13). Its fields
// are owned by the read goroutine.
type session struct {
	run      *run
	commands *commandWriter
	// released is set once the first hold has been answered with the
	// initial commands.
	released bool
	// stopHoldRelease cancels a delayed hold release, nil when none is
	// pending.
	stopHoldRelease func() bool
	// failure is the terminal outcome openvpn reported, valid once done is
	// closed.
	failure *failure
	done    chan struct{}
}

func newSession(r *run, commands *commandWriter) *session {
	return &session{run: r, commands: commands, done: make(chan struct{})}
}

// read handles management lines until the connection closes.
func (s *session) read(conn io.Reader) {
	defer close(s.done)
	defer s.cancelHoldRelease()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for scanner.Scan() {
		s.handle(strings.TrimSuffix(scanner.Text(), "\r"))
	}
	_, _ = io.Copy(io.Discard, conn)
}

func (s *session) handle(line string) {
	msg, err := parseManagementLine(line)
	if err != nil {
		s.log(domain.LogLevelDebug, "ignored a management message: "+err.Error())
		return
	}
	switch m := msg.(type) {
	case holdMessage:
		s.onHold(m)
	case passwordMessage:
		s.onPassword(m)
	case stateMessage:
		s.onState(m)
	case byteCountMessage:
		s.run.driver.emit(domain.TrafficEvent{BytesIn: m.in, BytesOut: m.out})
	case logMessage:
		s.onLog(m)
	case fatalMessage:
		s.fail(domain.ErrorCodeProcessFailed, m.text)
	case replyMessage:
		s.onReply(m)
	}
}

// onHold answers the first hold with the initial commands. Later holds
// follow internal restarts; their release waits the pause openvpn
// suggests, capped at the SPEC backoff maximum.
func (s *session) onHold(m holdMessage) {
	if !s.released {
		s.released = true
		s.run.forwardOutput.Store(false)
		s.commands.commands(commandStateOn, commandLogOn, commandByteCount, commandHoldRelease)
		return
	}
	s.cancelHoldRelease()
	delay := min(time.Duration(m.waitSeconds)*time.Second, maxHoldDelay)
	if delay == 0 {
		_ = s.commands.command(commandHoldRelease)
		return
	}
	s.stopHoldRelease = s.run.driver.opts.Clock.AfterFunc(delay, func() {
		_ = s.commands.command(commandHoldRelease)
	})
}

func (s *session) cancelHoldRelease() {
	if s.stopHoldRelease != nil {
		s.stopHoldRelease()
		s.stopHoldRelease = nil
	}
}

func (s *session) onPassword(m passwordMessage) {
	switch m.kind {
	case passwordNeeded:
		s.answer(m.realm)
	case passwordRejected:
		s.rejected(m)
	}
}

// answer sends the credentials for realm. It is called for every prompt,
// not only the first.
func (s *session) answer(realm string) {
	creds := s.run.creds
	switch realm {
	case realmAuth:
		if s.commands.send("username", credentialCommand("username", realmAuth, creds.username)) != nil {
			return
		}
		_ = s.commands.send("password", credentialCommand("password", realmAuth, creds.password))
	case realmPrivateKey:
		_ = s.commands.send("password", credentialCommand("password", realmPrivateKey, creds.keyPassphrase))
	default:
		s.log(domain.LogLevelWarn, fmt.Sprintf("openvpn asked for %q credentials, which TunnelDeck-VPN does not provide", realm))
	}
}

// rejected classifies a verification failure: no reason means rejected
// credentials, a TEMP reason is transient and openvpn retries by itself,
// any other reason is a server-side or configuration rejection.
func (s *session) rejected(m passwordMessage) {
	switch {
	case m.realm == realmPrivateKey:
		s.fail(domain.ErrorCodeAuthFailed, "the private key passphrase was rejected")
	case !m.hasReason:
		s.fail(domain.ErrorCodeAuthFailed, "the server rejected the username or password")
	case strings.HasPrefix(m.reason, "TEMP"):
		s.log(domain.LogLevelWarn, "the server reported a temporary authentication failure, openvpn retries: "+m.reason)
	default:
		s.fail(domain.ErrorCodeServerRejected, "the server refused the connection: "+m.reason)
	}
}

func (s *session) onState(m stateMessage) {
	switch m.name {
	case stateConnected:
		s.run.driver.emit(domain.StateEvent{
			State:  domain.StateConnected,
			VPNIP:  m.tunnelIP,
			Remote: remoteAddress(m),
			Since:  m.time,
		})
		if m.detail != detailSuccess {
			s.log(domain.LogLevelWarn, "openvpn connected with errors: "+m.detail)
		}
	case stateReconnecting:
		s.run.driver.emit(domain.StateEvent{State: domain.StateReconnecting, Message: m.detail, Since: m.time})
	}
}

func remoteAddress(m stateMessage) string {
	if m.remoteIP == "" || m.remotePort == "" {
		return m.remoteIP
	}
	return net.JoinHostPort(m.remoteIP, m.remotePort)
}

// onLog forwards a >LOG: line. Echoes of management commands are dropped;
// they contain the username in clear text.
func (s *session) onLog(m logMessage) {
	if isManagementEcho(m.text) {
		return
	}
	s.run.report(domain.LogEvent{Time: m.time, Level: managementLogLevel(m.flags, m.text), Text: m.text})
}

func (s *session) onReply(m replyMessage) {
	name := s.commands.settle()
	if !m.success {
		s.log(domain.LogLevelError, fmt.Sprintf("openvpn management command %q failed: %s", name, m.text))
	}
}

func (s *session) fail(code domain.ErrorCode, message string) {
	s.failure = &failure{code: code, message: message}
	s.log(domain.LogLevelError, message)
}

func (s *session) log(level domain.LogLevel, text string) { s.run.log(level, text) }

// commandWriter serialises writes to the management socket and remembers
// the commands awaiting a reply in order, so a reply can name its command.
type commandWriter struct {
	mu      sync.Mutex
	w       io.Writer
	pending []string
}

// command sends a command that carries no secret.
func (c *commandWriter) command(cmd string) error { return c.send(cmd, cmd) }

// commands sends cmds in order and stops at the first failed write; a
// failed write means the connection is gone.
func (c *commandWriter) commands(cmds ...string) {
	for _, cmd := range cmds {
		if c.command(cmd) != nil {
			return
		}
	}
}

// send writes line and queues name for the reply. name never contains a
// credential; line may.
func (c *commandWriter) send(name, line string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := io.WriteString(c.w, line+"\n"); err != nil {
		return fmt.Errorf("send %s: %w", name, err)
	}
	c.pending = append(c.pending, name)
	return nil
}

// settle returns the name of the oldest command still waiting for its
// reply, or "" when none is.
func (c *commandWriter) settle() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return ""
	}
	name := c.pending[0]
	c.pending = c.pending[1:]
	return name
}
