// Package control is the root-only unix socket through which a second
// tunneldeck process (for example "docker exec ... tunneldeck reset-admin")
// asks the running server to act. The protocol is one line per connection:
// the client sends a command, the server answers "ok" or "error: <reason>".
package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// SocketName is the file name of the socket in the runtime directory.
const SocketName = "control.sock"

// CommandResetAdmin removes the admin account and all sessions.
const CommandResetAdmin = "reset-admin"

const (
	socketMode     fs.FileMode = 0o600
	dirMode        fs.FileMode = 0o700
	maxLineBytes               = 256
	requestTimeout             = 30 * time.Second
	replyOK                    = "ok"
	replyErrPrefix             = "error: "
)

// ErrNoServer reports that no server listens on the socket.
var ErrNoServer = errors.New("no tunneldeck server is running")

// Handler runs one command.
type Handler func() error

// Server answers commands on a unix socket.
type Server struct {
	listener net.Listener
	path     string
	handlers map[string]Handler
	done     chan struct{}
}

// Listen creates the socket at path with mode 0600 inside a 0700
// directory. A socket left by a crashed server is replaced; a socket with a
// live server behind it is an error.
func Listen(path string, handlers map[string]Handler) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, fmt.Errorf("control socket: create directory: %w", err)
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	if err := os.Chmod(path, socketMode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("control socket: restrict mode: %w", err)
	}
	s := &Server{listener: listener, path: path, handlers: handlers, done: make(chan struct{})}
	go s.serve()
	return s, nil
}

func removeStale(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("control socket %s: another server is running", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("control socket: remove stale socket: %w", err)
	}
	return nil
}

// Close stops accepting commands and removes the socket file.
func (s *Server) Close() error {
	err := s.listener.Close()
	<-s.done
	if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
		err = errors.Join(err, removeErr)
	}
	return err
}

func (s *Server) serve() {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.handle(conn)
	}
}

// handle answers one connection. Commands run one at a time.
func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	if !peerAllowed(conn) {
		slog.Warn("control socket: refused a client that is neither root nor the server user")
		_, _ = fmt.Fprintf(conn, "%spermission denied\n", replyErrPrefix)
		return
	}
	command, err := readLine(conn)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "%sunreadable command\n", replyErrPrefix)
		return
	}
	_, _ = fmt.Fprintln(conn, s.run(command))
}

func (s *Server) run(command string) string {
	handler, ok := s.handlers[command]
	if !ok {
		return replyErrPrefix + "unknown command"
	}
	slog.Info("control command", "command", command)
	if err := handler(); err != nil {
		slog.Error("control command failed", "command", command, "error", err)
		return replyErrPrefix + err.Error()
	}
	return replyOK
}

func readLine(conn net.Conn) (string, error) {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", errors.New("empty request")
	}
	return strings.TrimSpace(scanner.Text()), nil
}

// Send asks the server behind path to run command. It returns an error
// wrapping ErrNoServer when no server listens, and the server's reason when
// the command failed.
func Send(ctx context.Context, path, command string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("control socket %s: %w", path, ErrNoServer)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		if isNoServer(err) {
			return fmt.Errorf("control socket %s: %w", path, ErrNoServer)
		}
		return fmt.Errorf("control socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintln(conn, command); err != nil {
		return fmt.Errorf("control socket: send: %w", err)
	}
	reply, err := readLine(conn)
	if err != nil {
		return fmt.Errorf("control socket: read reply: %w", err)
	}
	if reply == replyOK {
		return nil
	}
	return fmt.Errorf("server refused %s: %s", command, strings.TrimPrefix(reply, replyErrPrefix))
}

// isNoServer reports dial errors that mean nobody listens: the socket file
// vanished or nothing accepts on it.
func isNoServer(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) || isPlatformNoServer(err)
}
