package control

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// socketPath returns a short socket path; sun_path holds about 100 bytes,
// so t.TempDir() may be too long on some systems.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tdctl")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "run", SocketName)
}

func listen(t *testing.T, path string, handlers map[string]Handler) *Server {
	t.Helper()
	s, err := Listen(path, handlers)
	if err != nil {
		t.Skipf("unix sockets are not available here: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func send(t *testing.T, path, command string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Send(ctx, path, command)
}

func TestRoundTrip(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	listen(t, path, map[string]Handler{
		CommandResetAdmin: func() error { calls.Add(1); return nil },
		"fail":            func() error { return errors.New("store is read-only") },
	})

	if err := send(t, path, CommandResetAdmin); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("handler calls = %d, want 1", calls.Load())
	}
	if err := send(t, path, "fail"); err == nil || !strings.Contains(err.Error(), "store is read-only") {
		t.Errorf("Send(fail) = %v", err)
	}
	if err := send(t, path, "shutdown"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("Send(unknown) = %v", err)
	}
}

func TestSocketMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no unix file modes")
	}
	path := socketPath(t)
	listen(t, path, nil)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != socketMode {
		t.Errorf("mode = %v, want %v", mode, socketMode)
	}
}

func TestSendWithoutServer(t *testing.T) {
	path := socketPath(t)
	if err := send(t, path, CommandResetAdmin); !errors.Is(err, ErrNoServer) {
		t.Errorf("Send without socket file = %v, want ErrNoServer", err)
	}
	s := listen(t, path, nil)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file left after Close: %v", err)
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := socketPath(t)
	stale, err := net.Listen("unix", filepath.Clean(mustMkdir(t, path)))
	if err != nil {
		t.Skipf("unix sockets are not available here: %v", err)
	}
	if l, ok := stale.(*net.UnixListener); ok {
		l.SetUnlinkOnClose(false)
	}
	_ = stale.Close()
	if err := send(t, path, CommandResetAdmin); !errors.Is(err, ErrNoServer) {
		t.Errorf("Send to stale socket = %v, want ErrNoServer", err)
	}
	listen(t, path, map[string]Handler{CommandResetAdmin: func() error { return nil }})
	if err := send(t, path, CommandResetAdmin); err != nil {
		t.Errorf("Send after replacing the stale socket: %v", err)
	}
}

func TestListenRefusesWhileAServerRuns(t *testing.T) {
	path := socketPath(t)
	listen(t, path, nil)
	if s, err := Listen(path, nil); err == nil {
		_ = s.Close()
		t.Fatal("second Listen succeeded")
	}
}

func mustMkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return path
}
