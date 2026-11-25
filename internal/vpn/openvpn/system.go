package openvpn

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
)

// Process is a running openvpn child process.
type Process interface {
	// Output returns the combined stdout and stderr of the process. It
	// reaches EOF when the process has exited.
	Output() io.ReadCloser
	// Wait blocks until the process has exited. A non-zero exit status or a
	// death by signal is returned as an error.
	Wait() error
	// Kill ends the process with SIGKILL.
	Kill() error
}

// ProcessStarter starts child processes.
type ProcessStarter interface {
	Start(name string, args ...string) (Process, error)
}

// Dialer connects to the management unix socket.
type Dialer interface {
	Dial(ctx context.Context, socketPath string) (io.ReadWriteCloser, error)
}

// FileSystem holds the file operations on the runtime directory. Paths use
// forward slashes: they are paths of the Linux container.
type FileSystem interface {
	MkdirAll(path string, perm fs.FileMode) error
	Chmod(path string, perm fs.FileMode) error
	WriteFile(path string, data []byte, perm fs.FileMode) error
	Remove(path string) error
}

// execStarter starts real processes. It is the only os/exec use of the
// driver.
type execStarter struct{}

// Start runs name with args. stdout and stderr share one pipe so errors
// raised before the management interface exists are captured in order.
func (execStarter) Start(name string, args ...string) (Process, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("start %s: create output pipe: %w", name, err)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout = writer
	cmd.Stderr = writer
	configureCommand(cmd)
	err = cmd.Start()
	// The child holds its own copy of the write end; closing ours makes the
	// reader see EOF when the child exits.
	_ = writer.Close()
	if err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	return &execProcess{cmd: cmd, output: reader}, nil
}

type execProcess struct {
	cmd    *exec.Cmd
	output *os.File
}

func (p *execProcess) Output() io.ReadCloser { return p.output }
func (p *execProcess) Wait() error           { return p.cmd.Wait() }
func (p *execProcess) Kill() error           { return p.cmd.Process.Kill() }

// unixDialer dials unix domain sockets.
type unixDialer struct{}

func (unixDialer) Dial(ctx context.Context, socketPath string) (io.ReadWriteCloser, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath)
}

// osFileSystem uses the real file system.
type osFileSystem struct{}

func (osFileSystem) MkdirAll(path string, perm fs.FileMode) error { return os.MkdirAll(path, perm) }
func (osFileSystem) Chmod(path string, perm fs.FileMode) error    { return os.Chmod(path, perm) }
func (osFileSystem) Remove(path string) error                     { return os.Remove(path) }

func (osFileSystem) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(path, data, perm)
}
