package netguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CommandRunner runs an external program and returns its standard output.
// A command that cannot start or exits non-zero is reported as
// *CommandError.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

// CommandError describes a failed command: what ran, how it ended and what
// it wrote to standard error.
type CommandError struct {
	Name string
	Args []string
	// ExitCode is the process exit status, or -1 when the command did not
	// start or was killed.
	ExitCode int
	Stderr   string
	Err      error
}

// Error names the command line, the failure and the trimmed stderr.
func (e *CommandError) Error() string {
	line := strings.Join(append([]string{e.Name}, e.Args...), " ")
	msg := fmt.Sprintf("%s: %v", line, e.Err)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

// Unwrap returns the underlying os/exec error.
func (e *CommandError) Unwrap() error {
	return e.Err
}

// ExecRunner runs commands with os/exec. It forces the C locale so that the
// error messages netguard matches on are stable.
type ExecRunner struct{}

// Run executes name with args and returns its standard output.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), &CommandError{
			Name:     name,
			Args:     args,
			ExitCode: exitCode(err),
			Stderr:   strings.TrimSpace(stderr.String()),
			Err:      err,
		}
	}
	return stdout.String(), nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
