//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	composeFile    = "compose.yml"
	composeProject = "tunneldeck-e2e"
	// keepStackEnv set to 1 leaves the stack running after the test, for
	// debugging; tear it down with "docker compose -p tunneldeck-e2e down -v --rmi all".
	keepStackEnv = "E2E_KEEP_STACK"
	// commandTimeout bounds every docker command except the image build.
	commandTimeout = 2 * time.Minute
	buildTimeout   = 20 * time.Minute
)

// stack runs docker compose commands against the test stack.
type stack struct{}

// startStack builds the images, starts every service and registers the
// teardown, which removes containers, networks, volumes and the images
// built for the test.
func startStack(t *testing.T) stack {
	t.Helper()
	var s stack
	t.Cleanup(func() { s.tearDown(t) })
	s.compose(t, commandTimeout, "down", "--volumes", "--remove-orphans")
	s.compose(t, buildTimeout, "build")
	s.compose(t, commandTimeout, "up", "--detach", "--no-build", "--wait")
	return s
}

func (s stack) tearDown(t *testing.T) {
	if t.Failed() {
		out, _ := s.try(commandTimeout, "logs", "--no-color", "--tail", "80")
		t.Logf("service logs:\n%s", out)
	}
	if os.Getenv(keepStackEnv) == "1" {
		t.Logf("%s=1: the stack keeps running", keepStackEnv)
		return
	}
	if out, err := s.try(commandTimeout, "down", "--volumes", "--remove-orphans", "--rmi", "all"); err != nil {
		t.Errorf("tear down the stack: %v\n%s", err, out)
	}
}

// compose runs a docker compose subcommand and fails the test on error.
func (s stack) compose(t *testing.T, timeout time.Duration, args ...string) string {
	t.Helper()
	out, err := s.try(timeout, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return out
}

// exec runs a command in a service container and fails the test on error.
func (s stack) exec(t *testing.T, service string, args ...string) string {
	t.Helper()
	return s.compose(t, commandTimeout, append([]string{"exec", "-T", service}, args...)...)
}

// execInput runs a command in a service container with input on stdin.
func (s stack) execInput(t *testing.T, service, input string, args ...string) {
	t.Helper()
	full := append([]string{"exec", "-T", service}, args...)
	if out, err := s.run(commandTimeout, strings.NewReader(input), full...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

// tryExec runs a command in a service container; a failure is a result,
// not a test error.
func (s stack) tryExec(service string, args ...string) (string, error) {
	return s.try(commandTimeout, append([]string{"exec", "-T", service}, args...)...)
}

func (s stack) try(timeout time.Duration, args ...string) (string, error) {
	return s.run(timeout, nil, args...)
}

func (stack) run(timeout time.Duration, stdin *strings.Reader, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"compose", "-f", composeFile, "-p", composeProject}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("docker %s: %w", strings.Join(full, " "), err)
	}
	return out.String(), nil
}
