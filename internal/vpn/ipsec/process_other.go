//go:build !linux

package ipsec

import "os/exec"

// configureCommand has nothing to set outside Linux, where only builds and
// tests run.
func configureCommand(*exec.Cmd) {}
