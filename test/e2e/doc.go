// Package e2e holds the end-to-end test of TunnelDeck against throwaway
// OpenVPN servers in Docker, including the firewall with a LAN behind
// TunnelDeck. The test files carry the build tag e2e, so
// "go test ./..." skips them; run them with
//
//	go test -tags e2e -v -timeout 45m ./test/e2e/
//
// See README.md in this directory for the topology and the assertions.
package e2e
