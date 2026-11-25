// Package netguard manages the iptables chains that protect the host from the
// tunnel and the policy routing for replies through the tunnel. Every
// iptables and ip call goes through a CommandRunner.
package netguard
