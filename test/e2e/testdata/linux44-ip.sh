#!/bin/sh
# Emulates the policy-rule selectors of Linux 4.4 (Synology DSM 7.2) for the
# LAN TunnelDecks: ipproto, sport and dport exist since Linux 4.17, so any ip
# command naming them fails. Installed as /usr/local/sbin/ip, in front of the
# real /sbin/ip (compose.yml).
for arg in "$@"; do
	case "$arg" in
	ipproto | sport | dport)
		echo "Error: selector \"$arg\" is unknown to this kernel (e2e: Linux 4.4 emulation)" >&2
		exit 2
		;;
	esac
done
exec /sbin/ip "$@"
