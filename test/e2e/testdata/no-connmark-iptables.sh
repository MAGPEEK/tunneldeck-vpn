#!/bin/sh
# Emulates a kernel without xt_connmark for iptables-nft: a command naming the
# CONNMARK target or the connmark match fails as iptables fails for a missing
# extension; everything else runs unchanged. Installed as
# /usr/local/sbin/iptables-nft, in front of the real one (compose.yml).
for arg in "$@"; do
	case "$arg" in
	CONNMARK | connmark)
		echo "Warning: Extension $arg revision 0 not supported, missing kernel module? (e2e emulation)" >&2
		exit 2
		;;
	esac
done
exec /usr/sbin/xtables-nft-multi iptables "$@"
