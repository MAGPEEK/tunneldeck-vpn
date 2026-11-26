#!/bin/sh
# Starts the WireGuard test server (variant D).
#
# The device wg0 runs in the userspace wireguard-go and listens on UDP
# 51820 with the tunnel address 10.94.4.1/24. The server's key pair is
# generated on the first start; the test reads the public key from
# /run/e2e/server.pub and makes TunnelDeck's public key the only peer
# (peer.sh, installed as e2e-wgserver-peer). Like the OpenVPN servers it has the probe source
# 198.18.0.1 on lo and the network 10.99.0.0/24 "behind" it on remote0.
set -eu

ip addr replace 198.18.0.1/32 dev lo
ip link show remote0 >/dev/null 2>&1 || ip link add remote0 type dummy
ip addr replace 10.99.0.1/24 dev remote0
ip link set remote0 up

mkdir -p /run/e2e
if [ ! -f /run/e2e/server.key ]; then
  (umask 077 && wg genkey >/run/e2e/server.key)
fi
wg pubkey </run/e2e/server.key >/run/e2e/server.pub

# wireguard-go refuses to run on Linux without this, preferring the kernel
# module that Docker Desktop's VM may lack.
export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
wireguard-go --foreground wg0 &
pid=$!
trap 'kill "$pid"' INT TERM
until [ -S /var/run/wireguard/wg0.sock ]; do
  kill -0 "$pid"
  sleep 0.1
done
wg set wg0 private-key /run/e2e/server.key listen-port 51820
ip addr replace 10.94.4.1/24 dev wg0
ip link set wg0 up
wait "$pid"
