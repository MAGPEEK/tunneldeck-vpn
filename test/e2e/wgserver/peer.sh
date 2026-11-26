#!/bin/sh
# Makes the given public key the only peer of the WireGuard test server,
# with the pre-shared key if one is given.
#
#   e2e-wgserver-peer <public key> [<pre-shared key>]
#
# The peer gets the client address 10.94.4.2; the peers of earlier
# scenarios are removed, so every scenario starts with a fresh key pair.
set -eu

for old in $(wg show wg0 peers); do
  wg set wg0 peer "$old" remove
done
if [ $# -ge 2 ]; then
  (umask 077 && printf '%s\n' "$2" >/run/e2e/peer.psk)
  wg set wg0 peer "$1" allowed-ips 10.94.4.2/32 preshared-key /run/e2e/peer.psk
else
  wg set wg0 peer "$1" allowed-ips 10.94.4.2/32
fi
