#!/bin/sh
# Makes the given public key the only peer of the WireGuard test server.
#
#   e2e-wgserver-peer <public key>
#
# The peer gets the client address 10.94.4.2; the peers of earlier
# scenarios are removed, so every scenario starts with a fresh key pair.
set -eu

for old in $(wg show wg0 peers); do
  wg set wg0 peer "$old" remove
done
wg set wg0 peer "$1" allowed-ips 10.94.4.2/32
