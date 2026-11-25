#!/bin/sh
# Starts one OpenVPN test server variant.
#
#   entrypoint.sh <variant>    variant = name of a .conf file next to this script
#
# On first start it generates a throwaway PKI. It also adds the probe source
# address 198.18.0.1 (RFC 2544 benchmark range) to lo: probes sent from it
# reach TunnelDeck through the tunnel from an address outside the VPN pool,
# so TunnelDeck's replies only find their way back through policy routing.
set -eu

here=/etc/openvpn/e2e
pki=/etc/openvpn/pki

[ -f "$pki/ca.crt" ] || "$here/make-pki.sh" "$pki"
ip addr replace 198.18.0.1/32 dev lo
mkdir -p /run/e2e
touch /run/e2e/auth-attempts.log
exec openvpn --config "$here/$1.conf"
