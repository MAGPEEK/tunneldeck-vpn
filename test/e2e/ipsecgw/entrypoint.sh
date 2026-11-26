#!/bin/sh
# Starts the IPsec test gateway: the throwaway PKI on first start, the
# gateway's own addresses, the net-to-net web server, then charon with the
# connections of swanctl.conf.
#
# Addresses (README.md, "Variant E"):
#   gw0       10.94.5.1, 10.94.6.1, 10.94.7.1, 10.94.8.1: the gateway's
#             address in each virtual IP pool's network
#   remote0   10.99.0.1/24, the network behind the gateway
#   net0      10.98.0.1/24, the net-to-net network; httpd on port 80 answers
#             /cgi-bin/source with the client address it sees
#
# The client's CA certificate and PKCS#12 bundle land in /run/e2e/client.
set -eu

[ -f /etc/swanctl/x509ca/ca.crt ] || e2e-ipsecgw-pki /run/e2e/client "e2e PKCS#12 password"

# dummy <device> <address>...: a dummy interface with the addresses.
dummy() {
  device=$1
  shift
  ip link show "$device" >/dev/null 2>&1 || ip link add "$device" type dummy
  for address in "$@"; do
    ip addr replace "$address" dev "$device"
  done
  ip link set "$device" up
}

dummy gw0 10.94.5.1/32 10.94.6.1/32 10.94.7.1/32 10.94.8.1/32
dummy remote0 10.99.0.1/24
dummy net0 10.98.0.1/24

mkdir -p /www/cgi-bin /run/e2e
cat >/www/cgi-bin/source <<'CGI'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n%s\n' "$REMOTE_ADDR"
CGI
chmod 0755 /www/cgi-bin/source
httpd -p 10.98.0.1:80 -h /www

: >/run/e2e/charon.log
/usr/lib/strongswan/charon &
charon=$!
trap 'kill "$charon"' TERM INT
until swanctl --stats >/dev/null 2>&1; do sleep 0.2; done
swanctl --load-all
wait "$charon"
