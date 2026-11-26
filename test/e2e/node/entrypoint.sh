#!/bin/sh
# Starts one test node of the firewall end-to-end test.
#
#   e2e-node web      HTTP server on port 80; /cgi-bin/source answers with
#                     the client address the server sees
#   e2e-node ipsec    strongSwan charon; the test loads the connections
#
# Environment for ipsec:
#   INNER_ADDRESS     address/prefix of the network behind this IPsec
#                     endpoint, put on the dummy interface inner0
#   PUBLIC_ADDRESS    optional address/prefix added to lo, used as the IKE
#                     address (peer-ipsec, which shares server-a's network
#                     namespace)
#
# The default route of the LAN nodes is set by the test, because it points
# to the TunnelDeck container under test.
set -eu

web() {
  mkdir -p /www/cgi-bin
  cat >/www/cgi-bin/source <<'EOF'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n%s\n' "$REMOTE_ADDR"
EOF
  chmod 0755 /www/cgi-bin/source
  exec httpd -f -p 0.0.0.0:80 -h /www
}

ipsec() {
  if [ -n "${PUBLIC_ADDRESS:-}" ]; then
    ip addr replace "$PUBLIC_ADDRESS" dev lo
  fi
  ip link show inner0 >/dev/null 2>&1 || ip link add inner0 type dummy
  ip addr replace "$INNER_ADDRESS" dev inner0
  ip link set inner0 up
  exec /usr/lib/strongswan/charon
}

case "${1:-}" in
  web) web ;;
  ipsec) ipsec ;;
  *) echo "usage: e2e-node web|ipsec" >&2; exit 2 ;;
esac
