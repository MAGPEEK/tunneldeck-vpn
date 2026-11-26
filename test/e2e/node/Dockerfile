# Test node for the firewall part of the end-to-end test: a LAN web server
# (lan-web) and the two strongSwan IPsec endpoints (lan-ipsec, the stand-in
# for an IPsec router such as a LANCOM, and peer-ipsec on the VPN side).
# It is never published.
FROM alpine:3.24.4
# busybox-extras: httpd with CGI; strongswan: charon and swanctl; iproute2:
# routes, the inner dummy networks and manually keyed ESP (ip xfrm).
RUN apk add --no-cache busybox-extras strongswan iproute2
COPY --chmod=0755 entrypoint.sh /usr/local/bin/e2e-node
COPY strongswan.conf /etc/strongswan.d/e2e.conf
ENTRYPOINT ["/usr/local/bin/e2e-node"]
