# Throwaway OpenVPN test server for the end-to-end test. It is never
# published; the PKI is generated when the container starts.
FROM alpine:3.24.4
# openvpn: the server; openssl: the throwaway PKI; netcat-openbsd and curl:
# the probe that reaches TunnelDeck's VPN address through the tunnel.
RUN apk add --no-cache "openvpn~2.7" openssl iproute2 netcat-openbsd curl
COPY --chmod=0755 entrypoint.sh make-pki.sh verify.sh /etc/openvpn/e2e/
COPY *.conf /etc/openvpn/e2e/
ENTRYPOINT ["/etc/openvpn/e2e/entrypoint.sh"]
