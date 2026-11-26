# Throwaway WireGuard test server for the end-to-end test. It is never
# published; its key pair is generated when the container starts. The
# userspace wireguard-go runs the device, so no kernel module is needed.
FROM alpine:3.24.4
# wireguard-go: the device; wireguard-tools-wg: keys and peers through the
# device's UAPI socket; netcat-openbsd and curl: the probe that reaches
# TunnelDeck's VPN address through the tunnel.
RUN apk add --no-cache wireguard-go wireguard-tools-wg iproute2 netcat-openbsd curl
COPY --chmod=0755 entrypoint.sh /usr/local/bin/e2e-wgserver
COPY --chmod=0755 peer.sh /usr/local/bin/e2e-wgserver-peer
ENTRYPOINT ["/usr/local/bin/e2e-wgserver"]
