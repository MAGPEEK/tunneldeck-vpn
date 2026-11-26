# Throwaway IPsec gateway for the end-to-end test (variant E, SPEC §19):
# strongSwan with kernel IPsec, one connection per sign-in method and a
# net-to-net connection. It is never published; the PKI is generated when
# the container starts.
FROM alpine:3.24.4
# strongswan: charon and swanctl; openssl: the throwaway PKI and the
# client's PKCS#12 bundle; busybox-extras: httpd with the client-address
# CGI on the net-to-net network.
RUN apk add --no-cache strongswan openssl iproute2 busybox-extras
COPY --chmod=0755 entrypoint.sh /usr/local/bin/e2e-ipsecgw
COPY --chmod=0755 make-pki.sh /usr/local/bin/e2e-ipsecgw-pki
COPY strongswan.conf /etc/strongswan.d/e2e.conf
COPY swanctl.conf /etc/swanctl/conf.d/e2e.conf
ENTRYPOINT ["/usr/local/bin/e2e-ipsecgw"]
