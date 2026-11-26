# syntax=docker/dockerfile:1

FROM node:24.22.3-alpine3.24 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
COPY internal/web/dist/.gitkeep /src/internal/web/dist/.gitkeep
RUN npm run build

FROM golang:1.27.4-alpine3.24 AS build
ARG VERSION=0.1.0-dev
ARG REVISION=unknown
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=web /src/internal/web/dist/ ./internal/web/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/tunneldeck ./cmd/tunneldeck

# strongSwan's charon for the IPsec driver (SPEC §19). Alpine's strongswan
# package lacks the kernel-libipsec plugin, which runs ESP in user space on
# a TUN device, so the host needs no kernel IPsec and gets no XFRM state or
# policies. charon is therefore built from the release Alpine 3.24 ships
# (the checksum is the one of Alpine's APKBUILD) with just the plugins the
# driver loads: IKEv2, IKEv1 for the Aggressive Mode XAuth fallback, and
# kernel-libipsec patched to honour install_routes (build/strongswan). Its
# PID file lives in the driver's runtime directory. After loading its
# plugins (TUN device, IKE and VICI sockets) charon drops to the user ipsec
# and keeps only the capabilities they need (libcap). vici enables the
# counters plugin, which the driver never loads; it is left out.
FROM alpine:3.24.4 AS strongswan
ARG STRONGSWAN_VERSION=6.0.7
ARG STRONGSWAN_SHA512=1d10b0eaf39072db1d7f5237661e71c81107bb0bdea6a4bcbdff0c54eb7f72d6487f78c91a6f527c69ff20f9ee611d7e8cedcec4c5cc65d53ecc4301e1353240
RUN apk add --no-cache build-base linux-headers openssl-dev curl-dev libcap-dev
WORKDIR /src
RUN wget -q "https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2" \
 && echo "${STRONGSWAN_SHA512}  strongswan-${STRONGSWAN_VERSION}.tar.bz2" | sha512sum -c - \
 && tar xjf "strongswan-${STRONGSWAN_VERSION}.tar.bz2"
WORKDIR /src/strongswan-${STRONGSWAN_VERSION}
COPY build/strongswan/*.patch /src/patches/
RUN set -e; for p in /src/patches/*.patch; do patch -p1 --fuzz=0 < "$p"; done; \
    ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib --with-ipsecdir=/usr/lib/strongswan \
      --with-piddir=/run/tunneldeck/ipsec --with-capabilities=libcap --with-user=ipsec --with-group=ipsec \
      --disable-defaults --enable-charon --enable-ikev2 --enable-ikev1 --enable-vici \
      --enable-kernel-libipsec --enable-kernel-netlink --enable-socket-default \
      --enable-openssl --enable-pem --enable-x509 --enable-pkcs1 --enable-pkcs8 --enable-pubkey \
      --enable-constraints --enable-revocation --enable-curl --enable-nonce --enable-random --enable-kdf \
      --enable-eap-identity --enable-eap-mschapv2 --enable-xauth-generic --enable-shared --disable-static \
 && make -j"$(nproc)" \
 && make DESTDIR=/out install-strip \
 && rm -f /out/usr/lib/ipsec/*.la /out/usr/lib/ipsec/plugins/*.la /out/usr/lib/ipsec/plugins/libstrongswan-counters.so

FROM alpine:3.24.4
ARG VERSION=0.1.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="TunnelDeck-VPN" \
      org.opencontainers.image.description="Self-hosted VPN client with a web UI, packaged as one container" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="https://github.com/MAGPEEK/tunneldeck-vpn" \
      org.opencontainers.image.licenses="MIT"
# openvpn stays on the 2.7 series that docs/openvpn-notes.md was verified
# against; tzdata serves TZ for the daily reconnect (SPEC §4.3); libcurl
# (CRL and OCSP fetching) and libcap2 are charon's libraries besides
# OpenSSL, which openvpn brings. charon runs as the unprivileged system
# user ipsec, which can read nothing in /data (files 0600, owned by root).
RUN apk add --no-cache "openvpn~2.7" iptables iptables-legacy iproute2 ca-certificates tzdata libcurl libcap2 \
 && addgroup -S ipsec \
 && adduser -S -D -H -h /var/empty -s /sbin/nologin -G ipsec ipsec
COPY --from=strongswan /out/usr/lib/ipsec/ /usr/lib/ipsec/
COPY --from=strongswan /out/usr/lib/strongswan/charon /usr/lib/strongswan/charon
COPY --from=build /out/tunneldeck /usr/local/bin/tunneldeck
EXPOSE 8194
VOLUME /data
# The process runs as root on purpose: it creates the tun device through
# /dev/net/tun, starts OpenVPN or charon, and changes iptables chains and policy
# routing, which all need CAP_NET_ADMIN in the host network namespace. A
# non-root user would need ambient or file capabilities passed on to the
# openvpn, charon, iptables and ip child processes. Root inside a container that
# gets only NET_ADMIN on top of Docker's default set is the simpler setup;
# the root-only control socket and /data permissions rely on it too. charon
# itself drops to the user ipsec once its plugins are loaded.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/tunneldeck", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/tunneldeck"]
