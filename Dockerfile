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
# against; tzdata serves TZ for the daily reconnect (SPEC §4.3).
RUN apk add --no-cache "openvpn~2.7" iptables iptables-legacy iproute2 ca-certificates tzdata
COPY --from=build /out/tunneldeck /usr/local/bin/tunneldeck
EXPOSE 8194
VOLUME /data
# The process runs as root on purpose: it creates the tun device through
# /dev/net/tun, starts OpenVPN, and changes iptables chains and policy
# routing, which all need CAP_NET_ADMIN in the host network namespace. A
# non-root user would need ambient or file capabilities passed on to the
# openvpn, iptables and ip child processes. Root inside a container that
# gets only NET_ADMIN on top of Docker's default set is the simpler setup;
# the root-only control socket and /data permissions rely on it too.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/tunneldeck", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/tunneldeck"]
