# syntax=docker/dockerfile:1

FROM node:24.22.3-alpine3.24 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
COPY internal/web/dist/.gitkeep /src/internal/web/dist/.gitkeep
RUN npm run build

FROM golang:1.27.4-alpine3.24 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=web /src/internal/web/dist/ ./internal/web/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/tunneldeck ./cmd/tunneldeck

FROM alpine:3.24.4
RUN apk add --no-cache openvpn iptables iptables-legacy iproute2 ca-certificates
COPY --from=build /out/tunneldeck /usr/local/bin/tunneldeck
EXPOSE 8194
VOLUME /data
ENTRYPOINT ["/usr/local/bin/tunneldeck"]
