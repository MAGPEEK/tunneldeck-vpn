#!/bin/sh
# Generates a throwaway PKI in <dir>: CA, server and client certificates
# (ECDSA P-256, valid two days, with the key usages remote-cert-tls checks)
# and a tls-crypt key. Nothing of it is ever committed.
#
#   make-pki.sh <dir>
set -eu

mkdir -p "$1"
cd "$1"

new_key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
}

# issue <name> <common name> <extended key usage>
issue() {
  new_key "$1"
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n' "$3" >"$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 2 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
}

new_key ca
openssl req -x509 -new -key ca.key -subj "/CN=TunnelDeck e2e CA" -days 2 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
issue server e2e-server serverAuth
issue client e2e-client clientAuth
openvpn --genkey tls-crypt tc.key
chmod 600 ./*.key
