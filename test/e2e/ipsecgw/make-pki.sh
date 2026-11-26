#!/bin/sh
# Generates the gateway's throwaway PKI (ECDSA P-256, valid two days) into
# swanctl's directories: the CA, the gateway certificate for ipsec-gw.e2e
# and the client certificate for client.ipsec.e2e. The client's key and
# certificate go to <dir> as a PKCS#12 bundle (OpenSSL 3 defaults: AES-256,
# PBKDF2) protected by <password>. Nothing of it is ever committed.
#
#   make-pki.sh <dir> <password>
set -eu

out=$1
work=$(mktemp -d)
cd "$work"

new_key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
}

# issue <name> <identity> <extended key usage>: the identity is the common
# name and the DNS subject alternative name IKE checks the ID against.
issue() {
  new_key "$1"
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=DNS:%s\n' "$3" "$2" >"$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 2 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
}

new_key ca
openssl req -x509 -new -key ca.key -subj "/CN=TunnelDeck e2e IPsec CA" -days 2 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
issue gateway ipsec-gw.e2e serverAuth
issue client client.ipsec.e2e clientAuth

install -m 0644 ca.crt /etc/swanctl/x509ca/ca.crt
install -m 0644 gateway.crt /etc/swanctl/x509/gateway.crt
install -m 0600 gateway.key /etc/swanctl/private/gateway.key
mkdir -p "$out"
install -m 0644 ca.crt "$out/ca.crt"
openssl pkcs12 -export -inkey client.key -in client.crt -passout "pass:$2" -out "$out/client.p12"
rm -rf "$work"
