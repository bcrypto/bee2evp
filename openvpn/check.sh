#!/bin/sh
# *****************************************************************************
# \file check.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Checks OpenVPN built with Bee2evp support
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************
# Checks the bee2evp engine, BTLS ciphersuites in OpenSSL, belt ciphers in
# OpenVPN and makes real OpenVPN TLS 1.2 and TLS 1.3 handshakes (server and
# client on 127.0.0.1, dev null, no root needed) with temporary bign
# certificates.
#
# Usage: sh openvpn/check.sh <prefix>
#   <prefix> contains bin/openssl and sbin/openvpn (build/local by default).
set -eu

PREFIX=${1:-$(cd "$(dirname "$0")/.." && pwd)/build/local}
PORT=${PORT:-11999}
OSSL=$PREFIX/bin/openssl
OVPN=$PREFIX/sbin/openvpn
SUITES="DHE-BIGN-WITH-BELT-CTR-MAC-HBELT DHE-BIGN-WITH-BELT-DWP-HBELT"
SUITES13="TLS_BELT_CHE256_BELT_HASH TLS_BASH_PRG_AE2561_BASH256"

T=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null || true; rm -rf "$T"' EXIT

ok() { echo "OK   $*"; }
fail() { echo "FAIL $*"; exit 1; }

"$OSSL" engine -c bee2evp 2>&1 | grep -q belt-hash \
    && ok "engine bee2evp is loaded" || fail "engine bee2evp is not loaded ($OSSL engine -c bee2evp)"

"$OSSL" ciphers ALL | tr : '\n' > "$T/ciphers"
for s in $SUITES; do
    grep -qx "$s" "$T/ciphers" && ok "OpenSSL: ciphersuite $s" \
        || fail "OpenSSL does not see $s (engine is not attached in openssl.cnf or OpenSSL is not patched)"
done
"$OSSL" ciphers -s -tls1_3 | tr : '\n' > "$T/ciphers13"
for s in $SUITES13; do
    grep -qx "$s" "$T/ciphers13" && ok "OpenSSL: TLS 1.3 ciphersuite $s" \
        || fail "OpenSSL does not see TLS 1.3 $s (OpenSSL patch without TLS 1.3 support?)"
done

"$OVPN" --show-ciphers | grep -q '^belt-cbc256 ' && ok "OpenVPN: cipher belt-cbc256" \
    || fail "OpenVPN does not see belt-cbc256 (built without --with-openssl-engine=yes or the patch?)"
"$OVPN" --show-digests | grep -q '^belt-hash ' && ok "OpenVPN: digest belt-hash" \
    || fail "OpenVPN does not see belt-hash (built without --with-openssl-engine=yes or the patch?)"

# Temporary CA and certificates, bign-curve256v1
cd "$T"
"$OSSL" genpkey -genparam -algorithm bign -pkeyopt params:bign-curve256v1 -out params.pem
for n in ca server client; do "$OSSL" genpkey -paramfile params.pem -out $n.key; done
"$OSSL" req -new -x509 -key ca.key -subj /CN=check-ca -days 1 -out ca.crt
for n in server client; do
    # remote-cert-tls needs both keyUsage and extendedKeyUsage
    printf "keyUsage=digitalSignature,keyAgreement\nextendedKeyUsage=${n}Auth\n" > $n.ext
    "$OSSL" req -new -key $n.key -subj /CN=check-$n -out $n.csr
    "$OSSL" x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
        -extfile $n.ext -out $n.crt 2>/dev/null
done
"$OSSL" x509 -in server.crt -noout -text | grep -q bign-with-hbelt \
    && ok "bign-with-hbelt certificates issued" || fail "cannot issue bign certificates"

# Makes an OpenVPN handshake and checks the ciphersuite of the control channel
# and the data channel. $1: TLS version, $2: ciphersuite, the rest: options.
handshake() {
    v=$1 s=$2
    shift 2
    set -- --dev null --engine bee2evp --data-ciphers belt-cbc256 --auth belt-hash \
        --dh none --ca ca.crt --verb 3 "$@"
    "$OVPN" "$@" --proto tcp-server --lport "$PORT" --tls-server \
        --cert server.crt --key server.key --remote-cert-tls client > srv.log 2>&1 &
    PIDS="$PIDS $!"
    sleep 1
    "$OVPN" "$@" --proto tcp-client --remote 127.0.0.1 "$PORT" --tls-client \
        --cert client.crt --key client.key --remote-cert-tls server > cli.log 2>&1 &
    PIDS="$PIDS $!"

    i=0
    until grep -q 'Initialization Sequence Completed' srv.log && grep -q 'Initialization Sequence Completed' cli.log; do
        i=$((i + 1))
        [ $i -le 20 ] || { tail -20 srv.log cli.log; fail "handshake $s is not completed in 20 s"; }
        sleep 1
    done
    kill $PIDS 2>/dev/null; wait 2>/dev/null || true; PIDS=""

    grep -q "Control Channel: $v, cipher $v $s," cli.log || { cat cli.log; fail "control channel is not $v $s"; }
    grep -q "Data Channel: cipher 'belt-cbc256', auth 'belt-hash'" cli.log || { cat cli.log; fail "data channel is not belt"; }
    PORT=$((PORT + 1))
}

for s in $SUITES; do
    handshake TLSv1.2 "$s" --tls-version-min 1.2 --tls-version-max 1.2 --tls-cipher "$s"
    ok "OpenVPN handshake: control TLSv1.2 $s, data belt-cbc256/belt-hash"
done

# Without tls-groups the key exchange of TLS 1.3 uses X25519
for s in $SUITES13; do
    handshake TLSv1.3 "$s" --tls-version-min 1.3 --tls-ciphersuites "$s" \
        --tls-groups bign-curve256v1
    grep -q "peer temporary key: 256 bits bign" cli.log || { cat cli.log; fail "key exchange is not bign"; }
    ok "OpenVPN handshake: control TLSv1.3 $s, bign key exchange, data belt-cbc256/belt-hash"
done

echo "All checks passed"
