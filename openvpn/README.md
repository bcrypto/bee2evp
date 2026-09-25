# OpenVPN with Bee2evp

This folder contains what is needed to build [OpenVPN](https://openvpn.net)
that protects both of its channels with Belarusian cryptography:

- control channel: BTLS ciphersuites (STB 34.101.65), bign certificates
  and keys:
  - TLS 1.2: `DHE-BIGN-WITH-BELT-CTR-MAC-HBELT` or
    `DHE-BIGN-WITH-BELT-DWP-HBELT`;
  - TLS 1.3: `TLS_BELT_CHE256_BELT_HASH` or `TLS_BASH_PRG_AE2561_BASH256`
    with the `bign-curve256v1` key exchange group;
- data channel: `belt-cbc256` encryption and `belt-hash` HMAC.

Files:
- [patch](patch) — OpenVPN patches, one per OpenVPN tag;
- [check.sh](check.sh) — checks a build, see [Check](#check).

## Why OpenVPN needs a patch

Built against OpenSSL 3.x, OpenVPN 2.6 looks algorithms up with
`EVP_CIPHER_fetch()`/`EVP_MD_fetch()` and lists them with
`EVP_*_do_all_provided()`. These functions search OpenSSL providers only,
so algorithms of the bee2evp engine are invisible:
`--data-ciphers belt-cbc256` or `--auth belt-hash` fail with "not found".

The patch (see comments in [patch/openvpn-2.6.14.patch](patch/openvpn-2.6.14.patch)):
1. looks ciphers and digests up with `EVP_get_cipherbyname()` and
   `EVP_get_digestbyname()`, which see engine algorithms too, when engine
   support is compiled in (`HAVE_OPENSSL_ENGINE`), and keeps
   `EVP_*_fetch()` otherwise, e.g. with OpenSSL 4.0 which has no engines;
2. lists engine ciphers and digests in `--show-ciphers`/`--show-digests`;
3. loads the `--engine` engine before options are checked.

The engine is enabled by `--engine bee2evp` or by the engines section of
`openssl.cnf` (`default_algorithms = ALL`), which OpenSSL loads at startup.

BTLS ciphersuites themselves come from the OpenSSL patch in [btls](../btls).

## Build

OpenVPN is built by the common build script with the `-bv` option after
OpenSSL, Bee2 and Bee2evp:
```
bash scripts/build.sh -s -b -bv openssl-3.3.1
bash scripts/build.sh -t openssl-3.3.1      # includes the OpenVPN check
```
The OpenVPN tag is set by `--openvpn-tag=<tag>` (default `v2.6.14`),
`patch/openvpn-<tag without v>.patch` must exist. Everything is installed
into `build/local` (`BEE2EVP_INSTALL_DIR`): `sbin/openvpn`, `bin/openssl`,
`openssl.cnf` with the attached engine. An existing `build/openvpn` tree is
reset and the patch is applied again, so a changed patch gets into the build.

Important details of the build (see `build_openvpn` in
[scripts/source.sh](../scripts/source.sh)):
- `--with-openssl-engine=yes`: with OpenSSL 3.x engine support is disabled
  by default and the patched code is compiled out. OpenVPN then prints
  "OpenSSL hardware crypto engine functionality is not available";
- `openssl.cnf` of the built OpenSSL must attach the engine
  (`attach_bee2evp` does it). OpenSSL silently ignores a config with a
  syntax error, so a broken `openssl.cnf` looks exactly like a missing engine:
  check it with `openssl ciphers ALL | tr : '\n' | grep BIGN`;
- OpenVPN is linked with rpath to `build/local/lib`, so it uses the patched
  libssl/libcrypto, not the system ones;
- DCO, LZO, LZ4 and the PAM plugin are disabled. DCO supports
  AES-GCM/ChaCha20-Poly1305 only;
- man pages are not installed: git sources lack them.

Prerequisites besides the ones of Bee2evp: autoconf, automake, libtool,
pkg-config. On Linux also the libcap-ng development package
(`libcap-ng-dev` on Debian/Ubuntu).

On FreeBSD:
```
pkg install -y bash git cmake gmake autoconf automake libtool pkgconf python3 perl5
```

## Check

```
sh openvpn/check.sh build/local
```
The script checks the engine, BTLS ciphersuites in OpenSSL, `belt-cbc256`
and `belt-hash` in OpenVPN, issues temporary bign certificates and makes
OpenVPN handshakes over 127.0.0.1:
- TLS 1.2: `DHE-BIGN-WITH-BELT-CTR-MAC-HBELT` and
  `DHE-BIGN-WITH-BELT-DWP-HBELT`;
- TLS 1.3: `TLS_BELT_CHE256_BELT_HASH` and `TLS_BASH_PRG_AE2561_BASH256`,
  the key exchange must be bign.

It uses `dev null`, so no root is needed.

## Configuration

Server and client share these options:
```
engine bee2evp

# TLS 1.3, see below for TLS 1.2
tls-version-min 1.3
tls-ciphersuites TLS_BELT_CHE256_BELT_HASH:TLS_BASH_PRG_AE2561_BASH256
tls-groups bign-curve256v1

data-ciphers belt-cbc256
auth belt-hash

# bign certificates and keys
ca   ca.crt
cert server.crt
key  server.key
dh   none
remote-cert-tls client    # on the client: remote-cert-tls server
```

Both the TLS 1.3 ciphersuites and the key exchange group must be set explicitly.
OpenSSL puts BTLS ciphersuites and bign groups after the standard ones, so
with default options TLS 1.3 negotiates `TLS_AES_256_GCM_SHA384` and X25519,
only certificates stay bign. Check the client log:
```
Control Channel: TLSv1.3, cipher TLSv1.3 TLS_BELT_CHE256_BELT_HASH, ... peer temporary key: 256 bits bign
```

TLS 1.2 (`tls-cipher` sets TLS 1.2 ciphersuites only, `tls-ciphersuites`
TLS 1.3 ones):
```
tls-version-min 1.2
tls-version-max 1.2
tls-cipher DHE-BIGN-WITH-BELT-DWP-HBELT:DHE-BIGN-WITH-BELT-CTR-MAC-HBELT
```

Keys and certificates are made by the built `openssl`:
```
openssl genpkey -genparam -algorithm bign -pkeyopt params:bign-curve256v1 -out params.pem
openssl genpkey -paramfile params.pem -out server.key
openssl req -new -key server.key -subj /CN=server -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -out server.crt -extfile <(printf \
  'keyUsage=digitalSignature,keyAgreement\nextendedKeyUsage=serverAuth\n')
```
`remote-cert-tls` needs both extensions. For a client certificate use
`extendedKeyUsage=clientAuth`.

## Limitations

- The data channel uses `belt-cbc256` + `belt-hash`. OpenVPN accepts AEAD
  data ciphers of GCM and ChaCha20-Poly1305 modes only, so `belt-dwp*` cannot
  be used there.
- `tls-crypt`/`tls-crypt-v2` and dynamic tls-crypt use AES-256-CTR and
  HMAC-SHA256 regardless of the options.
