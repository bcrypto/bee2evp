# Bee2evp: an OpenSSL engine

[![Github Actions Build Status](https://github.com/bcrypto/bee2evp/actions/workflows/build.yml/badge.svg)](https://github.com/bcrypto/bee2evp/actions/workflows/build.yml)
[![Coverage Analysis](https://codecov.io/gh/bcrypto/bee2evp/coverage.svg?branch=master)](https://codecov.io/gh/bcrypto/bee2evp?branch=master)

## What is Bee2evp?

Bee2evp is a cryptographic library which encapsulates [Bee2](https://github.com/agievich/bee2)
into [OpenSSL](openssl.org). Bee2evp provides cryptographic services using the 
[EVP](https://wiki.openssl.org/index.php/EVP) interface. Bee2evp is organized 
as an OpenSSL engine.

## Build

```
[git submodule update --init]
mkdir build
cd build
cmake [-DCMAKE_BUILD_TYPE={Release|Debug|Coverage|ASan|ASanDbg|MemSan|MemSanDbg|Check}] ..
cmake --build . [--config={Release|Debug}]
[cmake --install .]
```

Build types (Release by default):
   
*  Coverage -- test coverage; 
*  ASan, ASanDbg -- [address sanitizer](http://en.wikipedia.org/wiki/AddressSanitizer);
*  MemSan, MemSanDbg -- [memory sanitizer](http://code.google.com/p/memory-sanitizer/);
*  Check -- strict compile rules.

## Preparations

Before building Bee2evp, it is necessary to build and configure Bee2 and OpenSSL. 
Bee2evp requires OpenSSL version 1.1.1 or higher.

### Building Bee2

See instructions in [github.com/agievich/bee2](https://github.com/agievich/bee2).

### Building OpenSSL

1. Download the latest source files from [openssl.org/source](https://openssl.org/source).
2. Unpack files into some directory, for example, `openssl-1.1.1`.
3. Go to this directory.
4. Run the following commands:
   ```		
   mkdir build
   cd build
   ../config 
   make
   make install
   ```

By default, OpenSSL {headers|binaries|libraries} will be installed
in the directory `/usr/local/{include|bin|lib}`.

### Configuring OpenSSL

1. Rename `/usr/local/ssl/openssl.cnf.dist` -> `/usr/local/lib/openssl.cnf`.
2. Open `/usr/local/lib/openssl.cnf`.
3. Add the following lines (before the `[new_oids]` section):
   ```
   openssl_conf = openssl_init
   [openssl_init]
   engines = engine_section
   [engine_section]
   bee2evp = bee2evp_section
   [bee2evp_section]
   engine_id = bee2evp
   dynamic_path = /usr/local/lib/libbee2evp.so
   default_algorithms = ALL
   ```
4. Make sure `LD_LIBRARY_PATH` includes `/usr/local/lib`.
   
### Listing the capabilities

```
openssl engine -c -t bee2evp
```

## Provider (OpenSSL 3 and 4)

OpenSSL 4 has no engines. For OpenSSL 3 and later, Bee2evp is also built as
an OpenSSL provider: the loadable module `bee2prov` (`bee2prov.so`,
`bee2prov.dylib`), installed into `<libdir>/ossl-modules`. With OpenSSL 3 both
the engine and the provider are built, with OpenSSL 4 only the provider
(see the CMake options `BUILD_ENGINE`, `BUILD_PROVIDER`).

The provider implements the same algorithms as the engine: belt-hash,
bash256/384/512, belt-ecb/cbc/cfb/ctr/dwp/che/kwp, bash-prg-ae2561,
belt-mac, belt-hmac, bign keys (DER/PEM/text encoding, PKCS#8 protected with
PBKDF2 + belt-hmac), bign signatures, bign-keytransport and bign
Diffie-Hellman. String options are the same: `-pkeyopt params:<curve>`,
`-pkeyopt enc_params:specified|cofactor`, `-sigopt sig:deterministic`,
`-macopt hexkey:<key>`.

Attach the provider in `openssl.cnf` (the default provider must then be
activated explicitly):
```
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
bee2prov = bee2prov_sect
[default_sect]
activate = 1
[bee2prov_sect]
module = /usr/local/lib/ossl-modules/bee2prov.so
activate = 1
```
or on the command line:
`openssl <cmd> -provider-path /usr/local/lib/ossl-modules -provider bee2prov -provider default`.

Listing the capabilities:
```
openssl list -providers -digest-algorithms -cipher-algorithms -key-managers
```

BTLS ciphersuites require the patched OpenSSL (see below). With OpenSSL 4
they are served by the provider: it implements the TLS editions of the
ciphers (`belt-dwpt`, `belt-ctrt`, `belt-chet`, `bash-prg-aet`) and declares
the bign curves as TLS groups. With OpenSSL 3 BTLS still requires the engine.

Limitations (of OpenSSL, not of the provider): OpenSSL derives object
identifiers of digests and ciphers from legacy tables, which algorithms of
third-party providers are absent from. Therefore CMS/PKCS#7 and PKCS#12 with
belt/bash algorithms do not work.

## BTLS

In [this folder](btls), patches for different versions of OpenSSL are provided. 
These patches support the following ciphersuites defined in STB 34.101.65 
(Btls, see [apmi.bsu.by/resources/std.html](http://apmi.bsu.by/resources/std.html)):
- `DHE-BIGN-WITH-BELT-CTR-MAC-HBELT`;
- `DHE-BIGN-WITH-BELT-DWP-HBELT`;
- `DHT-BIGN-WITH-BELT-CTR-MAC-HBELT`;
- `DHT-BIGN-WITH-BELT-DWP-HBELT`;
- `DHE-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT`;
- `DHE-PSK-BIGN-WITH-BELT-DWP-HBELT`;
- `DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT`;
- `DHT-PSK-BIGN-WITH-BELT-DWP-HBELT`.

### Build script
Bash script can be used for OpenSSL downloading, patching, configuring and
building, Bee2 and Bee2evp building and tests running.
```
bash scripts/build.sh [-s -b -t] <OPENSSL_TAG>
```
Available values for `OPENSSL_TAG` are patch names in directory `btls/patch`
and `openssl-4.0.2` (the provider is used with OpenSSL 4). The option `-p`
attaches the provider instead of the engine for OpenSSL 3.
Supported OS are Linux, MacOS, FreeBSD and Windows (via MSYS).
The script requires GNU binutils and GNU sed to be available via PATH 
environment variable (additional packages can be installed on MacOS).
On FreeBSD, the script uses GNU make (`gmake`) and the base system `sed`.

## OpenVPN

[OpenVPN](openvpn) with BTLS ciphersuites in the control channel and belt
in the data channel can be built by the same script with the `-bv` option:
```
bash scripts/build.sh -s -b -bv openssl-3.3.1
```
See [openvpn/README.md](openvpn/README.md) for details, configuration and
limitations.

### Build in Docker
```
# OpenSSL 1.1.1 + Bee2evp engine
docker build --progress="plain" -f dockerfiles/debian.Dockerfile \
   -t bcrypto/bee2evp:1.1.1 --build-arg OPENSSL_TAG=OpenSSL_1_1_1i .
# OpenSSL 3.3.1 + Bee2evp engine
docker build --progress="plain" -f dockerfiles/debian.Dockerfile \
   -t bcrypto/bee2evp:3.3.1 --build-arg OPENSSL_TAG=openssl-3.3.1 . 
```
Run bash on prepared docker image:
```
docker run --rm -it -v .:/usr/src  bcrypto/bee2evp:1.1.1 bash
```

## License

Bee2evp is distributed under the Apache License version 2.0. See 
[Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0) or 
[LICENSE](LICENSE.txt) for details.

## Automated tools

Platforms:

* [Github Actions](https://github.com/bcrypto/bee2evp/actions);
* [Travis CI](https://app.travis-ci.com/github/agievich/bee2) (archived).

Code coverage:

* [CodeCov](https://app.codecov.io/gh/bcrypto/bee2evp?branch=master).

