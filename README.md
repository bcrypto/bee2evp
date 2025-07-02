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
make
[make install]
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

## Build in Docker
```
# OpenSSL 1.1.1 + Bee2evp engine
docker build --progress="plain" -f dockerfiles/focal.Dockerfile \
   -t bcrypto/bee2evp:1.1.1 .
# OpenSSL 1.1.1 + Bee2evp engine + BTLS
docker build --progress="plain" -f dockerfiles/focal-btls.Dockerfile \
   -t bcrypto/bee2evp:1.1.1-btls .
# OpenSSL 3.0 + Bee2evp provider
docker build --progress="plain" -f dockerfiles/noble.Dockerfile \
   -t bcrypto/bee2evp:3.0 .  
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

